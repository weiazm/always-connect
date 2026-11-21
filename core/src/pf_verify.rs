//! Verification for the strict blocking rules. NetworkGuard owns the command
//! runner and all writes. No raw state-table or foreign-rule text escapes.

mod states;
pub use states::{check_states, clear_states, BlockingPolicy, StateError};

#[derive(Default)]
pub struct PfOutput {
    pub stdout: String,
    pub stderr: String,
}

fn diagnostic_lines(stderr: &str) -> impl Iterator<Item = &str> {
    stderr.lines().map(str::trim).filter(|line| {
        !matches!(
            *line,
            "" | "No ALTQ support in kernel" | "ALTQ related functions disabled"
        )
    })
}

fn readable(output: PfOutput) -> Option<String> {
    diagnostic_lines(&output.stderr)
        .next()
        .is_none()
        .then_some(output.stdout)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleChainError {
    ReadFailed,
    UnrecognizedRules,
    EarlierQuickPass,
    EarlierQuickBlock,
    AnchorUnreachable,
}

/// Verify the loaded call chain up to our anchor. The caller separately
/// verifies PF is enabled and the target anchor terminates all outbound rule
/// evaluation (including an unconditional final quick block).
pub fn verify_rule_chain<E>(
    mut run: impl FnMut(&[&str]) -> Result<PfOutput, E>,
) -> Result<(), RuleChainError> {
    let mut reads = 0;
    let mut read = |args: &[&str]| {
        reads += 1;
        if reads > 128 {
            return Err(RuleChainError::UnrecognizedRules);
        }
        run(args)
            .ok()
            .and_then(readable)
            .ok_or(RuleChainError::ReadFailed)
    };
    if walk_rules("", &mut read, 0)? {
        Ok(())
    } else {
        Err(RuleChainError::AnchorUnreachable)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn anchor_path(parent: &str, name: &str) -> Result<String, RuleChainError> {
    let mut parent = parent;
    let mut name = name;
    if let Some(absolute) = name.strip_prefix('/') {
        parent = "";
        name = absolute;
    }
    while let Some(relative) = name.strip_prefix("../") {
        if parent.is_empty() {
            return Err(RuleChainError::UnrecognizedRules);
        }
        parent = parent.rsplit_once('/').map_or("", |(prefix, _)| prefix);
        name = relative;
    }
    if !name.split('/').all(valid_name) {
        return Err(RuleChainError::UnrecognizedRules);
    }
    Ok(child_path(parent, name))
}

fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn read_args<'a>(path: &'a str, modifier: &'a str) -> Vec<&'a str> {
    if path.is_empty() {
        vec!["-s", modifier]
    } else {
        vec!["-a", path, "-s", modifier]
    }
}

type RulesRead<'a> = dyn FnMut(&[&str]) -> Result<String, RuleChainError> + 'a;

fn walk_rules(path: &str, read: &mut RulesRead<'_>, depth: usize) -> Result<bool, RuleChainError> {
    if path == crate::pf::ANCHOR {
        return Ok(true);
    }
    if depth > 16 {
        return Err(RuleChainError::UnrecognizedRules);
    }
    let rules = read(&read_args(path, "rules"))?;
    for line in rules.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["scrub" | "scrub-anchor", ..] => {}
            ["block", "in", ..] => {}
            [action @ ("pass" | "block"), options @ ..] => {
                // PF prints modifiers before selectors. Quoted label text or
                // a user-selected anchor name must never count as a modifier.
                let modifiers = options.iter().take_while(|word| {
                    !matches!(
                        **word,
                        "on" | "inet"
                            | "inet6"
                            | "proto"
                            | "all"
                            | "from"
                            | "to"
                            | "route-to"
                            | "reply-to"
                            | "dup-to"
                            | "label"
                            | "tag"
                    )
                });
                if modifiers.into_iter().any(|word| *word == "quick") {
                    return Err(if *action == "pass" {
                        RuleChainError::EarlierQuickPass
                    } else {
                        RuleChainError::EarlierQuickBlock
                    });
                }
            }
            ["anchor", name, options @ ..] if unconditional(options) => {
                let name = quoted(name).ok_or(RuleChainError::UnrecognizedRules)?;
                let reached = if name == "*" {
                    walk_children(path, read, depth + 1)?
                } else if let Some(parent) = name.strip_suffix("/*") {
                    let parent = anchor_path(path, parent)?;
                    walk_children(&parent, read, depth + 1)?
                } else {
                    let child = anchor_path(path, name)?;
                    walk_rules(&child, read, depth + 1)?
                };
                if reached {
                    return Ok(true);
                }
            }
            _ => return Err(RuleChainError::UnrecognizedRules),
        }
    }
    Ok(false)
}

fn quoted(field: &str) -> Option<&str> {
    field.strip_prefix('"')?.strip_suffix('"')
}

fn unconditional(options: &[&str]) -> bool {
    let options = options.strip_prefix(&["out"]).unwrap_or(options);
    matches!(options, ["all"] | ["from", "any", "to", "any"])
}

fn walk_children(
    parent: &str,
    read: &mut RulesRead<'_>,
    depth: usize,
) -> Result<bool, RuleChainError> {
    let anchors = read(&read_args(parent, "Anchors"))?;
    let mut children = Vec::new();
    let prefix = child_path(parent, "");
    for line in anchors
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let name = quoted(line).unwrap_or(line);
        let name = name.strip_prefix(&prefix).unwrap_or(name);
        if !valid_name(name) {
            return Err(RuleChainError::UnrecognizedRules);
        }
        children.push(name);
    }
    // Darwin evaluates wildcard children in strcmp order, not display order.
    children.sort_unstable();
    for child in children {
        if walk_rules(&child_path(parent, child), read, depth)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
