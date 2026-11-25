// Test-only driver. See docs/cold-login-pf-timing.md for the signed watchdog contract.
#[cfg(target_os = "macos")]
#[path = "cold-login-pf-timing/macos.rs"]
mod macos;

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    macos::main()
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("cold-login-pf-timing requires macOS");
    std::process::ExitCode::FAILURE
}
