use super::*;

fn into_string(text: String) -> *mut c_char {
    CString::new(text).map_or(std::ptr::null_mut(), CString::into_raw)
}

#[no_mangle]
extern "C" fn ac_login_direct_interface() -> *mut c_char {
    crate::connections::default_route_interface()
        .filter(|name| name.starts_with("en"))
        .map(into_string)
        .unwrap_or(std::ptr::null_mut())
}

// The Swift declarations pass borrowed, NUL-terminated UTF-8 strings.
fn string_ptr<T>(pointer: *const c_char, f: impl FnOnce(&str) -> T) -> Option<T> {
    if pointer.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(pointer) }.to_str().ok().map(f)
}

fn gateway(host: *const c_char, port: u16) -> Option<Gateway> {
    string_ptr(host, |host| Gateway::new(host, port)).flatten()
}

#[no_mangle]
extern "C" fn ac_login_cache_lookup(
    dir: *const c_char,
    host: *const c_char,
    port: u16,
) -> *mut c_char {
    let peers = string_ptr(dir, |dir| {
        string_ptr(host, |host| lookup(Path::new(dir), host, port))
    })
    .flatten()
    .unwrap_or_default();
    into_string(peers.join(","))
}

#[no_mangle]
extern "C" fn ac_login_cache_remember(
    dir: *const c_char,
    host: *const c_char,
    port: u16,
    address: *const c_char,
) -> bool {
    let result = string_ptr(dir, |dir| {
        string_ptr(host, |host| {
            string_ptr(address, |address| {
                remember(Path::new(dir), host, port, address).is_ok()
            })
        })
    });
    result.flatten().flatten().unwrap_or(false)
}

#[no_mangle]
extern "C" fn ac_login_preparation_new() -> *mut Preparation {
    Box::into_raw(Box::new(Preparation::default()))
}

#[no_mangle]
extern "C" fn ac_login_preparation_free(preparation: *mut Preparation) {
    if !preparation.is_null() {
        unsafe { drop(Box::from_raw(preparation)) };
    }
}

#[no_mangle]
extern "C" fn ac_login_preparation_confirm_direct(preparation: *mut Preparation) {
    if let Some(preparation) = unsafe { preparation.as_mut() } {
        preparation.confirm_direct();
    }
}

#[no_mangle]
extern "C" fn ac_login_preparation_begin(
    preparation: *mut Preparation,
    host: *const c_char,
    port: u16,
) -> u64 {
    let (Some(preparation), Some(gateway)) = (unsafe { preparation.as_mut() }, gateway(host, port))
    else {
        return 0;
    };
    preparation.begin(gateway, Instant::now()).unwrap_or(0)
}

#[no_mangle]
extern "C" fn ac_login_preparation_status(
    preparation: *const Preparation,
    host: *const c_char,
    port: u16,
) -> i32 {
    let (Some(preparation), Some(gateway)) = (unsafe { preparation.as_ref() }, gateway(host, port))
    else {
        return PreparationStatus::Idle as i32;
    };
    preparation.status(&gateway, Instant::now()) as i32
}

#[no_mangle]
extern "C" fn ac_login_preparation_finish(
    preparation: *mut Preparation,
    request: u64,
    address: *const c_char,
    certificate_rejected: bool,
) {
    if let Some(preparation) = unsafe { preparation.as_mut() } {
        let result = if certificate_rejected {
            Some(PreparedGateway::CertificateRejected)
        } else {
            string_ptr(address, parse_address)
                .flatten()
                .map(PreparedGateway::Address)
        };
        preparation.finish(request, result, Instant::now());
    }
}

#[no_mangle]
extern "C" fn ac_login_preparation_transport_failure(preparation: *mut Preparation, request: u64, timed_out: bool) {
    if let Some(preparation) = unsafe { preparation.as_mut() } {
        let reason = if timed_out { PreparedGateway::TimedOut } else { PreparedGateway::DnsFailed };
        preparation.finish(request, Some(reason), Instant::now());
    }
}

#[no_mangle]
extern "C" fn ac_login_preparation_take_result_for_intent(
    preparation: *mut Preparation,
    host: *const c_char,
    port: u16,
    certificate_rejected: *mut bool,
) -> *mut c_char {
    let result = unsafe { preparation.as_mut() }.and_then(|preparation| {
        preparation.take_for_intent(gateway(host, port).as_ref(), Instant::now())
    });
    if let Some(output) = unsafe { certificate_rejected.as_mut() } {
        *output = result == Some(PreparedGateway::CertificateRejected);
    }
    match result {
        Some(PreparedGateway::Address(address)) => into_string(address.to_string()),
        _ => std::ptr::null_mut(),
    }
}
