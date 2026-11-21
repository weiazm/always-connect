use super::*;

fn into_string(text: String) -> *mut c_char {
    CString::new(text).map_or(std::ptr::null_mut(), CString::into_raw)
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
extern "C" fn ac_login_preparation_finish(
    preparation: *mut Preparation,
    request: u64,
    address: *const c_char,
) {
    if let Some(preparation) = unsafe { preparation.as_mut() } {
        let now = Instant::now();
        if string_ptr(address, |address| {
            preparation.finish(request, Some(address), now)
        })
        .is_none()
        {
            preparation.finish(request, None, now);
        }
    }
}

#[no_mangle]
extern "C" fn ac_login_preparation_take_for_intent(
    preparation: *mut Preparation,
    host: *const c_char,
    port: u16,
) -> *mut c_char {
    let Some(preparation) = (unsafe { preparation.as_mut() }) else {
        return std::ptr::null_mut();
    };
    preparation
        .take_for_intent(gateway(host, port).as_ref(), Instant::now())
        .map_or(std::ptr::null_mut(), |address| {
            into_string(address.to_string())
        })
}
