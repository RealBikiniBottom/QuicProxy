#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub const MIMALLOC_PURGE_DELAY: Option<&str> = option_env!("MIMALLOC_PURGE_DELAY");

#[cfg(feature = "mimalloc")]
const MI_OPTION_PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

pub fn apply_mimalloc_options() -> Option<i64> {
    #[cfg(feature = "mimalloc")]
    {
        if std::env::var_os("MIMALLOC_PURGE_DELAY").is_some() {
            return None;
        }
        let delay: std::ffi::c_long = MIMALLOC_PURGE_DELAY?.trim().parse().ok()?;
        unsafe {
            libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, delay);
        }
        Some(delay as i64)
    }
    #[cfg(not(feature = "mimalloc"))]
    None
}
