/// Returns whether the current compilation target is Android.
pub const fn is_android() -> bool {
    cfg!(target_os = "android")
}

/// Returns whether the current compilation target is iOS.
pub const fn is_ios() -> bool {
    cfg!(target_os = "ios")
}

/// Returns whether the current compilation target is macOS.
pub const fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Returns whether the current compilation target is Windows.
pub const fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

/// Returns whether the current compilation target is Linux.
pub const fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Returns whether the current compilation target is an Apple platform.
pub const fn is_apple() -> bool {
    is_ios() || is_macos()
}

/// Returns whether the current compilation target is a mobile platform.
pub const fn is_mobile() -> bool {
    is_android() || is_ios()
}

/// Returns whether the current compilation target is a supported desktop platform.
pub const fn is_desktop() -> bool {
    is_macos() || is_windows() || is_linux()
}

