pub mod api;
pub mod bootstrap;
pub mod cache;
pub mod config;
pub mod dns;
pub mod proxy;
pub mod utils;

pub mod app {
    pub mod net {
        pub type OutboundInterface = crate::utils::interface::InterfaceInfo;
    }
}

pub mod common {
    pub mod errors {
        pub fn new_io_error<T: std::fmt::Display + Send + Sync + 'static>(
            msg: T,
        ) -> std::io::Error {
            std::io::Error::other(msg.to_string())
        }
    }
}

#[cfg(feature = "premium")]
pub mod premium;

#[cfg(all(feature = "premium", any(target_os = "android", feature = "jni")))]
pub use premium::android;

#[cfg(all(
    feature = "premium",
    any(
        target_os = "ios",
        all(target_os = "macos", feature = "apple-network-extension")
    )
))]
pub use premium::apple;
