pub mod common;
pub mod core_api;
pub mod core_manager;
pub mod management;
pub mod persist_handler;
pub mod persist_store;
pub mod reverse_proxy;
pub mod static_files;
pub mod sysinfo_api;

// 保持历史兼容：bootstrap.rs 使用 `crate::api::init_api`
pub use core_api::init_core_api as init_api;

// selector.rs 使用 `crate::api::get_outbound_info`
pub use core_api::get_outbound_info;
pub use core_api::TraceResponse;
