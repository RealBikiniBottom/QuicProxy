use crate::config::LogConfig;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};

#[cfg(any(
    target_os = "ios",
    all(target_os = "macos", feature = "apple-network-extension")
))]
mod nslog_writer {
    use std::ffi::CString;
    use std::io::{self, Write};
    use std::sync::Mutex;

    static LINE_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    type LogCallback = extern "C" fn(*const std::ffi::c_char, *const std::ffi::c_char);
    static LOG_CALLBACK: Mutex<Option<LogCallback>> = Mutex::new(None);

    #[unsafe(no_mangle)]
    pub extern "C" fn quicproxy_set_log_callback(callback: Option<LogCallback>) {
        *LOG_CALLBACK.lock().unwrap() = callback;
    }

    pub struct NsLogMakeWriter;

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for NsLogMakeWriter {
        type Writer = NsLogWriter<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            NsLogWriter {
                _lifetime: std::marker::PhantomData,
            }
        }
    }

    pub struct NsLogWriter<'a> {
        _lifetime: std::marker::PhantomData<&'a ()>,
    }

    impl Write for NsLogWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut line_buf = LINE_BUF.lock().unwrap();
            line_buf.extend_from_slice(buf);

            while let Some(nl_pos) = line_buf.iter().position(|&b| b == b'\n') {
                let line = &line_buf[..nl_pos];
                emit_nslog(line);
                line_buf.drain(..=nl_pos);
            }

            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let mut line_buf = LINE_BUF.lock().unwrap();
            if !line_buf.is_empty() {
                emit_nslog(&line_buf);
                line_buf.clear();
            }
            Ok(())
        }
    }

    fn emit_nslog(data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let msg = String::from_utf8_lossy(data);
        let msg = msg.trim_end();
        if msg.is_empty() {
            return;
        }

        let level = if msg.starts_with("ERROR") {
            "error"
        } else if msg.starts_with("WARN") || msg.starts_with(" WARN") {
            "warn"
        } else if msg.starts_with("INFO") || msg.starts_with(" INFO") {
            "info"
        } else {
            "debug"
        };

        let Ok(c_level) = CString::new(level) else {
            return;
        };
        let Ok(c_msg) = CString::new(msg.as_bytes()) else {
            return;
        };
        let callback = *LOG_CALLBACK.lock().unwrap();
        if let Some(callback) = callback {
            callback(c_level.as_ptr(), c_msg.as_ptr());
        }
    }
}

#[cfg(any(
    target_os = "ios",
    all(target_os = "macos", feature = "apple-network-extension")
))]
pub use nslog_writer::quicproxy_set_log_callback;

struct SizeLimitedFileAppender {
    path: PathBuf,
    max_size: u64,
    current_size: u64,
    file: Option<File>,
}

impl SizeLimitedFileAppender {
    fn new(path: PathBuf, max_size: u64) -> Self {
        let current_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            max_size,
            current_size,
            file: None,
        }
    }

    fn open_file(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.file = Some(file);
        }
        Ok(self
            .file
            .as_mut()
            .expect("file should be Some after open_file"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        let old_path = self.path.with_extension("log.old");
        if self.path.exists() {
            let _ = std::fs::rename(&self.path, &old_path);
        }
        self.current_size = 0;
        self.open_file()?;
        Ok(())
    }
}

impl Write for SizeLimitedFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.current_size + buf.len() as u64 > self.max_size {
            let _ = self.rotate();
        }
        let n = self.open_file()?.write(buf)?;
        self.current_size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
}

pub fn init_logging(
    log_config: &LogConfig,
) -> (
    tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>,
    Option<tracing_appender::non_blocking::WorkerGuard>,
) {
    /// A token type whose Drop ensures the layers stay alive.
    struct LogGuard {
        _reload_handle: tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>,
        _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    }

    static INIT: OnceLock<LogGuard> = OnceLock::new();
    if INIT.get().is_some() {
        // Already initialized in an earlier call (e.g. from apple.rs).
        // Return dummy handles so callers can still forget them.
        let (filter, reload_handle) = reload::Layer::new(EnvFilter::new("off"));
        return (reload_handle, None);
    }

    let (log_enabled, log_level, log_path, log_color, log_stdout, log_max_size, backtrace_mode) =
        match log_config {
            LogConfig::Level(l) => (
                true,
                l.as_str(),
                None,
                true,
                true,
                None,
                &crate::config::BacktraceMode::On,
            ),
            LogConfig::Detailed {
                enable,
                level,
                path,
                color,
                stdout,
                max_size,
                backtrace,
            } => (
                *enable,
                level.as_str(),
                path.as_deref(),
                *color,
                *stdout,
                *max_size,
                backtrace,
            ),
        };

    if !log_enabled {
        let (filter, reload_handle) = reload::Layer::new(EnvFilter::new("off"));
        tracing_subscriber::registry().with(filter).try_init().ok();
        return (reload_handle, None);
    }

    unsafe {
        std::env::set_var("RUST_BACKTRACE", backtrace_mode.as_env_value());
    }

    // Initialize logging with reload capability
    let (filter, reload_handle) = reload::Layer::new(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
    );

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_error::ErrorLayer::default());

    let mut file_guard = None;

    let fmt_layer_file = if let Some(path) = log_path {
        let path_buf = PathBuf::from(path);
        let dir = path_buf
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        // Ensure log directory exists
        if !dir.as_os_str().is_empty() && !dir.exists() {
            let _ = std::fs::create_dir_all(dir);
        }

        let (non_blocking, guard) = if let Some(max_size) = log_max_size {
            tracing_appender::non_blocking(SizeLimitedFileAppender::new(path_buf, max_size))
        } else {
            let filename = path_buf
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("quicproxy.log"));
            let file_appender = tracing_appender::rolling::never(dir, filename);
            tracing_appender::non_blocking(file_appender)
        };
        file_guard = Some(guard);

        Some(
            fmt::layer()
                .with_ansi(log_color)
                .with_file(true)
                .with_line_number(true)
                .with_target(false)
                .with_writer(non_blocking)
                .without_time(),
        )
    } else {
        None
    };

    let stdout_layer = if log_stdout {
        #[cfg(target_os = "android")]
        {
            match tracing_android::layer("quicproxy") {
                Ok(layer) => Some(layer),
                Err(error) => {
                    eprintln!("failed to create Android logcat layer: {error}");
                    None
                }
            }
        }

        #[cfg(not(target_os = "android"))]
        {
            let layer = fmt::layer()
                .with_ansi(log_color)
                .with_file(true)
                .with_line_number(true)
                .with_target(false)
                .without_time();

            #[cfg(any(
                target_os = "ios",
                all(target_os = "macos", feature = "apple-network-extension")
            ))]
            let layer = layer
                .with_ansi(false)
                .with_writer(nslog_writer::NsLogMakeWriter);

            #[cfg(not(any(
                target_os = "ios",
                all(target_os = "macos", feature = "apple-network-extension")
            )))]
            let layer = layer.with_writer(std::io::stdout);

            Some(layer)
        }
    } else {
        None
    };

    registry
        .with(fmt_layer_file)
        .with(stdout_layer)
        .try_init()
        .ok();

    // Store the real handles in OnceLock; return dummy handles so that
    // callers can forget them safely without affecting the held guards.
    let _ = INIT.set(LogGuard {
        _reload_handle: reload_handle,
        _file_guard: file_guard,
    });
    let (_, dummy_reload) = reload::Layer::new(EnvFilter::new("off"));
    (dummy_reload, None)
}
