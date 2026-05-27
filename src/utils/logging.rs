use crate::config::LogConfig;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};

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
        Ok(self.file.as_mut().expect("file should be Some after open_file"))
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
    let (log_level, log_path, log_color, log_stdout, log_max_size, backtrace_mode) = match log_config {
        LogConfig::Level(l) => (l.as_str(), None, true, true, None, &crate::config::BacktraceMode::On),
        LogConfig::Detailed {
            level,
            path,
            color,
            stdout,
            max_size,
            backtrace,
        } => (level.as_str(), path.as_deref(), *color, *stdout, *max_size, backtrace),
    };

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

    let fmt_layer_stdout = if log_stdout {
        Some(
            fmt::layer()
                .with_ansi(log_color)
                .with_file(true)
                .with_line_number(true)
                .with_target(false)
                .with_writer(std::io::stdout)
                .without_time(),
        )
    } else {
        None
    };

    registry.with(fmt_layer_file).with(fmt_layer_stdout).try_init().ok();

    (reload_handle, file_guard)
}
