//! Drop-in replacement for `anyhow::Context` that records where the context
//! was attached. Release builds on Windows and iOS ship without symbols, so a
//! captured backtrace only shows `<unknown>` frames; the source location is
//! compiled in and survives stripping.

use std::fmt;
use std::panic::Location;

/// A context message tagged with the call site that attached it.
pub struct Located<C> {
    context: C,
    location: &'static Location<'static>,
}

impl<C: fmt::Display> fmt::Display for Located<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}:{}]",
            self.context,
            self.location.file(),
            self.location.line()
        )
    }
}

impl<C: fmt::Display> fmt::Debug for Located<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Same methods as `anyhow::Context`, but every context carries `[file:line]`.
pub trait Context<T> {
    fn context<C>(self, context: C) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E> Context<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    #[track_caller]
    fn context<C>(self, context: C) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into().context(Located {
                context,
                location: Location::caller(),
            })),
        }
    }

    #[track_caller]
    fn with_context<C, F>(self, f: F) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(e.into().context(Located {
                context: f(),
                location: Location::caller(),
            })),
        }
    }
}

impl<T> Context<T> for Option<T> {
    #[track_caller]
    fn context<C>(self, context: C) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        match self {
            Some(v) => Ok(v),
            None => Err(anyhow::Error::msg(Located {
                context,
                location: Location::caller(),
            })),
        }
    }

    #[track_caller]
    fn with_context<C, F>(self, f: F) -> anyhow::Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(v) => Ok(v),
            None => Err(anyhow::Error::msg(Located {
                context: f(),
                location: Location::caller(),
            })),
        }
    }
}

/// Route panics into the log with their source location. The default hook
/// writes to stderr, which is not captured on iOS or by elevated Windows runs.
pub fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                *s
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.as_str()
            } else {
                "Box<dyn Any>"
            };
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown location".to_string());
            let thread = std::thread::current();
            let thread = thread.name().unwrap_or("<unnamed>");
            tracing::error!("thread '{}' panicked at {}: {}", thread, location, msg);
            default_hook(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::Context;

    #[test]
    fn context_records_call_site() {
        let err = "x".parse::<u8>().context("parse port").unwrap_err();
        let line = line!() - 1;
        let text = format!("{:#}", err);
        assert!(
            text.starts_with(&format!("parse port [src/utils/error.rs:{}]: ", line)),
            "{}",
            text
        );
        assert!(err.downcast_ref::<std::num::ParseIntError>().is_some());
    }

    #[test]
    fn with_context_on_option_and_anyhow() {
        let none: Option<u8> = None;
        let err = none.with_context(|| format!("missing {}", "tag")).unwrap_err();
        assert!(format!("{}", err).starts_with("missing tag [src/utils/error.rs:"));

        let inner: anyhow::Result<()> = Err(anyhow::anyhow!("inner"));
        let err = inner.context("outer").unwrap_err();
        let text = format!("{:#}", err);
        assert!(text.contains("outer [src/utils/error.rs:"), "{}", text);
        assert!(text.ends_with(": inner"), "{}", text);
    }
}
