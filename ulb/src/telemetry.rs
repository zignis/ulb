use std::{
    borrow::Cow,
    cell::Cell,
    io::Write,
    sync::OnceLock,
};

use anstyle::{
    AnsiColor,
    Color,
    Style,
};
use env_logger::Builder;
use indicatif::{
    MultiProgress,
    ProgressStyle,
};
use indicatif_log_bridge::LogWrapper;
use log::Level;

pub static TLM_MULTI_PROGRESS: OnceLock<MultiProgress> = OnceLock::new();

thread_local! {
    static IS_BPF_LOG_CTX: Cell<bool> = const{ Cell::new(false) };
}

#[cfg(feature = "debug")]
struct KernelCtxGuard;

#[cfg(feature = "debug")]
impl Drop for KernelCtxGuard {
    fn drop(&mut self) {
        IS_BPF_LOG_CTX.with(|x| x.set(false));
    }
}

/// log message from ebpf
#[cfg(feature = "debug")]
pub(super) fn bpf_log_closure<F: FnOnce()>(f: F) {
    IS_BPF_LOG_CTX.with(|x| x.set(true));
    let _ctx = KernelCtxGuard;
    f();
}

#[derive(Debug)]
enum MsgType {
    Debug,
    Warn,
    Error,
}

impl TryFrom<&str> for MsgType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, <MsgType as TryFrom<&str>>::Error> {
        if value.len() < 5 {
            return Err(());
        }

        match &value[..3] {
            "[D:" => Ok(Self::Debug),
            "[W:" => Ok(Self::Warn),
            "[E:" => Ok(Self::Error),
            _ => Err(()),
        }
    }
}

impl MsgType {
    pub fn get_style(&self) -> Option<Style> {
        match self {
            Self::Warn => Some(
                Style::new()
                    .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
                    .bold(),
            ),
            Self::Error => Some(
                Style::new()
                    .fg_color(Some(Color::Ansi(AnsiColor::Red)))
                    .bold(),
            ),
            _ => None,
        }
    }
}

/// parses a telemetry prefix `[D:X]`, `[W:X]` or `[E:X]` from the message and
/// extract the depth from it. returns `(depth, type, rest_of_msg)`.
fn parse_message(msg: &str) -> (usize, Option<MsgType>, &str) {
    if let Ok(msg_type) = MsgType::try_from(msg)
        && let Some((depth_str, rest)) = msg[3..].split_once(']')
        && let Ok(depth) = depth_str.parse::<usize>()
    {
        return (depth, Some(msg_type), rest.trim_start());
    }

    (0, None, msg)
}

fn generate_tree_indent(depth: usize) -> String {
    if depth == 0 {
        return String::new();
    }

    let mut indent = String::with_capacity(depth * 4);
    indent.push_str(&"┃   ".repeat(depth - 1));
    indent.push_str("┣━ ");
    indent
}

fn get_style(level: Level, msg_type: Option<MsgType>, is_kernel: bool) -> Style {
    if let Some(style) = msg_type.and_then(|x| x.get_style()) {
        return style;
    }

    match (level, is_kernel) {
        (Level::Error, _) => Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Red)))
            .bold(),
        (Level::Warn, _) => Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Yellow)))
            .bold(),
        (Level::Info, true) => Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Green)))
            .bold(),
        (Level::Info, false) => Style::new()
            .fg_color(Some(Color::Ansi(AnsiColor::Blue)))
            .bold(),
        (Level::Debug, true) => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))),
        (Level::Debug, false) => Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
        (Level::Trace, _) => Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack))),
    }
}

pub fn init(fancy: bool) {
    let logger = Builder::from_default_env()
        .format(|buf, record| {
            let target = record.target();
            let module = target.split("::").last().unwrap_or(target);
            let message = format!("{}", record.args());
            let (depth, msg_type, remainder) = parse_message(&message);
            let indent_branch = generate_tree_indent(depth);
            let is_kernel = IS_BPF_LOG_CTX.with(|c| c.get());
            let style = get_style(record.level(), msg_type, is_kernel);
            let tree_style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack)));

            writeln!(
                buf,
                "{}{}{}{}[{}]{} {}",
                tree_style.render(),
                indent_branch,
                tree_style.render_reset(),
                style.render(),
                module,
                style.render_reset(),
                remainder
            )
        })
        .build();

    let max_level = logger.filter();

    if fancy {
        let multi = MultiProgress::new();
        LogWrapper::new(multi.clone(), logger)
            .try_init()
            .expect("failed to set logger");

        TLM_MULTI_PROGRESS
            .set(multi)
            .expect("failed to set multi progress");
    } else {
        log::set_boxed_logger(Box::new(logger)).expect("failed to set logger");
    }

    log::set_max_level(max_level);
}

//

pub struct ProgressBar(Option<indicatif::ProgressBar>);

impl ProgressBar {
    pub fn new<M>(size: u64, msg: M) -> Self
    where
        M: Into<Cow<'static, str>>,
    {
        match TLM_MULTI_PROGRESS.get() {
            Some(multi) => {
                let pb = multi.add(indicatif::ProgressBar::new(size));
                pb.set_style(
                    ProgressStyle::with_template(
                        "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
                    )
                    .expect("template failed")
                    .progress_chars("##-"),
                );
                pb.set_message(msg);

                Self(Some(pb))
            }

            None => Self(None),
        }
    }

    pub fn enabled(&self) -> bool {
        self.0.is_some()
    }

    pub fn inc(&self) {
        if let Some(pb) = &self.0 {
            pb.inc(1);
        }
    }

    pub fn finish<M>(&self, msg: M)
    where
        M: Into<Cow<'static, str>>,
    {
        if let Some(pb) = &self.0 {
            pb.finish_with_message(msg);
        }
    }
}
