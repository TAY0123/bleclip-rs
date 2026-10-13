use crate::wire::MAX_TEXT;
use anyhow::{Context, Result};
use arboard::Clipboard;
use clap::ValueEnum;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Direction {
    Both,
    Send,
    Receive,
}

impl Direction {
    pub fn can_send(self) -> bool {
        self != Self::Receive
    }
    pub fn can_receive(self) -> bool {
        self != Self::Send
    }
}

pub struct ClipboardSync {
    // Keep the Clipboard handle alive: required for clipboard ownership on X11/Wayland.
    clipboard: Clipboard,
    last_text: Option<String>,
    direction: Direction,
}

impl ClipboardSync {
    pub fn new(direction: Direction) -> Result<Self> {
        let mut clipboard = Clipboard::new().context("cannot access desktop clipboard; run in a GUI session")?;
        let last_text = clipboard.get_text().ok();
        Ok(Self { clipboard, last_text, direction })
    }

    pub fn direction(&self) -> Direction { self.direction }

    /// Only a *new* clipboard change is transmitted, never preexisting clipboard data.
    pub fn check_local_change(&mut self) -> Option<String> {
        if !self.direction.can_send() { return None; }
        let Ok(text) = self.clipboard.get_text() else { return None };
        if self.last_text.as_deref() == Some(text.as_str()) { return None; }
        self.last_text = Some(text.clone());
        if text.len() > MAX_TEXT {
            eprintln!("Clipboard change skipped: {} bytes exceeds maximum {}", text.len(), MAX_TEXT);
            return None;
        }
        Some(text)
    }

    /// Updates local state before applying the remote value; prevents echo loops.
    pub fn apply_remote(&mut self, text: &str) -> Result<bool> {
        if !self.direction.can_receive() { return Ok(false); }
        if self.last_text.as_deref() == Some(text) { return Ok(false); }
        // Only suppress an echo after the write succeeds.
        self.clipboard.set_text(text.to_owned()).context("failed to write desktop clipboard")?;
        self.last_text = Some(text.to_owned());
        Ok(true)
    }
}
