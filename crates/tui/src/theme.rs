//! Color palette and border styles for the TUI.
//!
//! Kept in one place so views stay visually consistent and the palette
//! can be tweaked (or themed) without touching view code.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Block;

/// The application's color palette.
pub struct Theme;

impl Theme {
    /// Border color for the active view.
    pub const fn border_active() -> Color {
        Color::Cyan
    }
    /// Border color for inactive views.
    pub const fn border_dim() -> Color {
        Color::DarkGray
    }
    /// Color for the top/bottom status bars.
    pub const fn bar_bg() -> Color {
        Color::Black
    }
    /// Color for headings.
    pub const fn heading() -> Color {
        Color::Yellow
    }
    /// Color for `info` severity alerts.
    pub const fn info() -> Color {
        Color::Blue
    }
    /// Color for `warning` severity alerts.
    pub const fn warning() -> Color {
        Color::Yellow
    }
    /// Color for `critical` severity alerts.
    pub const fn critical() -> Color {
        Color::Red
    }
    /// Color for error text.
    pub const fn error() -> Color {
        Color::Red
    }
    /// Color for the "reachable" indicator in the status bar.
    pub const fn ok() -> Color {
        Color::Green
    }
    /// Color for muted/secondary text.
    pub const fn muted() -> Color {
        Color::DarkGray
    }
}

/// A bordered block for the active view.
pub fn active_block(title: &str) -> Block<'_> {
    Block::bordered()
        .title(format!(" {title} "))
        .border_style(Style::default().fg(Theme::border_active()))
}

/// A bordered block for an inactive/secondary panel.
pub fn dim_block(title: &str) -> Block<'_> {
    Block::bordered()
        .title(format!(" {title} "))
        .border_style(Style::default().fg(Theme::border_dim()))
}

/// Style for the status bar.
pub fn bar_style() -> Style {
    Style::default()
        .bg(Theme::bar_bg())
        .add_modifier(Modifier::BOLD)
}

/// Style for a heading.
pub fn heading_style() -> Style {
    Style::default()
        .fg(Theme::heading())
        .add_modifier(Modifier::BOLD)
}
