//! SudoStamp on the desktop (docs/DESKTOP.md).
//!
//! Everything here is per-user and unprivileged: it holds no key, is not in the PAM stack and cannot
//! approve anything. The pure modules take their input as arguments and do no I/O, so every parser
//! of untrusted bytes is unit-tested in isolation; the edges (`listener`, `notify`, `tray`, `exec`,
//! `window`, `daemon`) only move bytes between them and the desktop.
#![forbid(unsafe_code)]

// Pure.
pub mod agent;
pub mod doctor;
pub mod engine;
pub mod event;
pub mod history;
pub mod keys;
pub mod pam;
pub mod paths;
pub mod pause;
pub mod setup;
pub mod state;
pub mod text;
pub mod track;

#[cfg(test)]
mod testutil;
