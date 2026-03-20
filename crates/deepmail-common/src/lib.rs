//! DeepMail Common — Shared library for the DeepMail platform.
//!
//! Provides configuration, error types, database access, Redis queue,
//! data models, upload validation, and utility functions used by both
//! the API server and worker processes.

pub mod audit;
pub mod cache;
pub mod config;
pub mod db;
pub mod errors;
pub mod models;
pub mod queue;
pub mod quota;
pub mod reuse;
pub mod upload;
pub mod utils;
