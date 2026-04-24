//! DeepMail Common — Shared library for the DeepMail platform.
//!
//! Provides configuration, error types, database access, Redis queue,
//! data models, upload validation, and utility functions used by both
//! the API server and worker processes.

pub mod abuse;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod db;
pub mod errors;
pub mod models;
pub mod queue;
pub mod quota;
pub mod retention;
pub mod reuse;
pub mod telemetry;
pub mod upload;
pub mod utils;

/// Generated protobuf / gRPC types for all DeepMail services.
///
/// Each sub-module corresponds to a `.proto` file in the `proto/` directory.
/// Downstream crates should import from here rather than calling `include_proto!`
/// directly, so that proto compilation happens in one place.
///
/// Usage: `use deepmail_common::proto::dkim::v1::*;`
pub mod proto {
    pub mod dkim {
        pub mod v1 {
            tonic::include_proto!("deepmail.dkim.v1");
        }
    }
    pub mod homograph {
        pub mod v1 {
            tonic::include_proto!("deepmail.homograph.v1");
        }
    }
    pub mod billing {
        pub mod v1 {
            tonic::include_proto!("deepmail.billing.v1");
        }
    }
}
