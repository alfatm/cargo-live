//! Credential broker: agent providers, client forwarding, phase-gated
//! per-job brokers and the helper modes that git, Cargo and Docker run.

pub mod audit;
pub mod broker;
pub mod config;
pub mod github;
pub mod helpers;
pub mod providers;
pub mod resolve;

pub use broker::Broker;
pub use config::AgentCreds;
pub use resolve::{CredSession, ToClient};
