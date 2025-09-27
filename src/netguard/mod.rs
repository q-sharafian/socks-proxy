pub mod dummy_netguard;
mod grpc_netguard;
use bytes::Bytes;
use thiserror::Error;
use std::{fmt::Display, net::{Ipv4Addr, Ipv6Addr}};
use std::future::Future;
use std::hash::Hash;
use std::hash::Hasher;
use std::collections::HashMap;

#[derive(Debug, Error)]
pub enum NetGuardError {
  #[error("user {username} not found")]
  UserNotFound { username: String },
  #[error("authentication of the username failed: {0}")]
  AuthFailed(String),
  #[error("net-usage limit reached (i.e. usage volume exhausted): {0}")]
  LimitReached(String),
  #[error("authentication token expired")]
  AuthTokenExpired,
  #[error("internal error: {0}")]
  InternalError(String)
}

#[derive(Debug)]
pub struct NetUsage {
  /// In bytes
  pub read_rate: u64,
  /// In bytes
  pub write_rate: u64,
}

impl Display for NetUsage {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "read: {}, write: {}", self.read_rate, self.write_rate)
  }
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub enum NetAddrType {
  IPV4(Ipv4Addr),
  IPV6(Ipv6Addr),
  Domain(Bytes),
}

#[derive(Debug)]
pub enum NetBanStatus {
  /// Restricted by the goverment/country
  Restricted,
  /// Blocked by the user
  Blocked,
  /// Is allowed to use
  Allowed
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SocksAuth {
  pub username: Bytes,
  pub password: Bytes
}

pub const NONE_SOCKS_AUTH: SocksAuth = SocksAuth {
  username: Bytes::new(),
  password: Bytes::new()
};

impl SocksAuth {
  pub fn username2string(&self) -> String {
    String::from_utf8_lossy(&self.username).to_string()
  }
}

/// The implementation of this trait should be thread-safe.
pub trait NetGuard: Send + Sync {
  /// Generate authentication token.
  ///
  /// ## Some possible errors:
  /// - UserNotFound
  /// - AuthFailed
  /// - InternalError
  fn generate_token(&mut self, auth: &SocksAuth) -> impl Future<Output = Result<Bytes, NetGuardError>> + Send;
  /// Validate authentication token.
  /// 
  /// ## Some possible erros:
  /// - AuthFailed
  /// - UserNotFound
  /// - InternalError
  /// - AuthTokenExpired
  async fn validate_token(&mut self, token: &Bytes) -> Result<(), NetGuardError>;
  /// Check if such user could use specified net address
  /// 
  /// ## Some possible errors:
  /// - AuthFailed
  /// - InternalError
  /// - AuthTokenExpired
  fn is_allowed(&mut self, token: &Bytes, net_type: NetAddrType) -> impl std::future::Future<Output = Result<bool, NetGuardError>> + Send;
  /// Store net usage rate.
  /// 
  /// ## Some possible errors:
  /// - InternalError
  /// - LimitReached
  /// - AuthTokenExpired
  async fn set_net_usage(&mut self, token: &Bytes, net_usage: NetUsage) -> Result<(), NetGuardError>;
}

pub use dummy_netguard::DummyNetGuard;