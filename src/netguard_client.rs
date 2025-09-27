use crate::cache::Cache;
use crate::netguard::{NetAddrType, NetGuard, NetUsage, SocksAuth};
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
pub type NGClientCache<T: Cache<SocksAuth, Bytes>> = Arc<Mutex<T>>;
pub type NGClientNetGuard<T: NetGuard> = Arc<Mutex<T>>;

/// Each connection has a NetGuardClient.
#[derive(Debug, Clone)]
pub struct NetGuardClient<T: NetGuard, U: Cache<SocksAuth, Bytes>> {
  netguard: NGClientNetGuard<T>,
  auth: Option<SocksAuth>,
  /// Return true if the user has been authenticated at least once.
  is_authed: bool,
  cache: NGClientCache<U>,
}

#[derive(Debug, Error)]
pub enum NetGuardClientError {
  #[error("user {username} not found")]
  UserNotFound { username: String },
  #[error("authentication of the username failed: {0}")]
  AuthFailed(String),
  #[error("net-usage limit reached: {0}")]
  LimitReached(String),
  #[error("internal error: {0}")]
  InternalError(String),
}

impl<T: NetGuard, U: Cache<SocksAuth, Bytes>> NetGuardClient<T, U> {
  /// Create a new NetGuardClient.
  pub fn new(netguard: NGClientNetGuard<T>, cache: NGClientCache<U>) -> Self {
    let netguard_client = NetGuardClient {
      auth: None,
      netguard,
      cache,
      is_authed: false,
    };
    netguard_client
  }

  /// Return true if the user has been authenticated at least once.
  pub fn is_authed(&self) -> bool {
    self.is_authed
  }

  /// Authenticate the user. If the user authneticated, return OK.
  ///
  /// # Some possible errors:
  /// * `AuthFailed`: authentication failed
  pub async fn authenticate(&mut self, auth: SocksAuth) -> Result<(), NetGuardClientError> {
    let c = self.cache.clone();
    if let Some(_token) = c.lock().await.get(auth.clone()).await {
      self.auth = Some(auth);
      self.is_authed = true;
    } else {
      let auth_token: Bytes;
      let result = self
        .netguard
        .clone()
        .lock()
        .await
        .generate_token(&auth)
        .await;
      match result {
        Ok(token) => {
          auth_token = token;
        }
        Err(e) => return Err(NetGuardClientError::AuthFailed(e.to_string())),
      }
      self
        .cache
        .clone()
        .lock()
        .await
        .put(auth.clone(), auth_token.clone());
      self.auth = Some(auth);
      self.is_authed = true;
    }

    Ok(())
  }

  pub async fn is_allowed(
    &self,
    auth: SocksAuth,
    net_type: NetAddrType,
  ) -> Result<bool, NetGuardClientError> {
    if !self.is_authed {
      return Err(NetGuardClientError::UserNotFound {
        username: String::from_utf8(auth.username.clone().to_vec())
          .unwrap_or_else(|_| "parse-error".to_string()),
      });
    }
    let token = match self.cache.clone().lock().await.get(auth.clone()).await {
      Some(token) => token,
      None => {
        let result = self
          .netguard
          .clone()
          .lock()
          .await
          .generate_token(&auth)
          .await;
        match result {
          Ok(token) => token,
          Err(e) => return Err(NetGuardClientError::AuthFailed(e.to_string())),
        }
      }
    };

    let result = self
      .netguard
      .clone()
      .lock()
      .await
      .is_allowed(&token, net_type)
      .await;
    return result.map_err(|e| NetGuardClientError::InternalError(e.to_string()));
  }

  pub async fn add_net_usage(&self, net_usage: NetUsage) -> Result<(), NetGuardClientError> {
    if self.is_authed == false {
      panic!("The netguard client is not authenticated during sending net-usage to the server")
    }

    let token: Bytes;
    match self
      .cache
      .clone()
      .lock()
      .await
      .get(self.auth.clone().unwrap())
      .await
    {
      Some(t) => token = t,
      None => {
        let result = self
          .netguard
          .clone()
          .lock()
          .await
          .generate_token(&self.auth.clone().unwrap())
          .await;
        match result {
          Err(e) => return Err(NetGuardClientError::AuthFailed(e.to_string())),
          Ok(t) => token = t,
        }
      }
    };

    match self
      .netguard
      .clone()
      .lock()
      .await
      .set_net_usage(&token, net_usage)
      .await
    {
      Ok(_) => Ok(()),
      Err(e) => return Err(NetGuardClientError::InternalError(e.to_string())),
    }
  }
}
