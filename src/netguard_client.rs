use crate::cache::Cache;
use crate::netguard::{NONE_SOCKS_AUTH, NetAddrType, NetGuard, NetUsage, SocksAuth};
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;
pub type NGClientCache<T> = Arc<Mutex<T>>;
pub type NGClientNetGuard<T> = Arc<Mutex<T>>;
use std::thread;

/// Each connection has a NetGuardClient.
#[derive(Debug, Clone)]
pub struct NetGuardClient<T: NetGuard, U: Cache<SocksAuth, Bytes>> {
  netguard: NGClientNetGuard<T>,
  auth: Option<SocksAuth>,
  /// Return true if the user has been authenticated at least once.
  is_authed: bool,
  cache: NGClientCache<U>,
  /// Just used for testing purposes
  id: u32,
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

impl<'a, T: NetGuard, U: Cache<SocksAuth, Bytes>> NetGuardClient<T, U> {
  /// Create a new NetGuardClient.
  pub fn new(netguard: NGClientNetGuard<T>, cache: NGClientCache<U>) -> NetGuardClient<T, U> {
    NetGuardClient {
      auth: None,
      netguard,
      cache,
      is_authed: false,
      id: rand::random::<u32>(),
    }
  }

  /// Return true if the user has been authenticated at least once.
  pub fn is_authed(&self) -> bool {
    trace!(
      "Checking is_authed for user '{}' (id: {}): {}",
      if let Some(auth) = &self.auth {
        auth.username2string()
      } else {
        "None".to_string()
      },
      self.id,
      self.is_authed
    );

    // self.is_authed
    true
  }

  /// Authenticate the user. If the user authneticated, return OK.
  /// If the input be equals `NONE_SOCKS_AUTH`, authenticate the user and return OK.
  ///
  /// # Some possible errors:
  /// * `AuthFailed`: authentication failed
  pub async fn authenticate(&mut self, auth: SocksAuth) -> Result<(), NetGuardClientError> {
    trace!("Authenticating user: '{}', id: {}", auth, self.id);
    if auth == NONE_SOCKS_AUTH {
      trace!("Authenticate with NONE_SOCKS_AUTH");
      self.auth = Some(auth);
      self.is_authed = true;
      return Ok(());
    }

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
        Err(e) => {
          trace!("Failed to generate token: {}", e);
          return Err(NetGuardClientError::AuthFailed(e.to_string()));
        }
      }
      self
        .cache
        .clone()
        .lock()
        .await
        .put(auth.clone(), auth_token.clone())
        .await
        .unwrap_or_else(|_| {
          trace!("Failed to put auth-token to the cache");
        });
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
    if self.is_authed() == false {
      panic!(
        "The netguard client is not authenticated during sending net-usage to the server. (id: {})",
        self.id
      );
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

  /// It's the same `add_net_usage` but it's syncronous call.
  pub fn sync_add_net_usage(self: Arc<Self>, net_usage: NetUsage) -> Result<(), NetGuardClientError>
  where
    T: 'static,
    U: 'static,
  {
    let s = self.clone();
    tokio::spawn(async move {
      if let Err(e) = s.add_net_usage(net_usage.clone()).await {
        warn!(
          "It seems usage-rate doesn't send to the accounting system correctly (ACCOUNTING_FAILED_ERR_1172): {} ({})",
          net_usage, e
        )
      }
    });
    Ok(())
  }
}
