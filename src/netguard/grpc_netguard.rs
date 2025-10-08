pub mod net_sentinel {
  tonic::include_proto!("net_sentinel");
}
use crate::cache::Cache;
use crate::netguard::grpc_netguard::net_sentinel::AuthToken;
use crate::netguard::grpc_netguard::net_sentinel::generate_auth_request::State;
use crate::netguard::{NetGuard, NetGuardError};
use net_sentinel::net_sentinel_client::NetSentinelClient;
use net_sentinel::{
  AddNetUsageRequest, AuthSocks5, GenerateAuthRequest, IsAllowedRequest, NetAddress,
  NetAddressType, ResultStatus, ValidateAuthRequest,
};
use std::time::SystemTime;

/// Used for the cache
pub struct CacheAuthTokenVal {
  is_valid: bool,
  /// when the token expires
  expires: SystemTime,
}

pub struct CacheAllowedKey {
  addr: super::NetAddrType,
  auth_token: AuthToken,
}

#[derive(Clone)]
pub struct GrpcNetGuard<A, B>
where
  A: Cache<AuthToken, CacheAuthTokenVal>,
  B: Cache<CacheAllowedKey, bool>,
{
  client: NetSentinelClient<tonic::transport::Channel>,
  auth_token_cache: A,
  /// Cache for storing allowed addresses
  allowed_cache: B,
}

impl<A, B> GrpcNetGuard<A, B>
where
  A: Cache<AuthToken, CacheAuthTokenVal>,
  B: Cache<CacheAllowedKey, bool>,
{
  /// Create a new GrpcNetGuard and initialize it.
  pub async fn new(dst_addr: String, auth_token_cache: A, allowed_addr_cache: B) -> Self {
    let client = NetSentinelClient::connect(dst_addr)
      .await
      .unwrap_or_else(|e| panic!("Failed to connect to NetGuard: {}", e));

    GrpcNetGuard {
      client,
      auth_token_cache,
      allowed_cache: allowed_addr_cache,
    }
  }
}

impl<A: Cache<AuthToken, CacheAuthTokenVal>, B: Cache<CacheAllowedKey, bool>> NetGuard
  for GrpcNetGuard<A, B>
{
  async fn generate_token(
    &mut self,
    auth: &super::SocksAuth,
  ) -> Result<bytes::Bytes, super::NetGuardError> {
    let username = String::from_utf8(auth.username.clone().to_vec());
    let password = String::from_utf8(auth.password.clone().to_vec());
    if username.is_err() || password.is_err() {
      return Err(super::NetGuardError::InternalError(format!(
        "Failed to parse username or password"
      )));
    }
    let req = tonic::Request::new(GenerateAuthRequest {
      state: Some(State::Socks5(AuthSocks5 {
        username: username.unwrap(),
        password: password.unwrap(),
      })),
    });

    let response = self.client.generate_auth_token(req).await;
    if response.is_err() {
      return Err(super::NetGuardError::InternalError(format!(
        "Failed to generate token: {}",
        response.expect_err("error")
      )));
    }
    let status = response.unwrap().into_inner();
    let result = map_grpc_status_code(status.status(), status.message);
    if result.is_some() {
      return Err(result.unwrap());
    } else {
      let _ = self
        .auth_token_cache
        .put(
          AuthToken {
            token: status.token.clone(),
          },
          CacheAuthTokenVal {
            is_valid: true,
            expires: SystemTime::now() + std::time::Duration::from_secs(status.ttl),
          },
        )
        .await;
      return Ok(status.token.into());
    }
  }

  // TODO: Implement ttl checking of token
  async fn validate_token(&mut self, token: &bytes::Bytes) -> Result<(), super::NetGuardError> {
    let auth_token = AuthToken {
      token: String::from_utf8_lossy(token).into_owned(),
    };
    match self.auth_token_cache.get(auth_token.clone()).await {
      Some(val) => {
        if !val.is_valid {
          return Err(super::NetGuardError::AuthTokenExpired);
        } else if val.expires < SystemTime::now() {
          return Err(super::NetGuardError::AuthTokenExpired);
        } else {
          return Ok(());
        }
      }
      None => {}
    };

    let req = tonic::Request::new(ValidateAuthRequest {
      auth_token: Some(auth_token),
    });
    let response = self.client.validate_auth_token(req).await;
    if response.is_err() {
      return Err(super::NetGuardError::InternalError(format!(
        "Failed to validate token: {}",
        response.expect_err("error")
      )));
    }

    let status = response.unwrap().into_inner();
    let result = map_grpc_status_code(status.status(), status.message);
    if result.is_some() {
      return Err(result.unwrap());
    } else {
      return Ok(());
    }
  }

  async fn is_allowed(
    &mut self,
    token: &bytes::Bytes,
    net_type: super::NetAddrType,
  ) -> Result<bool, super::NetGuardError> {
    match self
      .allowed_cache
      .get(CacheAllowedKey {
        auth_token: AuthToken {
          token: String::from_utf8_lossy(token).into_owned(),
        },
        addr: net_type.clone(),
      })
      .await
    {
      Some(val) => return Ok(val),
      None => {}
    }

    let (net_type2, addr) = map_net_addr_type(net_type.clone());
    let req = tonic::Request::new(IsAllowedRequest {
      auth_token: Some(AuthToken {
        token: String::from_utf8_lossy(token).into_owned(),
      }),
      address: Some(NetAddress {
        address: addr,
        r#type: net_type2.into(),
      }),
    });

    let response = self.client.is_allowed(req).await;
    if response.is_err() {
      return Err(NetGuardError::InternalError(format!(
        "Failed to communicate with net-sentinel: {}",
        response.expect_err("error")
      )));
    }
    let status = response.unwrap().into_inner();
    let result = map_grpc_status_code(status.status(), status.message);
    if result.is_some() {
      return Err(result.unwrap());
    } else {
      let _ = self
        .allowed_cache
        .put(
          CacheAllowedKey {
            auth_token: AuthToken {
              token: String::from_utf8_lossy(token).into_owned(),
            },
            addr: net_type.clone(),
          },
          status.allowed,
        )
        .await;
      return Ok(status.allowed);
    }
  }

  // TODO: Implement cache/queue for this method
  async fn set_net_usage(
    &mut self,
    token: &bytes::Bytes,
    net_usage: super::NetUsage,
  ) -> Result<(), super::NetGuardError> {
    let req = tonic::Request::new(AddNetUsageRequest {
      auth_token: Some(AuthToken {
        token: String::from_utf8_lossy(token).into_owned(),
      }),
      download_usage: net_usage.read_rate,
      upload_usage: net_usage.write_rate,
    });

    let response = self.client.add_net_usage(req).await;
    if response.is_err() {
      return Err(NetGuardError::InternalError(format!(
        "Failed to communicate with net-sentinel: {}",
        response.expect_err("error")
      )));
    }
    let status = response.unwrap().into_inner();
    let result = map_grpc_status_code(status.status(), status.message);
    if result.is_some() {
      return Err(result.unwrap());
    } else {
      return Ok(());
    }
  }
}

/// Note that if the input `ResultStatus` be equals `ResultStatus::Success`, return `None`.
fn map_grpc_status_code(status: ResultStatus, msg: String) -> Option<super::NetGuardError> {
  match status {
    ResultStatus::AuthFailed => Some(super::NetGuardError::AuthFailed(msg)),
    ResultStatus::AuthExpired => Some(super::NetGuardError::AuthTokenExpired),
    ResultStatus::Error => Some(super::NetGuardError::InternalError(msg)),
    ResultStatus::Success => None,
    _ => Some(super::NetGuardError::InternalError(msg)),
  }
}

fn map_net_addr_type(net_type: super::NetAddrType) -> (NetAddressType, String) {
  match net_type {
    super::NetAddrType::IPV4(ipv4) => (NetAddressType::NetAddressIpv4, ipv4.to_string()),
    super::NetAddrType::IPV6(ipv6) => (NetAddressType::NetAddressIpv6, ipv6.to_string()),
    super::NetAddrType::Domain(domain) => (
      NetAddressType::NetAddressDomain,
      String::from_utf8_lossy(&domain).to_string(),
    ),
  }
}
