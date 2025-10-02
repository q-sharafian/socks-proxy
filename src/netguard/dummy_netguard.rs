use bytes::Bytes;
use crate::netguard::{NetAddrType, NetGuard, NetGuardError, NetUsage, SocksAuth};

/// This implementation does not raise any errors in either method (assuming success upon 
/// running) and is useful for testing.
#[derive(Clone)]
pub struct DummyNetGuard {}

impl NetGuard for DummyNetGuard {
    async fn generate_token(&mut self, _auth: &SocksAuth) -> Result<bytes::Bytes, NetGuardError> {
        return Ok(bytes::Bytes::from("token"));
    }

    async fn is_allowed(&mut self, _token: &Bytes, _net_type: NetAddrType) -> Result<bool, NetGuardError> {
        return Ok(true);
    }

    async fn set_net_usage(&mut self, _token: &Bytes, _net_usage: NetUsage) -> Result<(), NetGuardError> {
        return Ok(());
    }
    
    async fn validate_token(&mut self, _token: &Bytes) -> Result<(), NetGuardError> {
        return Ok(());
    }
}

impl DummyNetGuard {
    pub fn new() -> DummyNetGuard {
        return DummyNetGuard {};
    }
}

