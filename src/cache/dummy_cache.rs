use crate::cache::Cache;
use anyhow::{Ok, Result};
use std::future::Future;
use std::marker::Send;

/// This implementation behaves such that all requests seem to be completed successfully.
#[derive(Clone)]
pub struct DummyCache {}

impl DummyCache {
  pub fn new() -> DummyCache {
    DummyCache {}
  }
}

impl<K, V: Send> Cache<K, V> for DummyCache
where
  K: 'static + Send,
  V: 'static,
{
  /// If occured any error or there is no value, returns None
  fn get(&mut self, _key: K) -> impl Future<Output = Option<V>> + Send {
    std::future::ready(None)
  }

  async fn remove(&mut self, _key: K) -> Result<()> {
    Ok(())
  }

  fn put(&mut self, _key: K, _value: V) -> impl Future<Output = Result<()>> + Send {
    std::future::ready(Ok(()))
  }
}
