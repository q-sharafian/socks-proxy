use anyhow::{Ok, Result};
use std::future::Future;
pub mod dummy_cache;
pub mod mock_cache;
pub mod lru_cache;
pub use lru_cache::LruCache;

/// Note that all implementations must be thread-safe.
pub trait Cache<K, V>: Send + Sync + Clone + 'static
where
  K: 'static,
  V: 'static,
{
  /// If occured any error or there is no value, returns None
  fn get(&mut self, key: K) -> impl Future<Output = Option<V>> + Send;
  fn put(&mut self, key: K, value: V) -> impl Future<Output = Result<()>> + Send;
  fn remove(&mut self, key: K) -> impl Future<Output = Result<()>> + Send;
}