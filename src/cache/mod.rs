use std::{cmp::Eq, hash::Hash, num::NonZero, sync::Arc};
use anyhow::{Ok, Result};
use lru;
use tokio::sync::Mutex;
use std::future::Future;
pub mod mock_cache;
pub mod dummy_cache;

/// Note that all implementations must be thread-safe.
pub trait Cache<K, V>: Send + Sync {
  /// If occured any error or there is no value, returns None
  fn get(&mut self, key: K) -> impl Future<Output = Option<V>> + Send;
  async fn put(&mut self, key: K, value: V) -> Result<()>;
  async fn remove(&mut self, key: K) -> Result<()>;
}

pub struct LruCache<K: Hash + Eq, V> {
  cache: Arc<Mutex<lru::LruCache<K, V>>>,
}

impl<K: Hash + Eq, V> LruCache<K, V> {
  /// `size` is the maximum number of entries the cache could stores.
  pub fn new(size: usize) -> LruCache<K, V> {
    let cache: lru::LruCache<K, V> = lru::LruCache::new(NonZero::new(size).unwrap());
    LruCache::<K, V> { cache: Arc::new(Mutex::new(cache)) }
  }
}

impl<K, V> Cache<K, V> for LruCache<K, V>
where
  V: std::marker::Send + Clone,
  K: Hash + Eq + std::marker::Send,
{
  async fn get(&mut self, key: K) -> Option<V> {
    let mut cache = self.cache.lock().await;
    let val = cache.get(&key);
    match val {
      Some(v) => Some(v.clone()),
      None => None,
    }
  }
  
  async fn put(&mut self, key: K, value: V) -> Result<()> {
    let mut cache = self.cache.lock().await;
    cache.put(key, value);
    Ok(())
  }

  async fn remove(&mut self, key: K) -> Result<()> {
    let mut cache = self.cache.lock().await;
    cache.demote(&key);
    Ok(())
  }
}
