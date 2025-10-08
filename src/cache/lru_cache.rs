use std::{cmp::Eq, hash::Hash, num::NonZero, sync::Arc};
use tokio::sync::Mutex;
use lru;
use anyhow::{Ok, Result};
use crate::cache::Cache;

#[derive(Clone)]
pub struct LruCache<K: Hash + Eq, V> {
  cache: Arc<Mutex<lru::LruCache<K, V>>>,
}

impl<K: Hash + Eq, V> LruCache<K, V> {
  /// `size` is the maximum number of entries the cache could stores.
  pub fn new(size: usize) -> LruCache<K, V> {
    let cache: lru::LruCache<K, V> = lru::LruCache::new(NonZero::new(size).unwrap());
    LruCache::<K, V> {
      cache: Arc::new(Mutex::new(cache)),
    }
  }
}

impl<K, V> Cache<K, V> for LruCache<K, V>
where
  V: std::marker::Send + Clone + 'static,
  K: Hash + Eq + std::marker::Send + Clone + 'static,
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
    cache.pop( &key);
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_lru_cache() {
    let mut cache = LruCache::new(3);
    cache.put(1, 1).await.unwrap();
    cache.put(2, 2).await.unwrap();
    cache.put(3, 3).await.unwrap();
    assert_eq!(cache.get(1).await, Some(1));
    assert_eq!(cache.get(2).await, Some(2));
    assert_eq!(cache.get(3).await, Some(3));
    assert_ne!(cache.get(4).await, Some(4));
    cache.put(4, 4).await.unwrap();
    assert_eq!(cache.get(1).await, None);
    assert_eq!(cache.get(2).await, Some(2));
    assert_eq!(cache.get(3).await, Some(3));
    assert_eq!(cache.get(4).await, Some(4));
  }

  #[tokio::test]
  async fn test_lru_cache_remove() {
    let mut cache = LruCache::new(3);
    cache.put(1, 1).await.unwrap();
    cache.put(2, 2).await.unwrap();
    cache.put(3, 3).await.unwrap();
    assert_eq!(cache.get(1).await, Some(1));
    assert_eq!(cache.get(2).await, Some(2));
    assert_eq!(cache.get(3).await, Some(3));
    assert_ne!(cache.get(4).await, Some(4));
    cache.remove(2).await.unwrap();
    assert_eq!(cache.get(1).await, Some(1));
    assert_eq!(cache.get(2).await, None, "it seems the key is not removed. key: {}", 2);
    assert_eq!(cache.get(3).await, Some(3));
    assert_eq!(cache.get(4).await, None);
  }
}