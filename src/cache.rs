use std::{cmp::Eq, hash::Hash, num::NonZero, u64};

use lru;

pub trait Cache<K, V>: Send {
  fn get(&mut self, key: &K) -> Option<&V>;
  fn put(&mut self, key: K, value: V);
  fn remove(&mut self, key: &K);
}
pub struct LruCache<K: Hash + Eq, V> {
  cache: lru::LruCache<K, V>,
}

impl<K: Hash + Eq, V> LruCache<K, V> {
  pub fn new(size: usize) -> LruCache<K, V> {
    let cache: lru::LruCache<K, V> = lru::LruCache::new(NonZero::new(size).unwrap());
    LruCache::<K, V> { cache }
  }
}

impl<K, V> Cache<K, V> for LruCache<K, V>
where
  V: std::marker::Send,
  K: Hash + Eq + std::marker::Send,
{
  fn get(&mut self, key: &K) -> Option<&V> {
    self.cache.get(key)
  }
  fn put(&mut self, key: K, value: V) {
    self.cache.put(key, value);
  }
  fn remove(&mut self, key: &K) {
    self.cache.demote(key);
  }
}
