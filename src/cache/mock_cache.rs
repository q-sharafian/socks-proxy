use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

// Define the Result type (you might want to use a more specific error type)
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// The Cache trait as specified
pub trait Cache<K, V>: Send + Sync {
  /// If occurred any error or there is no value, returns None
  async fn get(&mut self, key: K) -> Option<V>;
  async fn put(&mut self, key: K, value: V) -> Result<()>;
  async fn remove(&mut self, key: K) -> Result<()>;
}

// Simple in-memory cache mock implementation
#[derive(Debug, Clone)]
pub struct MockCache<K, V> {
  storage: Arc<RwLock<HashMap<K, V>>>,
  // Optional: simulate failures for testing
  should_fail: bool,
}

impl<K, V> MockCache<K, V>
where
  K: Hash + Eq + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
{
  pub fn new() -> Self {
    Self {
      storage: Arc::new(RwLock::new(HashMap::new())),
      should_fail: false,
    }
  }

  pub fn new_with_failure_simulation() -> Self {
    Self {
      storage: Arc::new(RwLock::new(HashMap::new())),
      should_fail: true,
    }
  }

  pub fn set_failure_mode(&mut self, should_fail: bool) {
    self.should_fail = should_fail;
  }

  // Helper method to get current size (useful for testing)
  pub async fn size(&self) -> usize {
    let storage = self.storage.read().await;
    storage.len()
  }

  // Helper method to clear the cache
  pub async fn clear(&mut self) {
    let mut storage = self.storage.write().await;
    storage.clear();
  }
}

impl<K, V> Cache<K, V> for MockCache<K, V>
where
  K: Hash + Eq + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
{
  async fn get(&mut self, key: K) -> Option<V> {
    // Simulate potential failures or errors by returning None
    if self.should_fail {
      return None;
    }

    let storage = self.storage.read().await;
    storage.get(&key).cloned()
  }

  async fn put(&mut self, key: K, value: V) -> Result<()> {
    if self.should_fail {
      return Err("Simulated put failure".into());
    }

    let mut storage = self.storage.write().await;
    storage.insert(key, value);
    Ok(())
  }

  async fn remove(&mut self, key: K) -> Result<()> {
    if self.should_fail {
      return Err("Simulated remove failure".into());
    }

    let mut storage = self.storage.write().await;
    storage.remove(&key);
    Ok(())
  }
}

// Alternative implementation with more realistic error scenarios
#[derive(Debug, Clone)]
pub struct RealisticMockCache<K, V> {
  storage: Arc<RwLock<HashMap<K, V>>>,
  max_capacity: usize,
}

impl<K, V> RealisticMockCache<K, V>
where
  K: Hash + Eq + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
{
  pub fn new(max_capacity: usize) -> Self {
    Self {
      storage: Arc::new(RwLock::new(HashMap::new())),
      max_capacity,
    }
  }
}

impl<K, V> Cache<K, V> for RealisticMockCache<K, V>
where
  K: Hash + Eq + Clone + Send + Sync + 'static,
  V: Clone + Send + Sync + 'static,
{
  async fn get(&mut self, key: K) -> Option<V> {
    let storage = self.storage.read().await;
    storage.get(&key).cloned()
  }

  async fn put(&mut self, key: K, value: V) -> Result<()> {
    let mut storage = self.storage.write().await;

    // Simulate capacity error
    if storage.len() >= self.max_capacity && !storage.contains_key(&key) {
      return Err("Cache capacity exceeded".into());
    }

    storage.insert(key, value);
    Ok(())
  }

  async fn remove(&mut self, key: K) -> Result<()> {
    let mut storage = self.storage.write().await;
    storage.remove(&key);
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn test_basic_cache_operations() {
    let mut cache = MockCache::<String, i32>::new();

    // Test put and get
    assert!(cache.put("key1".to_string(), 42).await.is_ok());
    assert_eq!(cache.get("key1".to_string()).await, Some(42));

    // Test get non-existent key
    assert_eq!(cache.get("non_existent".to_string()).await, None);

    // Test remove
    assert!(cache.remove("key1".to_string()).await.is_ok());
    assert_eq!(cache.get("key1".to_string()).await, None);
  }

  #[tokio::test]
  async fn test_failure_simulation() {
    let mut cache = MockCache::<String, i32>::new_with_failure_simulation();

    // All operations should fail or return None
    assert_eq!(cache.get("key1".to_string()).await, None);
    assert!(cache.put("key1".to_string(), 42).await.is_err());
    assert!(cache.remove("key1".to_string()).await.is_err());
  }

  #[tokio::test]
  async fn test_realistic_cache_capacity() {
    let mut cache = RealisticMockCache::<String, i32>::new(2);

    // Fill to capacity
    assert!(cache.put("key1".to_string(), 1).await.is_ok());
    assert!(cache.put("key2".to_string(), 2).await.is_ok());

    // Should fail when exceeding capacity
    assert!(cache.put("key3".to_string(), 3).await.is_err());

    // Should succeed when updating existing key
    assert!(cache.put("key1".to_string(), 10).await.is_ok());
    assert_eq!(cache.get("key1".to_string()).await, Some(10));
  }

  #[tokio::test]
  async fn test_concurrent_access() {
    let cache = Arc::new(tokio::sync::Mutex::new(MockCache::<String, i32>::new()));

    let handles: Vec<_> = (0..10)
      .map(|i| {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
          let mut cache = cache.lock().await;
          let key = format!("key{}", i);
          let _ = cache.put(key.clone(), i).await;
          cache.get(key).await
        })
      })
      .collect();

    let results: Vec<_> = futures::future::join_all(handles)
      .await
      .into_iter()
      .map(|r| r.unwrap())
      .collect();

    // Check that all operations completed
    assert_eq!(results.len(), 10);
  }
}

// Example usage
#[tokio::main]
async fn main() -> Result<()> {
  // Basic usage
  let mut cache = MockCache::<String, String>::new();

  // Put some values
  cache.put("hello".to_string(), "world".to_string()).await?;
  cache.put("foo".to_string(), "bar".to_string()).await?;

  // Get values
  if let Some(value) = cache.get("hello".to_string()).await {
    println!("Found: {}", value);
  }

  // Remove a value
  cache.remove("foo".to_string()).await?;

  // Try to get removed value
  match cache.get("foo".to_string()).await {
    Some(value) => println!("Found: {}", value),
    None => println!("Value not found or error occurred"),
  }

  Ok(())
}
