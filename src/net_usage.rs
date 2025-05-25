use bytes::Bytes;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::env;
use std::ffi::c_char;
use std::ptr::null;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::MutexGuard;
use tokio::{sync::Mutex as TokioMutex, time};

#[link(name = "req_processor", kind = "dylib")]
extern "C" {
  fn update_usage_rate(username: *const c_char, read_bytes: u64, write_bytes: u64) -> bool;
  fn update_usage_rate_list(
    username: *const *const c_char,
    read_bytes: *const u64,
    write_bytes: *const u64,
    count: u64,
  ) -> bool;
}

#[derive(Debug)]
struct UsageRate {
  read_bytes: u64,
  write_bytes: u64,
}

#[derive(Debug, Clone)]
// It's thread safe
pub struct NetUsage {
  cache: Arc<TokioMutex<BTreeMap<Bytes, UsageRate>>>,
  /// A queue contains usernames.
  /// Push in front and pop from the back.
  queue: Arc<TokioMutex<VecDeque<Bytes>>>,
  cleanup_batch_size: u64,
  threshold: u64,
}

#[derive(Debug, Error)]
pub enum NetUsageError {
  #[error("Accounting service error: {0}")]
  AccountingError(String),
}

impl NetUsage {
  pub fn new() -> NetUsage {
    trace!("Creatin new NetUsage instance");
    let net_usage = NetUsage {
      cache: Arc::new(TokioMutex::new(BTreeMap::new())),
      queue: Arc::new(TokioMutex::new(VecDeque::new())),
      cleanup_batch_size: env::var("NET_USAGE_CLEANUP_BATCH_SIZE")
        .unwrap_or("50".to_string())
        .parse::<u64>()
        .unwrap(),
      threshold: env::var("NET_USAGE_THRESHOLD")
        .unwrap_or("15728640".to_string())
        .parse::<u64>()
        .unwrap(),
    };

    trace!("Starting NetUsage cleanup scheduler");
    net_usage.clone().schedule_usage_cleanup();
    net_usage
  }

  /// Adds usage rate to the cache
  pub async fn update_usage_rate(
    &mut self,
    username: Bytes,
    read_bytes: u64,
    write_bytes: u64,
  ) -> Result<(), NetUsageError> {
    let user_str = String::from_utf8_lossy(&username);
    let mut cache = self.cache.lock().await;
    let usage = UsageRate {
      read_bytes,
      write_bytes,
    };
    let mut user_usage = cache.get_mut(&username);
    if user_usage.as_ref().is_some() {
      user_usage.as_mut().unwrap().read_bytes += read_bytes;
      user_usage.as_mut().unwrap().write_bytes += write_bytes;
    } else {
      cache.insert(username.clone(), usage);
      self.queue.lock().await.push_front(username.clone());
    }
    let user_usage = cache.get_mut(&username).unwrap();
    trace!(
      "Updated usage rate of user {} in the accounting system. read: {} bytes, write: {} bytes",
      user_str,
      user_usage.read_bytes,
      user_usage.write_bytes
    );

    if user_usage.write_bytes + user_usage.read_bytes >= self.threshold {
      trace!(
        "Sending usage rate of user {} to the accounting system",
        if user_str.len() > 0 {
          user_str.clone()
        } else {
          std::borrow::Cow::Borrowed("<None>")
        },
      );
      let is_success = NetUsage::send_accounting_data(
        if username.len() > 0 {
          username.as_ptr() as *const c_char
        } else {
          null()
        },
        user_usage.read_bytes,
        user_usage.write_bytes,
      );
      if is_success {
        trace!(
          "Successfully send usage rate of user {} to the accounting system. Reseting usage rate",
          user_str
        );
        user_usage.read_bytes = 0;
        user_usage.write_bytes = 0;
        return Ok(());
      } else {
        return Err(NetUsageError::AccountingError(format!(
          "Failed to send usage rate of user {} to the accounting system",
          user_str
        )));
      }
    }
    Ok(())
  }

  /// Periodically send usage rate to the accounting system and clean them from the cache
  fn schedule_usage_cleanup(mut self) {
    tokio::spawn(async move {
      let period = Duration::from_secs(
        env::var("SCHEDULE_NET_USAGE_CLEANUP_INTERVAL")
          .unwrap_or("7200".to_string())
          .parse::<u64>()
          .unwrap_or(7200),
      );
      trace!(
        "Starting NetUsage cleanup scheduler in each {} seconds",
        period.as_secs()
      );
      let mut interval = time::interval(period);
      loop {
        trace!("Starting new usage rate cleanup based scheeduler");
        interval.tick().await; // Wait for the next tick
                               // Spawn a new task for the actual work to avoid blocking the interval timer
                               // if the task itself is long-running or might block.
                               // let shared_self = Arc::new(Mutex::new(self.clone()));
                               // tokio::spawn(async move {
                               //   shared_self.lock().await.usage_cleanup().await;
                               // });
        self.usage_cleanup().await;
        trace!(
          "Usage rate cleanup finished. The number of elements in the cache: '{}'",
          self.cache.lock().await.len()
        );
      }
    });
  }

  async fn usage_cleanup(&mut self) {
    let mut is_last_fetched = false;
    loop {
      if is_last_fetched {
        return ();
      }
      let mut usernames = Vec::<Bytes>::new();
      let mut read_bytes = Vec::<u64>::new();
      let mut write_bytes = Vec::<u64>::new();

      for i in 0..self.cleanup_batch_size {
        let username = self.queue.lock().await.pop_back();
        if username.is_none() {
          is_last_fetched = true;
          break;
        }
        usernames.push(username.clone().unwrap());
        let mut cache = self.cache.lock().await;
        let usage = cache.get(&username.clone().unwrap()).unwrap();
        read_bytes.push(usage.read_bytes);
        write_bytes.push(usage.write_bytes);
        cache.remove(&username.unwrap());
      }

      let mut is_updated = false;
      for i in 0..2 {
        let is_success = unsafe {
          update_usage_rate_list(
            usernames.as_ptr() as *const *const c_char,
            read_bytes.as_ptr(),
            write_bytes.as_ptr(),
            usernames.len() as u64,
          )
        };
        if is_success {
          trace!(
            "Successfully send {} usage rates in {}'th trying times to the accounting system",
            usernames.len(),
            i + 1
          );
          is_updated = true;
          break;
        } else {
          debug!(
            "Failed to send usage rate in {}'th trying times to the accounting system. ",
            i + 1
          );
        }
      }

      // If the updation failed, insert the data back to the cache
      if !is_updated {
        warn!("Failed to send usage rate to the accounting system. Inserting them back to the cache. Count: {}", usernames.len());
        for i in 0..usernames.len() {
          let usage = UsageRate {
            read_bytes: read_bytes[i],
            write_bytes: write_bytes[i],
          };
          self.cache.lock().await.insert(usernames[i].clone(), usage);
        }
      }
    }
  }

  /// If username be empty, use 0 as input. (Use ptr::null())
  fn send_accounting_data(username: *const c_char, read_bytes: u64, write_bytes: u64) -> bool {
    trace!("aaa {:?}", username);
    unsafe { update_usage_rate(username, read_bytes, write_bytes) }
  }
}
