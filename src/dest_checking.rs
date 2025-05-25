use bytes::Bytes;
use std::env;
use std::ffi::c_char;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cache::{Cache, LruCache};

#[link(name = "req_processor", kind = "dylib")]
extern "C" {
  /// addr_type: `0` for IPv4, `1` for IPv6, and `2` for domain name. (at the end of domain
  /// name must placed null character `\0`)
  fn has_access2dest(username: *const c_char, addr_type: u8, addr: *mut u8) -> bool;
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub enum DestType {
  IPV4(Ipv4Addr),
  IPV6(Ipv6Addr),
  /// At the end of domain name must placed null character `\0`
  Domain(Bytes),
}

#[derive(Hash, PartialEq, Eq)]
struct CacheKey {
  username: Bytes,
  dest_type: DestType,
}

pub struct DestChecking {
  cache: Box<dyn Cache<CacheKey, bool>>,
}

impl DestChecking {
  pub fn new() -> Self {
    DestChecking {
      cache: Box::new(LruCache::<CacheKey, bool>::new(
        env::var("MAX_DEST_CHECK_CACHE_SIZE")
          .unwrap_or("1000".to_string())
          .parse::<usize>()
          .unwrap(),
      )),
    }
  }

  pub fn has_access(&mut self, username: Bytes, dest_type: DestType) -> bool {
    let key = CacheKey {
      username: username.clone(),
      dest_type: dest_type.clone(),
    };
    let user_str = String::from_utf8_lossy(&username);
    let access_check = self.cache.get(&key);
    if access_check.is_some() {
      trace!(
        "Cache hit for user {} and dest {:?}",
        user_str,
        DestChecking::pretty_print_addr(&dest_type)
      );
      return *access_check.unwrap();
    }

    let access_check = unsafe {
      has_access2dest(
        username.as_ptr() as *const c_char,
        match dest_type {
          DestType::IPV4(_) => 0,
          DestType::IPV6(_) => 1,
          DestType::Domain(_) => 2,
        },
        match dest_type {
          DestType::IPV4(addr) => addr.octets().as_ptr() as *mut u8,
          DestType::IPV6(addr) => addr.octets().as_ptr() as *mut u8,
          DestType::Domain(ref addr) => addr.as_ptr() as *mut u8,
        },
      )
    };
    self.cache.put(key, access_check);
    trace!(
      "Found user '{}' and dest {} and put in cache. Has access? {}",
      user_str,
      DestChecking::pretty_print_addr(&dest_type),
      access_check
    );

    access_check
  }

  fn pretty_print_addr(addr_type: &DestType) -> String {
    match addr_type {
      DestType::Domain(addr) => String::from_utf8_lossy(addr).to_string(),
      DestType::IPV4(addr) => addr
        .octets()
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<String>>()
        .join("."),
      DestType::IPV6(addr) => {
        let addr_16 = addr.octets();
        addr_16
          .iter()
          .map(|x| format!("{:x}", x))
          .collect::<Vec<String>>()
          .join(":")
      }
    }
  }
}
