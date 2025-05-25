use crate::cache::{Cache, LruCache};
use bytes::Bytes;
use std::{
  env,
  ffi::{c_char, CStr},
};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawAuthResult {
  success: bool,
  /// Rate limit in bytes. 0 means no limit
  rate_limit: usize,
  msg: *mut c_char,
}

#[link(name = "req_processor", kind = "dylib")]
extern "C" {
  fn is_authenticated(username: *const c_char, password: *const u8) -> *mut RawAuthResult;
  fn free_auth_result(result: *mut RawAuthResult);
}

#[derive(Clone, Debug)]
pub struct AuthResult {
  pub authenticated: bool,
  /// Rate limit in bytes. 0 means no limit
  pub rate_limit: usize,
  pub msg: Option<String>,
}

#[derive(Debug)]
struct CacheAuthResult {
  auth_result: AuthResult,
  password: Bytes,
}

/// Check if such user exists and could use the program
pub struct Authenticator {
  cache: Box<dyn Cache<c_char, CacheAuthResult>>,
}

impl Authenticator {
  pub fn new() -> Self {
    Authenticator {
      cache: Box::new(LruCache::<c_char, CacheAuthResult>::new(
        env::var("MAX_AUTH_CACHE_SIZE")
          .unwrap_or("1000".to_string())
          .parse::<usize>()
          .unwrap(),
      )),
    }
  }

  /// Checks if such user exists and could access to the service
  pub fn check(
    &mut self,
    username: &c_char,
    password: &[u8],
  ) -> Result<Option<AuthResult>, String> {
    let user_cache = self.cache.get(username);
    let user_str = unsafe { CStr::from_ptr(username) }
      .to_str()
      .unwrap_or("None");

    if user_cache.is_some() {
      trace!(
        "Cache hit for authenticating user {}: {:?}",
        user_str,
        user_cache.unwrap()
      );
      if user_cache.unwrap().password != password {
        debug!("Wrong password for {}", user_str);
        return Err(format!("Passsword of username {} is wrong", user_str));
      }
      return Result::Ok(Some(user_cache.unwrap().auth_result.clone()));
    }

    let result_ptr = unsafe { is_authenticated(username, password.as_ptr()) };
    if result_ptr.is_null() {
      trace!("User {} not found in db", user_str);
      return Ok(None);
    }
    let result = unsafe {
      AuthResult {
        authenticated: (*result_ptr).success,
        rate_limit: (*result_ptr).rate_limit as usize,
        msg: if (*result_ptr).msg.is_null() {
          None
        } else {
          Some(
            CStr::from_ptr((*result_ptr).msg)
              .to_str()
              .unwrap()
              .to_string(),
          )
        },
      }
    };
    unsafe {
      free_auth_result(result_ptr);
    }
    trace!("Found user '{}' and put in cache", user_str);
    self.cache.put(
      username.clone(),
      CacheAuthResult {
        auth_result: result.clone(),
        password: Bytes::from(password.to_vec()),
      },
    );
    Result::Ok(Some(result))
  }
}
