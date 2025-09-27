use crate::NetGuardClient;
use crate::cache::Cache;
use crate::netguard::NetGuard;
use crate::netguard::NetUsage;
use crate::netguard::SocksAuth;
use bytes::Bytes;
use pin_project_lite::pin_project;
use std::io::Result as IoResult;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
  /// Custom Stream
  /// A custom stream that could calculate usage data and send it to the accouinting system.
  #[derive(Debug)]
  pub struct CStream<S, T: NetGuard, U: Cache<SocksAuth, Bytes>> {
    #[pin] // This ensures that if `S` is !Unpin, `self.inner` gets a `Pin<&mut S>`
    inner: S,
    usage_rate: ByteCount<T, U>, // A service to send usage rate to the accounting system.
    is_send_usage: bool, // If true, send usage rate of data to the accounting system
    username: Option<Bytes>,
    netguard_client: Arc<NetGuardClient<T, U>>,
  }
}

impl<'a, S, T: NetGuard, U: Cache<SocksAuth, Bytes>> CStream<S, T, U> {
  /// Creates a new `ForwardingPrintStream` wrapping the given `inner` stream.
  /// The `prefix` is used in print statements to identify this stream.
  pub fn new(
    inner: S,
    send_usage_data: bool,
    username: Option<Bytes>,
    netguard_client: Arc<NetGuardClient<T, U>>,
  ) -> Self {
    let a = Self {
      inner,
      usage_rate: ByteCount::new(
        send_usage_data,
        username.clone(),
        netguard_client.clone(),
      ),
      is_send_usage: send_usage_data,
      username: username,
      netguard_client: netguard_client,
    };
    a
  }

  /// Set if usage data should be sent or not
  pub fn set_send_usage_data(&mut self, send_usage_data: bool) {
    self.is_send_usage = send_usage_data;
    self.usage_rate.set_send_usage(send_usage_data);
  }
}

pub trait StreamExt {
  fn set_username(&mut self, username: Option<Bytes>);
}

impl<'a, S, T: NetGuard, U: Cache<SocksAuth, Bytes>> StreamExt for CStream<S, T, U> {
  fn set_username(&mut self, username: Option<Bytes>) {
    trace!(
      "Set cstream username to `{}`",
      String::from_utf8(
        username
          .clone()
          .unwrap_or_else(|| "None".bytes().collect())
          .to_vec()
      )
      .unwrap_or_else(|_| "parse-error".to_string())
    );
    self.username = username.clone();
    self.usage_rate.set_username(username.clone());
  }
}

impl<S, T: NetGuard, U: Cache<SocksAuth, Bytes>> AsyncRead for CStream<S, T, U>
where
  S: AsyncRead, // The inner stream must be AsyncRead
{
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<IoResult<()>> {
    let this = self.project(); // `this.inner` is `Pin<&mut S>`

    let initial_filled_len = buf.filled().len();
    let poll_result = this.inner.poll_read(cx, buf);

    match &poll_result {
      Poll::Ready(Ok(())) => {
        let newly_filled_data = &buf.filled()[initial_filled_len..];
        if !newly_filled_data.is_empty() {
          this
            .usage_rate
            .add_read_rate(newly_filled_data.len() as i64);
        } else {
          // 0 bytes read typically means EOF if poll_result is Ok(())
          trace!("READ EOF (0 bytes)");
        }
      }
      Poll::Ready(Err(e)) => {
        debug!("READ error: {:?}", e);
      }
      Poll::Pending => {
        // Optionally log pending states if needed for debugging
        // println!("[{}] READ pending", prefix_str);
      }
    }
    poll_result
  }
}

impl<S, T: NetGuard, U: Cache<SocksAuth, Bytes>> AsyncWrite for CStream<S, T, U>
where
  S: AsyncWrite, // The inner stream must be AsyncWrite
{
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8], // Data to be written
  ) -> Poll<IoResult<usize>> {
    let this = self.project();
    let poll_result = this.inner.poll_write(cx, buf);

    match &poll_result {
      Poll::Ready(Ok(bytes_written)) => {
        if *bytes_written > 0 {
          this.usage_rate.add_write_rate(*bytes_written as i64);
        } else if !buf.is_empty() {
          // Attempted to write data, but 0 bytes were written
          debug!(
            "WRITE 0 bytes (attempted {}). Downstream may be full or closed.",
            buf.len()
          );
        }
        // If buf is empty, 0 bytes written is normal, no print needed.
      }
      Poll::Ready(Err(e)) => {
        debug!("WRITE error for {} bytes: {:?}", buf.len(), e);
      }
      Poll::Pending => {
        // println!("[{}] WRITE pending for {} bytes", prefix_str, buf.len());
      }
    }
    poll_result
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
    let this = self.project();
    // println!("[{}] FLUSHING...", prefix_str);

    let poll_result = this.inner.poll_flush(cx);
    match &poll_result {
      Poll::Ready(Ok(())) => {
        // println!("[{}] FLUSH successful", prefix_str);
      }
      Poll::Ready(Err(e)) => {
        debug!("FLUSH error: {:?}", e);
      }
      Poll::Pending => {
        // println!("[{}] FLUSH pending", prefix_str);
      }
    }
    poll_result
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
    let this = self.project();
    let poll_result = this.inner.poll_shutdown(cx);
    match &poll_result {
      Poll::Ready(Ok(())) => {
        // println!("[{}] SHUTDOWN successful", prefix_str);
      }
      Poll::Ready(Err(e)) => {
        debug!("SHUTDOWN error: {:?}", e);
      }
      Poll::Pending => {
        // println!("[{}] SHUTDOWN pending", prefix_str);
      }
    }
    poll_result
  }
}

#[derive(Debug)]
/// A data structure that keeps track of the number of bytes read or written by a
/// stream and send them to the accounting system.
struct ByteCount<T: NetGuard, U: Cache<SocksAuth, Bytes>> {
  read_rate: Mutex<u64>,
  /// In bytes
  write_rate: Mutex<u64>,
  /// In bytes
  username: Option<Bytes>,
  /// If true, send usage rate of data to the accounting system
  send_usage: bool,
  netguard_client: Arc<NetGuardClient<T, U>>,
}

impl<T: NetGuard, U: Cache<SocksAuth, Bytes>> ByteCount<T, U> {
  fn new(
    send_usage: bool,
    username: Option<Bytes>,
    netguard_client: Arc<NetGuardClient<T, U>>,
  ) -> ByteCount<T, U> {
    ByteCount {
      read_rate: Mutex::new(0),
      write_rate: Mutex::new(0),
      username,
      send_usage,
      netguard_client: netguard_client,
    }
  }
  /// Get net usage
  fn get(&self) -> NetUsage {
    NetUsage {
      read_rate: *self.read_rate.lock().unwrap(),
      write_rate: *self.write_rate.lock().unwrap(),
    }
  }

  /// Add read usage. `bytes` could be positive or negative
  fn add_read_rate(&self, bytes: i64) {
    if bytes < 0 {
      *self.read_rate.lock().unwrap() -= bytes.abs() as u64;
    } else {
      *self.read_rate.lock().unwrap() += bytes as u64;
    }
  }

  /// Add write usage. `bytes` could be positive or negative
  fn add_write_rate(&self, bytes: i64) {
    if bytes < 0 {
      *self.write_rate.lock().unwrap() -= bytes.abs() as u64;
    } else {
      *self.write_rate.lock().unwrap() += bytes as u64;
    }
  }

  /// Set if the usage rate should send usage data to the accounting system.
  /// If `true`, the usage rate will send usage data to the accounting system.
  fn set_send_usage(&mut self, send_usage: bool) {
    self.send_usage = send_usage;
  }

  fn set_username(&mut self, username: Option<Bytes>) {
    self.username = username;
  }

  async fn cleanup(&mut self) {
    trace!(
      "Cleaning up {}: {} bytes exchanged.",
      "ByteCount",
      self.get(),
    );
    trace!(
      "Send usage rate of user {} to the accounting system: {}",
      match self.username.clone() {
        None => "None".to_string(),
        Some(username) => String::from_utf8_lossy(&username).to_string(),
      },
      self.send_usage
    );
    if self.send_usage {
      let net_usage = self.get();

      tokio::spawn(async move {
        async fn writer() {
          println!("Writing...");
        }
        writer().await;
      });
      let ngc = self.netguard_client.clone();
      if !ngc.is_authed() {
        panic!("The netguard client is not authenticated during sending net-usage to the server")
      }
      match ngc.clone().add_net_usage(net_usage).await {
        Err(e) => debug!("Failed to send usage rate to the accounting system: {}", e),
        Ok(()) => debug!("Successfully sent usage rate to the accounting system"),
      };
    }
  }
}

impl<'a, T: NetGuard + 'a, U: Cache<SocksAuth, Bytes> + 'a> Drop for ByteCount<T, U> {
  fn drop(&mut self) {
    let usage = self.get();
    if usage.read_rate > 0 || usage.write_rate > 0 {
      warn!(
        "It seems usage-rate doesn't send to the accounting system correctly (ACCOUNTING_FAILED_ERR_0384): {}",
        usage
      )
    }
  }
}
