use crate::NetUsage;
use bytes::Bytes;
use pin_project_lite::pin_project;
use std::io::Result as IoResult;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
  /// Custom Stream
  /// A custom stream that could calculate usage data and send it to the accouinting system.
  #[derive(Debug)]
  pub struct CStream<S> {
    #[pin] // This ensures that if `S` is !Unpin, `self.inner` gets a `Pin<&mut S>`
    inner: S,
    write_usage_rate: ByteCount, // Usage rate of wrote data in bytes
    read_usage_rate: ByteCount, // Usage rate of read data in bytes
    send_usage: bool, // If true, send usage rate of data to the accounting system
    username: Option<Vec<u8>>,
    net_usage: NetUsage,
  }
}

impl<'a, S> CStream<S> {
  /// Creates a new `ForwardingPrintStream` wrapping the given `inner` stream.
  /// The `prefix` is used in print statements to identify this stream.
  pub fn new(
    inner: S,
    send_usage_data: bool,
    username: &'a Option<Vec<u8>>,
    net_usage: NetUsage,
  ) -> Self {
    let a = Self {
      inner,
      read_usage_rate: ByteCount::new(
        "read_bytes".to_string(),
        send_usage_data,
        0,
        username.clone(),
        net_usage.clone(),
      ),
      write_usage_rate: ByteCount::new(
        "write_bytes".to_string(),
        send_usage_data,
        1,
        username.clone(),
        net_usage.clone(),
      ),
      send_usage: send_usage_data,
      username: username.clone(),
      net_usage,
    };
    a
  }

  /// Set if usage data should be sent or not
  pub fn set_send_usage_data(&mut self, send_usage_data: bool) {
    self.send_usage = send_usage_data;
    self.read_usage_rate.set_send_usage(send_usage_data);
    self.write_usage_rate.set_send_usage(send_usage_data);
  }
}

pub trait StreamExt {
  fn set_username(&mut self, username: Option<Vec<u8>>);
}

impl<'a, S> StreamExt for CStream<S> {
  fn set_username(&mut self, username: Option<Vec<u8>>) {
    trace!(
      "Set cstream username to `{}`",
      String::from_utf8(username.clone().unwrap_or_else(|| "None".bytes().collect()))
        .unwrap_or_else(|_| "parse-error".to_string())
    );
    self.username = username.clone();
    self.read_usage_rate.set_username(username.clone());
    self.write_usage_rate.set_username(username.clone());
  }
}

impl<S> AsyncRead for CStream<S>
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
          this.read_usage_rate.add(newly_filled_data.len() as i64);
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

impl<S> AsyncWrite for CStream<S>
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
          this.write_usage_rate.add(*bytes_written as i64);
          // println!(
          //   "[{}] WRITE {} bytes (out of {} attempted): \"{}\"",
          //   prefix_str,
          //   bytes_written,
          //   buf.len(),
          //   String::from_utf8_lossy(&buf[..*bytes_written])
          // );
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
struct ByteCount {
  count: Mutex<u64>,
  tag: String,
  /// 0 for read, 1 for write
  byte_type: u8,
  username: Option<Vec<u8>>,
  send_usage: bool,
  net_usage: NetUsage,
}

impl ByteCount {
  fn new(
    tag: String,
    send_usage: bool,
    byte_type: u8,
    username: Option<Vec<u8>>,
    net_usage: NetUsage,
  ) -> ByteCount {
    ByteCount {
      count: Mutex::new(0 as u64),
      tag: tag,
      byte_type: byte_type,
      username: username,
      send_usage: send_usage,
      net_usage,
    }
  }
  fn get(&self) -> u64 {
    *self.count.lock().unwrap()
  }
  // Add bytes to the count. Value could be positive or negative
  fn add(&self, bytes: i64) {
    if bytes < 0 {
      *self.count.lock().unwrap() -= bytes.abs() as u64;
    } else {
      *self.count.lock().unwrap() += bytes as u64;
    }
  }
  fn set_send_usage(&mut self, send_usage: bool) {
    self.send_usage = send_usage;
  }

  fn set_username(&mut self, username: Option<Vec<u8>>) {
    self.username = username;
  }

  // async fn update_usage_rate(&self, username: &Vec<u8>, read_bytes: u64, write_bytes: u64) {
  //   self
  //     .net_usage
  //     .lock()
  //     .await
  //     .update_usage_rate(Bytes::from(username.clone()), read_bytes, write_bytes)
  //     .await;
  // }
}

impl Drop for ByteCount {
  fn drop(&mut self) {
    trace!("Destructing {}: {} bytes exchanged.", self.tag, self.get(),);
    trace!(
      "Send usage rate of user {} to the accounting system: {}",
      match self.username.clone() {
        None => "None".to_string(),
        Some(username) => String::from_utf8_lossy(&username).to_string(),
      },
      self.send_usage
    );
    if self.send_usage {
      let read_bytes = if self.byte_type == 0 { self.get() } else { 0 };
      let write_bytes = if self.byte_type == 1 { self.get() } else { 0 };
      // match &self.username.clone() {
      //   Some(username) => {
      //     self
      //       .net_usage
      //       .update_usage_rate(Bytes::from(username.clone()), read_bytes, write_bytes);
      //     // update_usage_rate(username.as_ptr() as *const c_char, read_bytes, write_bytes);
      //   }
      //   None => {
      //     // update_usage_rate(std::ptr::null(), read_bytes, write_bytes);
      //     self
      //       .net_usage
      //       .update_usage_rate(Bytes::from(Vec::new()), read_bytes, write_bytes);
      //   }
      // }
      let username = self.username.clone(); // Clone self.username here
      let mut net_usage = self.net_usage.clone(); // Clone self.net_usage here

      tokio::spawn(async move {
        match username {
          Some(username) => {
            match net_usage
              .update_usage_rate(Bytes::from(username.clone()), read_bytes, write_bytes).await {
                Ok(_) => (),
                Err(err) => warn!("Failed to update usage rate for username {}: {}", String::from_utf8_lossy(&username), err),
                          };
            // update_usage_rate(username.as_ptr() as *const c_char, read_bytes, write_bytes);
          }
          None => {
            // update_usage_rate(std::ptr::null(), read_bytes, write_bytes);
            match net_usage
              .update_usage_rate(Bytes::from(Vec::new()), read_bytes, write_bytes).await{
                Ok(_) => (),
                Err(err) => warn!("Failed to update usage rate for username None: {}", err),
              };
          }
        }
      });
    }
  }
}
