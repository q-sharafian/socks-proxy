use pin_project_lite::pin_project;
use std::io::Result as IoResult;
use std::os::raw::c_char;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[link(name = "req_processor", kind = "dylib")]
extern "C" {
  fn update_usage_rate(username: *const c_char, read_bytes: u64, write_bytes: u64);
}

pin_project! {
  /// Custom Stream
  /// A custom stream that could calculate usage data and send it to the accouinting system.
  #[derive(Debug)]
  pub struct CStream<'a, S> {
    #[pin] // This ensures that if `S` is !Unpin, `self.inner` gets a `Pin<&mut S>`
    inner: S,
    write_usage_rate: ByteCount<'a>, // Usage rate of wrote data in bytes
    read_usage_rate: ByteCount<'a>, // Usage rate of read data in bytes
    send_usage: bool, // If true, send usage rate of data to the accounting system
    username: Option<Vec<u8>>
  }
}

impl<'a, S> CStream<'a, S> {
  /// Creates a new `ForwardingPrintStream` wrapping the given `inner` stream.
  /// The `prefix` is used in print statements to identify this stream.
  pub fn new(inner: S, send_usage_data: bool, username: &'a Option<Vec<u8>>) -> Self {
    let a = Self {
      inner,
      read_usage_rate: ByteCount::new("read_bytes".to_string(), send_usage_data, 0, &username),
      write_usage_rate: ByteCount::new("write_bytes".to_string(), send_usage_data, 1, &username),
      send_usage: send_usage_data,
      username: username.clone(),
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

impl<'a, S> StreamExt for CStream<'a, S> {
  fn set_username(&mut self, username: Option<Vec<u8>>) {
    trace!(
      "Setting username to `{}` (in cstream)",
      String::from_utf8(username.clone().unwrap_or_else(|| "None".bytes().collect()))
        .unwrap_or_else(|_| "parse-error".to_string())
    );
    self.username = username;
  }
}

impl<'a, S> AsyncRead for CStream<'a, S>
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
          // *this.read_bytes. += newly_filled_data.len() as u64;
          // println!(
          //   "[{}] READ {} bytes: \"{}\"", // Using lossy UTF-8 for general display
          //   prefix_str,
          //   newly_filled_data.len(),
          //   String::from_utf8_lossy(newly_filled_data)
          // );
          // For hex output of binary data, you could use:
          // print!("[{}] READ {} bytes: ", prefix_str, newly_filled_data.len());
          // for byte in newly_filled_data { print!("{:02x} ", byte); }
          // println!();
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

impl<'a, S> AsyncWrite for CStream<'a, S>
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
struct ByteCount<'a> {
  count: Mutex<u64>,
  tag: String,
  /// 0 for read, 1 for write
  byte_type: u8,
  username: &'a Option<Vec<u8>>,
  send_usage: bool,
}

impl<'a> ByteCount<'a> {
  fn new(tag: String, send_usage: bool, byte_type: u8, username: &Option<Vec<u8>>) -> ByteCount {
    ByteCount {
      count: Mutex::new(0 as u64),
      tag: tag,
      byte_type: byte_type,
      username: username,
      send_usage: send_usage,
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
}

impl Drop for ByteCount<'_> {
  fn drop(&mut self) {
    trace!("Destructing {}: {} bytes exchanged.", self.tag, self.get(),);
    trace!(
      "Send usage rate to the accounting system: {}",
      self.send_usage
    );
    if self.send_usage {
      let read_bytes = if self.byte_type == 0 { self.get() } else { 0 };
      let write_bytes = if self.byte_type == 1 { self.get() } else { 0 };
      unsafe {
        match &self.username {
          Some(username) => {
            update_usage_rate(username.as_ptr() as *const c_char, read_bytes, write_bytes);
          }
          None => {
            update_usage_rate(std::ptr::null(), read_bytes, write_bytes);
          }
        }
      }
    }
  }
}
