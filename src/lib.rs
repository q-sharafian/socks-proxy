// #![forbid(unsafe_code)]
mod cstream;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use cstream::{CStream, StreamExt};
use snafu::Snafu;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::raw::c_char;
use std::ptr::null;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::time::timeout;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct AuthResult {
  success: bool,
  /// Rate limit in bytes. 0 means no limit
  rate_limit: usize,
  msg: *mut c_char,
}

#[link(name = "req_processor", kind = "dylib")]
extern "C" {
  fn is_authenticated(username: *const c_char, password: *const u8) -> *mut AuthResult;
  fn free_auth_result(result: *mut AuthResult);
  /// addr_type: `0` for IPv4, `1` for IPv6, and `2` for domain name. (at the end of domain
  /// name must placed null character `\0`)
  fn has_access2dest(username: *const c_char, addr_type: u8, addr: *mut u8) -> bool;
}

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct User {
  pub username: String,
  password: String,
}

pub struct SocksReply {
  // From rfc 1928 (S6),
  // the server evaluates the request, and returns a reply formed as follows:
  //
  //    +----+-----+-------+------+----------+----------+
  //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  //    +----+-----+-------+------+----------+----------+
  //    | 1  |  1  | X'00' |  1   | Variable |    2     |
  //    +----+-----+-------+------+----------+----------+
  //
  // Where:
  //
  //      o  VER    protocol version: X'05'
  //      o  REP    Reply field:
  //         o  X'00' succeeded
  //         o  X'01' general SOCKS server failure
  //         o  X'02' connection not allowed by ruleset
  //         o  X'03' Network unreachable
  //         o  X'04' Host unreachable
  //         o  X'05' Connection refused
  //         o  X'06' TTL expired
  //         o  X'07' Command not supported
  //         o  X'08' Address type not supported
  //         o  X'09' to X'FF' unassigned
  //      o  RSV    RESERVED
  //      o  ATYP   address type of following address
  //         o  IP V4 address: X'01'
  //         o  DOMAINNAME: X'03'
  //         o  IP V6 address: X'04'
  //      o  BND.ADDR       server bound address
  //      o  BND.PORT       server bound port in network octet order
  //
  buf: [u8; 10],
}

impl SocksReply {
  pub fn new(status: ResponseCode) -> Self {
    let buf = [
      // VER
      SOCKS_VERSION,
      // REP
      status as u8,
      // RSV
      RESERVED,
      // ATYP
      1,
      // BND.ADDR
      0,
      0,
      0,
      0,
      // BND.PORT
      0,
      0,
    ];
    Self { buf }
  }

  pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
  where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
  {
    stream.write_all(&self.buf[..]).await?;
    Ok(())
  }
}

#[derive(Error, Debug)]
pub enum MerinoError {
  #[error("IO error: {0}")]
  Io(#[from] io::Error),

  #[error("Socks error: {0}")]
  Socks(#[from] ResponseCode),
}

#[derive(Debug, Snafu)]
/// Possible SOCKS5 Response Codes
pub enum ResponseCode {
  Success = 0x00,
  #[snafu(display("SOCKS5 Server Failure"))]
  Failure = 0x01,
  #[snafu(display("SOCKS5 Rule failure"))]
  RuleFailure = 0x02,
  #[snafu(display("network unreachable"))]
  NetworkUnreachable = 0x03,
  #[snafu(display("host unreachable"))]
  HostUnreachable = 0x04,
  #[snafu(display("connection refused"))]
  ConnectionRefused = 0x05,
  #[snafu(display("TTL expired"))]
  TtlExpired = 0x06,
  #[snafu(display("Command not supported"))]
  CommandNotSupported = 0x07,
  #[snafu(display("Addr Type not supported"))]
  AddrTypeNotSupported = 0x08,
  #[snafu(display("Access to destination is forbidden for the user"))]
  DestForbidden = 0x09,
}

impl From<MerinoError> for ResponseCode {
  fn from(e: MerinoError) -> Self {
    match e {
      MerinoError::Socks(e) => e,
      MerinoError::Io(_) => ResponseCode::Failure,
    }
  }
}

/// DST.addr variant types
#[derive(PartialEq)]
enum AddrType {
  /// IP V4 address: X'01'
  V4 = 0x01,
  /// DOMAINNAME: X'03'
  Domain = 0x03,
  /// IP V6 address: X'04'
  V6 = 0x04,
}

impl AddrType {
  /// Parse Byte to Command
  fn from(n: usize) -> Option<AddrType> {
    match n {
      1 => Some(AddrType::V4),
      3 => Some(AddrType::Domain),
      4 => Some(AddrType::V6),
      _ => None,
    }
  }

  // /// Return the size of the AddrType
  // fn size(&self) -> u8 {
  //     match self {
  //         AddrType::V4 => 4,
  //         AddrType::Domain => 1,
  //         AddrType::V6 => 16
  //     }
  // }
}

/// SOCK5 CMD Type
#[derive(Debug)]
enum SockCommand {
  Connect = 0x01,
  Bind = 0x02,
  UdpAssosiate = 0x3,
}

impl SockCommand {
  /// Parse Byte to Command
  fn from(n: usize) -> Option<SockCommand> {
    match n {
      1 => Some(SockCommand::Connect),
      2 => Some(SockCommand::Bind),
      3 => Some(SockCommand::UdpAssosiate),
      _ => None,
    }
  }
}

/// Client Authentication Methods
pub enum AuthMethods {
  /// No Authentication
  NoAuth = 0x00,
  // GssApi = 0x01,
  /// Authenticate with a username / password
  UserPass = 0x02,
  SmartAuth = 0x80,
  /// Cannot authenticate
  NoMethods = 0xFF,
}

pub struct Merino {
  listener: TcpListener,
  users: Arc<Vec<User>>,
  auth_methods: Arc<Vec<u8>>,
  // Timeout for connections
  timeout: Option<Duration>,
  is_smart_auth: bool,
}

impl Merino {
  /// Create a new Merino instance
  pub async fn new(
    port: u16,
    ip: &str,
    mut auth_methods: Vec<u8>,
    users: Vec<User>,
    timeout: Option<Duration>,
  ) -> io::Result<Self> {
    let is_smart_auth = auth_methods.contains(&(AuthMethods::SmartAuth as u8));
    if is_smart_auth {
      info!("Smart Auth is enabled");
      auth_methods.clear();
      auth_methods.push(AuthMethods::UserPass as u8);
      auth_methods.push(AuthMethods::NoAuth as u8);
    }
    trace!(
      "Creating new Merino instance: ip:{}, port:{}, auth_methods:{:?}, users:{:?}, timeout:{:?}, is_smart_auth:{}",
      ip,
      port,
      auth_methods,
      users,
      timeout,
      is_smart_auth
    );

    info!("Listening on {}:{}", ip, port);
    Ok(Merino {
      listener: TcpListener::bind((ip, port)).await?,
      auth_methods: Arc::new(auth_methods),
      users: Arc::new(users),
      timeout,
      is_smart_auth,
    })
  }

  pub async fn serve(&mut self) {
    info!("Serving Connections...");
    while let Ok((stream, client_addr)) = self.listener.accept().await {
      let users = self.users.clone();
      let auth_methods = self.auth_methods.clone();
      let timeout = self.timeout.clone();
      let is_smart_auth = self.is_smart_auth.clone();
      let mut cstream: CStream<TcpStream> = CStream::new(stream, false, &None);
      if is_smart_auth {
        cstream.set_send_usage_data(true);
      }

      tokio::spawn(async move {
        let mut client = SOCKClient::new(cstream, users, auth_methods, timeout, is_smart_auth);
        match client.init().await {
          Ok(_) => {}
          Err(error) => {
            error!("Error! {:?}, client: {:?}", error, client_addr);

            if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await {
              warn!("Failed to send error code: {:?}", e);
            }

            if let Err(e) = client.shutdown().await {
              warn!("Failed to shutdown TcpStream: {:?}", e);
            };
          }
        };
      });
    }
  }
}

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static + StreamExt> {
  stream: T,
  auth_nmethods: u8,
  auth_methods: Arc<Vec<u8>>,
  authed_users: Arc<Vec<User>>,
  socks_version: u8,
  timeout: Option<Duration>,
  is_smart_auth: bool,
}

impl<T> SOCKClient<T>
where
  T: AsyncRead + AsyncWrite + Send + Unpin + StreamExt + 'static,
{
  /// Create a new SOCKClient
  pub fn new(
    stream: T,
    authed_users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
    is_smart_auth: bool,
  ) -> Self {
    SOCKClient {
      stream,
      auth_nmethods: 0,
      socks_version: 0,
      authed_users,
      auth_methods,
      timeout,
      is_smart_auth,
    }
  }

  pub fn set_username(&mut self, username: Option<Vec<u8>>) {
    self.stream.set_username(username);
  }

  /// Create a new SOCKClient with no auth
  pub fn new_no_auth(stream: T, timeout: Option<Duration>) -> Self {
    // FIXME: use option here
    let authed_users: Arc<Vec<User>> = Arc::new(Vec::new());
    let mut no_auth: Vec<u8> = Vec::new();
    no_auth.push(AuthMethods::NoAuth as u8);
    let auth_methods: Arc<Vec<u8>> = Arc::new(no_auth);

    SOCKClient {
      stream,
      auth_nmethods: 0,
      socks_version: 0,
      authed_users,
      auth_methods,
      timeout,
      is_smart_auth: false,
    }
  }

  /// Mutable getter for inner stream
  pub fn stream_mut(&mut self) -> &mut T {
    &mut self.stream
  }

  /// Check if username + password pair are valid
  fn authed(&self, user: &User) -> bool {
    self.authed_users.contains(user)
  }

  /// Shutdown a client
  pub async fn shutdown(&mut self) -> io::Result<()> {
    self.stream.shutdown().await?;
    Ok(())
  }

  pub async fn init(&mut self) -> Result<(), MerinoError> {
    debug!("New connection");
    let mut header = [0u8; 2];
    // Read a byte from the stream and determine the version being requested
    self.stream.read_exact(&mut header).await?;

    self.socks_version = header[0];
    self.auth_nmethods = header[1];

    trace!(
      "Version: {} Auth nmethods: {}",
      self.socks_version,
      self.auth_nmethods
    );

    match self.socks_version {
      SOCKS_VERSION => {
        // Authenticate w/ client
        let username = self.auth().await?;
        self.set_username(username.clone());
        // Handle requests
        self.handle_client(username).await?;
      }
      _ => {
        warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
        self.shutdown().await?;
      }
    }

    Ok(())
  }

  // Return user if the auth method is userpass
  async fn auth(&mut self) -> Result<Option<Vec<u8>>, MerinoError> {
    debug!("Authenticating");
    // Get valid auth methods
    let methods = self.get_avalible_methods().await?;
    trace!("methods: {:?}", methods);

    let mut response = [0u8; 2];

    // Set the version in the response
    response[0] = SOCKS_VERSION;

    let mut username_vec: Option<Vec<u8>> = Option::None;
    if methods.contains(&(AuthMethods::UserPass as u8)) {
      // Set the default auth method (NO AUTH)
      response[1] = AuthMethods::UserPass as u8;

      debug!("Sending USER/PASS packet");
      self.stream.write_all(&response).await?;

      let mut header = [0u8; 2];

      // Read a byte from the stream and determine the version being requested
      self.stream.read_exact(&mut header).await?;

      // debug!("Auth Header: [{}, {}]", header[0], header[1]);

      // Username parsing
      let ulen = header[1] as usize;

      username_vec = Some(vec![0; ulen]);

      self
        .stream
        .read_exact(&mut username_vec.clone().unwrap())
        .await?;

      // Password Parsing
      let mut plen = [0u8; 1];
      self.stream.read_exact(&mut plen).await?;

      let mut password = vec![0; plen[0] as usize];
      self.stream.read_exact(&mut password).await?;

      let username = String::from_utf8_lossy(&mut &username_vec.clone().unwrap()).to_string();
      let password = String::from_utf8_lossy(&password).to_string();
      let user = User { username, password };

      let mut smart_auth_success = false;
      if self.is_smart_auth {
        debug!("Smart Authenticating...");
        let username_c = CString::new(user.username.clone()).unwrap();
        let password_c = CString::new(user.password.clone()).unwrap();
        let password_ptr = password_c.as_ptr() as *const u8;
        let mut rate_limit: usize = 0;
        let mut result_msg: String = "".to_string();
        let mut result_null = true;
        unsafe {
          let result_ptr: *mut AuthResult = is_authenticated(username_c.as_ptr(), password_ptr);
          if !result_ptr.is_null() {
            result_null = false;
            smart_auth_success = result_ptr.as_ref().unwrap().success;
            rate_limit = result_ptr.as_ref().unwrap().rate_limit;
            result_msg = CStr::from_ptr(result_ptr.as_ref().unwrap().msg)
              .to_str()
              .unwrap_or_default()
              .to_string();
          }
          free_auth_result(result_ptr);
          trace!(
            "Smart auth result: result_null: {}, success: {}, rate_limit: {}, msg: {}",
            result_null,
            smart_auth_success,
            rate_limit,
            result_msg
          );
        }

        if result_null || !smart_auth_success {
          response[1] = AuthMethods::NoMethods as u8;
          self.stream.write_all(&response).await?;
          self.shutdown().await?;
          return Err(MerinoError::Socks(ResponseCode::Failure));
        }
      }

      // Authenticate passwords
      if (self.is_smart_auth && smart_auth_success) || (!self.is_smart_auth && self.authed(&user)) {
        debug!("Access Granted. User: {}", user.username);
        let response = [1, ResponseCode::Success as u8];
        self.stream.write_all(&response).await?;
      } else {
        debug!("Access Denied. User: {}", user.username);
        let response = [1, ResponseCode::Failure as u8];
        self.stream.write_all(&response).await?;
        // Shutdown
        self.shutdown().await?;
      }

      return Ok(username_vec);
    } else if methods.contains(&(AuthMethods::NoAuth as u8)) {
      let mut smart_auth_success = false;
      let mut result_is_null = true;
      if self.is_smart_auth {
        debug!("Smart Authenticating...");
        let mut rate_limit: usize = 0;
        let mut result_msg: String = "".to_string();
        if self.is_smart_auth {
          unsafe {
            let result_ptr: *mut AuthResult = is_authenticated(null(), null());
            // free_auth_result(result_ptr);
            if !result_ptr.is_null() {
              result_is_null = false;
              smart_auth_success = result_ptr.as_ref().unwrap().success;
              rate_limit = result_ptr.as_ref().unwrap().rate_limit;
              let c_char = result_ptr.as_ref().unwrap().msg;
              if !c_char.is_null() {
                let c_str = CStr::from_ptr(c_char);
                let rust_string = c_str.to_string_lossy().into_owned();
                result_msg = rust_string;
              }
            }
            free_auth_result(result_ptr);
            trace!(
              "Smart auth result: result_null: {}, success: {}, rate_limit: {}, msg: {}",
              result_is_null,
              smart_auth_success,
              rate_limit,
              result_msg
            );
          }
        }
      }

      if (result_is_null || !smart_auth_success) && self.is_smart_auth {
        trace!("Smart auth failed: is-null: {}", result_is_null);
        response[1] = AuthMethods::NoMethods as u8;
        self.stream.write_all(&response).await?;
        // self.shutdown().await?;
        return Err(MerinoError::Socks(ResponseCode::Failure));
      } else {
        trace!("Sending NOAUTH packet");
        response[1] = AuthMethods::NoAuth as u8;
        self.stream.write_all(&response).await?;
        trace!("NOAUTH sent");
        return Ok(None);
      };
    } else {
      warn!("Client has no suitable Auth methods!");
      response[1] = AuthMethods::NoMethods as u8;
      self.stream.write_all(&response).await?;
      self.shutdown().await?;

      Err(MerinoError::Socks(ResponseCode::Failure))
    }
  }

  /// Handles a client
  pub async fn handle_client(&mut self, username: Option<Vec<u8>>) -> Result<usize, MerinoError> {
    debug!("Starting to relay data");

    let mut req = SOCKSReq::from_stream(&mut self.stream).await?;

    if req.addr_type == AddrType::V6 {}

    // Log Request
    let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);
    info!(
      "New Request: Command: {:?} Addr: {}, Port: {}",
      req.command, displayed_addr, req.port
    );

    // Check if the user could have access to the destination address
    let addr_type = match req.addr_type {
      AddrType::V4 => 0,
      AddrType::V6 => 1,
      AddrType::Domain => 2,
    };
    let has_access = unsafe {
      match username {
        Some(ref username) => {
          trace!(
            "Username is not none. addr_type: {}, addr: {}",
            addr_type,
            displayed_addr
          );
          has_access2dest(
            username.as_ptr() as *const i8,
            addr_type,
            req.addr.as_mut_ptr(),
          )
        }
        None => {
          trace!(
            "Username is none. addr_type: {}, addr: {}",
            addr_type,
            displayed_addr
          );
          has_access2dest(null(), addr_type, req.addr.as_mut_ptr())
        }
      }
    };
    if !has_access {
      let username_str = match username {
        Some(un) => String::from_utf8_lossy(&un).to_string(),
        None => "None".to_string(),
      };
      trace!(
        "The user '{}' doesn't have access to the dest {}",
        username_str,
        displayed_addr
      );
      return Err(MerinoError::Socks(ResponseCode::DestForbidden));
    };

    // Respond
    match req.command {
      // Use the Proxy to connect to the specified addr/port
      SockCommand::Connect => {
        debug!("Handling CONNECT Command");
        let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port).await?;
        trace!("Connecting to: {:?}", sock_addr);
        let time_out = if let Some(time_out) = self.timeout {
          time_out
        } else {
          Duration::from_millis(500)
        };

        let mut target = timeout(
          time_out,
          async move { TcpStream::connect(&sock_addr[..]).await },
        )
        .await
        .map_err(|_| MerinoError::Socks(ResponseCode::ConnectionRefused))??;
        trace!("Connected!");
        SocksReply::new(ResponseCode::Success)
          .send(&mut self.stream)
          .await?;

        trace!("copy bidirectional");

        match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
          // ignore not connected for shutdown error
          Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
            trace!("already closed");
            Ok(0)
          }
          Err(e) => Err(MerinoError::Io(e)),
          Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
        }
      }
      SockCommand::Bind => Err(MerinoError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Bind not supported",
      ))),
      SockCommand::UdpAssosiate => Err(MerinoError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "UdpAssosiate not supported",
      ))),
    }
  }

  /// Return the avalible methods based on `self.auth_nmethods`
  async fn get_avalible_methods(&mut self) -> io::Result<Vec<u8>> {
    let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
    for _ in 0..self.auth_nmethods {
      let mut method = [0u8; 1];
      self.stream.read_exact(&mut method).await?;
      if self.auth_methods.contains(&method[0]) {
        methods.append(&mut method.to_vec());
      }
    }
    Ok(methods)
  }
}

/// Convert an address and AddrType to a SocketAddr
async fn addr_to_socket(
  addr_type: &AddrType,
  addr: &[u8],
  port: u16,
) -> io::Result<Vec<SocketAddr>> {
  match addr_type {
    AddrType::V6 => {
      let new_addr = (0..8)
        .map(|x| {
          trace!("{} and {}", x * 2, (x * 2) + 1);
          (u16::from(addr[x * 2]) << 8) | u16::from(addr[(x * 2) + 1])
        })
        .collect::<Vec<u16>>();

      Ok(vec![SocketAddr::from(SocketAddrV6::new(
        Ipv6Addr::new(
          new_addr[0],
          new_addr[1],
          new_addr[2],
          new_addr[3],
          new_addr[4],
          new_addr[5],
          new_addr[6],
          new_addr[7],
        ),
        port,
        0,
        0,
      ))])
    }
    AddrType::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
      Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
      port,
    ))]),
    AddrType::Domain => {
      let mut domain = String::from_utf8_lossy(addr).to_string();
      domain.push(':');
      domain.push_str(&port.to_string());

      Ok(lookup_host(domain).await?.collect())
    }
  }
}

/// Convert an AddrType and address to String
fn pretty_print_addr(addr_type: &AddrType, addr: &[u8]) -> String {
  match addr_type {
    AddrType::Domain => String::from_utf8_lossy(addr).to_string(),
    AddrType::V4 => addr
      .iter()
      .map(std::string::ToString::to_string)
      .collect::<Vec<String>>()
      .join("."),
    AddrType::V6 => {
      let addr_16 = (0..8)
        .map(|x| (u16::from(addr[x * 2]) << 8) | u16::from(addr[(x * 2) + 1]))
        .collect::<Vec<u16>>();

      addr_16
        .iter()
        .map(|x| format!("{:x}", x))
        .collect::<Vec<String>>()
        .join(":")
    }
  }
}

/// Proxy User Request
#[allow(dead_code)]
struct SOCKSReq {
  pub version: u8,
  pub command: SockCommand,
  pub addr_type: AddrType,
  pub addr: Vec<u8>,
  pub port: u16,
}

impl SOCKSReq {
  /// Parse a SOCKS Req from a TcpStream
  async fn from_stream<T>(stream: &mut T) -> Result<Self, MerinoError>
  where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
  {
    // From rfc 1928 (S4), the SOCKS request is formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    // Where:
    //
    //      o  VER    protocol version: X'05'
    //      o  CMD
    //         o  CONNECT X'01'
    //         o  BIND X'02'
    //         o  UDP ASSOCIATE X'03'
    //      o  RSV    RESERVED
    //      o  ATYP   address type of following address
    //         o  IP V4 address: X'01'
    //         o  DOMAINNAME: X'03'
    //         o  IP V6 address: X'04'
    //      o  DST.ADDR       desired destination address
    //      o  DST.PORT desired destination port in network octet
    //         order
    trace!("Server waiting for connect (receiving request details)");
    let mut packet = [0u8; 4];
    // Read a byte from the stream and determine the version being requested
    stream.read_exact(&mut packet).await?;
    trace!("Server received {:?}", packet);

    if packet[0] != SOCKS_VERSION {
      warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
      stream.shutdown().await?;
    }

    // Get command
    let command = match SockCommand::from(packet[1] as usize) {
      Some(com) => Ok(com),
      None => {
        warn!("Invalid Command");
        stream.shutdown().await?;
        Err(MerinoError::Socks(ResponseCode::CommandNotSupported))
      }
    }?;

    // DST.address
    let addr_type = match AddrType::from(packet[3] as usize) {
      Some(addr) => Ok(addr),
      None => {
        error!("No Addr");
        stream.shutdown().await?;
        Err(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
      }
    }?;

    trace!("Getting Addr");
    // Get Addr from addr_type and stream
    let addr: Vec<u8> = match addr_type {
      AddrType::Domain => {
        let mut dlen = [0u8; 1];
        stream.read_exact(&mut dlen).await?;
        let mut domain = vec![0u8; dlen[0] as usize];
        stream.read_exact(&mut domain).await?;
        domain
      }
      AddrType::V4 => {
        let mut addr = [0u8; 4];
        stream.read_exact(&mut addr).await?;
        addr.to_vec()
      }
      AddrType::V6 => {
        let mut addr = [0u8; 16];
        stream.read_exact(&mut addr).await?;
        addr.to_vec()
      }
    };

    // read DST.port
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;

    // Merge two u8s into u16
    let port = (u16::from(port[0]) << 8) | u16::from(port[1]);

    // Return parsed request
    Ok(SOCKSReq {
      version: packet[0],
      command,
      addr_type,
      addr,
      port,
    })
  }
}
