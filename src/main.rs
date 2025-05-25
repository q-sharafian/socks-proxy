#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![warn(clippy::all, rust_2018_idioms)]
#[macro_use]
extern crate log;

use clap::{ArgGroup, Parser, ValueEnum};
use merino::*;
use std::env;
use std::error::Error;
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;

/// Logo to be printed at when merino is run
const LOGO: &str = r"
     / \  | |__  _ __(_)___| |__   __ _ _ __ ___  
    / _ \ | '_ \| '__| / __| '_ \ / _` | '_ ` _ \ 
   / ___ \| |_) | |  | \__ \ | | | (_| | | | | | |
  /_/   \_\_.__/|_|  |_|___/_| |_|\__,_|_| |_| |_|

 A SOCKS5 Proxy server written in Rust
";

#[derive(Debug, PartialEq, Clone, ValueEnum)]
enum AuthType {
  NoAuth,
  Users,
  SmartAuth,
}

#[derive(Parser, Debug)]
#[clap(version)]
#[clap(group(
    ArgGroup::new("auth")
        .required(true)
        .args(&["auth_type", "users"]),
), group(
    ArgGroup::new("log")
        .args(&["verbosity", "quiet"])
        .required(false)
))]
struct Opt {
  #[clap(short, long, default_value_t = 1080)]
  /// Set port to listen on
  port: u16,

  #[clap(short, long, default_value = "127.0.0.1")]
  /// Set ip to listen on
  ip: String,

  #[clap(long)]
  /// Allow insecure configuration
  allow_insecure: bool,

  #[clap(long, default_value_t = AuthType::NoAuth)]
  #[arg(value_enum)]
  /// Set type of authentication
  auth_type: AuthType,

  #[clap(short, long)]
  /// CSV File with username/password pairs
  users: Option<PathBuf>,

  /// Log verbosity level. -vv for more verbosity.
  /// Environmental variable `RUST_LOG` overrides this flag!
  // #[clap(short, parse(from_occurrences))]
  #[clap(short, default_value_t = 3)]
  verbosity: u8,

  /// Do not output any logs (even errors!). Overrides `RUST_LOG`
  #[clap(short)]
  quiet: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  dotenv::dotenv().ok();
  
  println!("{}", LOGO);

  let opt = Opt::parse();

  // Setup logging
  let log_env = env::var("RUST_LOG");
  if log_env.is_err() {
    let level = match opt.verbosity {
      1 => "merino=DEBUG",
      2 => "merino=TRACE",
      _ => "merino=INFO",
    };
    env::set_var("RUST_LOG", level);
  }

  if !opt.quiet {
    pretty_env_logger::init_timed();
  }

  if log_env.is_ok() && (opt.verbosity != 0) {
    warn!(
      "Log level is overriden by environmental variable to `{}`",
      // It's safe to unwrap() because we checked for is_ok() before
      log_env.unwrap().as_str()
    );
  }

  // Setup Proxy settings

  let mut auth_methods: Vec<u8> = Vec::new();

  // Allow unauthenticated connections
  if opt.auth_type == AuthType::SmartAuth {
    auth_methods.push(merino::AuthMethods::SmartAuth as u8);
  } else if opt.auth_type == AuthType::NoAuth {
    auth_methods.push(merino::AuthMethods::NoAuth as u8);
  }
  // Enable username/password auth
  let mut authed_users: Result<Vec<User>, Box<dyn Error>> = Ok(Vec::new());
  if opt.auth_type != AuthType::SmartAuth {
    authed_users = match opt.users {
      Some(users_file) => {
        auth_methods.push(AuthMethods::UserPass as u8);
        let file = std::fs::File::open(&users_file).unwrap_or_else(|e| {
          error!("Can't open file {:?}: {}", &users_file, e);
          std::process::exit(1);
        });

        let metadata = file.metadata()?;
        // 7 is (S_IROTH | S_IWOTH | S_IXOTH) or the "permisions for others" in unix
        if (metadata.mode() & 7) > 0 && !opt.allow_insecure {
          error!(
            "Permissions {:o} for {:?} are too open. \
                    It is recommended that your users file is NOT accessible by others. \
                    To override this check, set --allow-insecure",
            metadata.mode() & 0o777,
            &users_file
          );
          std::process::exit(1);
        }

        let mut users: Vec<User> = Vec::new();

        let mut rdr = csv::Reader::from_reader(file);
        for result in rdr.deserialize() {
          let record: User = match result {
            Ok(r) => r,
            Err(e) => {
              error!("{}", e);
              std::process::exit(1);
            }
          };

          trace!("Loaded user: {}", record.username);
          users.push(record);
        }

        if users.is_empty() {
          error!(
            "No users loaded from {:?}. Check configuration.",
            &users_file
          );
          std::process::exit(1);
        }

        Ok(users)
      }
      _ => Ok(Vec::new()),
    };
  }

  let authed_users = authed_users?;

  let authenticator = Authenticator::new();
  let dest_checker = DestChecking::new();
  let net_usage = NetUsage::new();
  // Create proxy server
  let mut merino = Merino::new(
    opt.port,
    &opt.ip,
    auth_methods,
    authed_users,
    None,
    Mutex::new(authenticator),
    Mutex::new(dest_checker),
    net_usage,
  )
  .await?;
  // Start Proxies
  merino.serve().await;
  Ok(())
}
