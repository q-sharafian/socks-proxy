```
                     _
 _ __ ___   ___ _ __(_)_ __   ___
| '_ ` _ \ / _ \ '__| | '_ \ / _ \
| | | | | |  __/ |  | | | | | (_) |
|_| |_| |_|\___|_|  |_|_| |_|\___/
```

**A `SOCKS5` Proxy server written in Rust**

[![Crates.io](https://img.shields.io/crates/v/merino.svg)](https://crates.io/crates/merino)
[![stego](https://docs.rs/merino/badge.svg)](https://docs.rs/merino)
[![License](https://img.shields.io/crates/l/pbr.svg)](https://github.com/ajmwagar/merino/blob/master/LICENSE.md)
[![Build Status](https://travis-ci.org/ajmwagar/merino.svg?branch=master)](https://travis-ci.org/ajmwagar/merino)
[![dependency status](https://deps.rs/repo/github/ajmwagar/merino/status.svg)](https://deps.rs/repo/github/ajmwagar/merino)

## 🎁 Features

- Written in **100% Safe Rust**
- Multi-threaded connection handler
- Lightweight (Less than 0.6% CPU usage while surfing the web/streaming YouTube)
- Standalone binary (no system dependencies)
- `1+ Gb/second` connection speeds (**On Gigabit LAN network over ethernet. Results may vary!**)
- Tunable logging (by flags or `RUST_LOG` environmental variable)
- `SOCKS5` Compatible Authentication methods:
  - `NoAuth`
  - Username & Password
  - `GSSAPI` Coming Soon!

## 📦 Installation & 🏃 Usage

### Installation

```bash
cargo install merino
```

OR

```bash
git clone https://github.com/ajmwagar/merino
cd merino
cargo install --path .
```

OR do the following:  
1) Set env vars
2) run `cargo build` or `cargo build --release`
3) Run `RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/debug/merino --auth-type smart-auth` or `./target/debug/merino --auth-type smart-auth`
OR

```bash
docker image pull ghcr.io/ajmwagar/merino:latest
```

- To check if a port is open use below command:
```bash
telnet <dest-ip> <dest-port>
netstat -lntu
ss -lntu
```
- Disabling/enabling proxy for some services
```bash
sudo vim /etc/apt/apt.conf # Add some code here for disabling/enabling Apt proxy
vim .docker/config.json # Edit this file for enabling/disabling Docker proxy
```

### Usage

```bash
# Start a SOCKS5 Proxy server listening on port 1080 without authentication
RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/release/merino --auth-type no-auth

# Use username/password authentication and read users from users.csv
RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/release/merino --users users.csv --allow-insecure

# Decide if a user has to be authenticated or not based on the business logic:
RUST_LOG=trace LD_LIBRARY_PATH=~/Development/req-processor/target/release ./target/release/merino --auth-type smart-auth

# Display a help menu
merino --help
```

OR

```bash
docker container run --pull=always --name=merino -p=8001:8001 ghcr.io/ajmwagar/merino:latest --no-auth --port=8001
```

TODO: In long-time connections (like streams), calculate the usage rate time in shorter intervals.

# 🚥 Roadmap

- [x] IPV6 Support
- [ ] `SOCKS5` Authentication Methods
  - [x] `NOAUTH`
  - [x] `USERPASS`
  - [ ] `GSSAPI` Coming Soon!
- [ ] Custom plugin/middleware support
- [ ] `SOCKS5` Commands
  - [x] `CONNECT`
  - [ ] `BIND`
  - [ ] `ASSOCIATE`
- [ ] Benchmarks & Unit tests
- [ ] [Actix](https://github.com/actix-rs/actix) based backend
- [ ] `SOCKS4`/`SOCKS4a` Support
