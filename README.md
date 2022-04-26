ftp-rs
================

The full supported FTP client for Rust

## Installation

FTPS support is disabled by default. To enable it `ftps` should be activated in `Cargo.toml`.
```toml
[dependencies]
ftp-rs = { version = "<version>", features = ["ftps"] }
```

## Usage
```rust
use std::str;
use std::io::Cursor;
use ftp_rs::FtpClient;

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a connection to an FTP server and authenticate to it.
    let mut ftp_client = FtpClient::connect("192.168.32.204:21").await?;
    let _ = ftp_client.login("username", "password").await?;

    // Get the current Directory that the client will be reading from and writing to.
    println!("Current Directory: {}", ftp_client.pwd().await?);
    
    // Change into a new Directory, relative to the one we are currently in.
    let _ = ftp_client.cwd("test_data").await?;

    // Retrieve (GET) a File from the FTP server in the current working Directory.
    let remote_file = ftp_client.simple_retr("ftpext-charter.txt").await?;
    println!("Read File with contents\n{}\n", str::from_utf8(&remote_file.into_inner()).await?);

    // Store (PUT) a File from the client to the current working Directory of the server.
    let mut reader = Cursor::new("Hello from the Rust \"ftp-rs\" crate!".as_bytes());
    let _ = ftp_client.put("greeting.txt", &mut reader).await?;
    println!("Successfully wrote greeting.txt");

    // Terminate the connection to the server.
    let _ = ftp_client.quit();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new()
        .threaded_scheduler()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
}
```
