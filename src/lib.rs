//! ftp is an FTP client written in Rust.
//!
//! ### Usage
//!
//! Here is a basic usage example:
//!
//! ```rust,no_run
//! use ftp_rs::FtpClient;
//! async {
//!   let mut ftp_client = FtpClient::connect("172.25.82.139:21").await.unwrap_or_else(|err|
//!       panic!("{}", err)
//!   );
//!   let _ = ftp_client.quit();
//! };
//! ```
//!
//! ### FTPS
//!
//! The client supports FTPS on demand. To enable it the client should be
//! compiled with feature `openssl` enabled what requires
//! [openssl](https://crates.io/crates/openssl) dependency.
//!
//! The client uses explicit mode for connecting FTPS what means you should
//! connect the server as usually and then switch to the secure mode (TLS is used).
//! For better security it's the good practice to switch to the secure mode
//! before authentication.
//!
//! ### FTPS Usage
//!
//! ```rust,no_run
//! use std::convert::TryFrom;
//! use std::path::Path;
//! use ftp_rs::FtpClient;
//! use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
//!
//! async {
//!   let ftp_client = FtpClient::connect("172.25.82.139:21").await.unwrap();
//!   
//!   let mut root_store = RootCertStore::empty();
//!   // root_store.add_pem_file(...);
//!   let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
//!   let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
//!
//!   // Switch to the secure mode
//!   let mut ftp_client = ftp_client.into_secure(conf, domain).await.unwrap();
//!   ftp_client.login("anonymous", "anonymous").await.unwrap();
//!   // Do other secret stuff
//!   // Switch back to the insecure mode (if required)
//!   let mut ftp_client = ftp_client.into_insecure().await.unwrap();
//!   // Do all public stuff
//!   let _ = ftp_client.quit().await;
//! };
//! ```
//!

mod connection;
mod ftp_client;
pub mod ftp_reply;
pub mod types;
pub mod cmd;

pub use self::connection::Connection;
pub use self::ftp_client::FtpClient;
pub use self::types::FtpError;

pub const REPLY_CODE_LEN: usize = 3;

pub const MODES: &'static str = "AEILNTCFRPSBC";

pub trait StringExt {
    fn substring(&self, start_index: usize, end_index: usize) -> &str;
}

impl StringExt for str {
    fn substring(&self, start_index: usize, end_index: usize) -> &str {
        if end_index <= start_index {
            return "";
        }

        let mut indices = self.char_indices();

        let obtain_index = |(index, _char)| index;
        let str_len = self.len();

        unsafe {
            self.slice_unchecked(
                indices.nth(start_index).map_or(str_len, &obtain_index),
                indices
                    .nth(end_index - start_index - 1)
                    .map_or(str_len, &obtain_index),
            )
        }
    }
}