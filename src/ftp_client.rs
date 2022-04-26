//! FTP module.
use std::borrow::{Borrow, Cow};
use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::net::{IpAddr, SocketAddr};
use std::string::String;

use chrono::offset::TimeZone;
use chrono::{DateTime, Utc};
use regex::Regex;
use tokio::io::{
    copy, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufStream,
};
use tokio::net::{TcpStream, ToSocketAddrs};
#[cfg(feature = "ftps")]
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, rustls::ServerName, TlsConnector};

use crate::cmd::Command;
use crate::connection::Connection;
use crate::types::{FileType, FtpError, Result};
use crate::{cmd, ftp_reply, StringExt, MODES, REPLY_CODE_LEN};

lazy_static::lazy_static! {
    // This regex extracts IP and Port details from PASV command response.
    // The regex looks for the pattern (h1,h2,h3,h4,p1,p2).
    static ref PORT_RE: Regex = Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap();

    // This regex extracts modification time from MDTM command response.
    static ref MDTM_RE: Regex = Regex::new(r"\b(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\b").unwrap();

    // This regex extracts File size from SIZE command response.
    static ref SIZE_RE: Regex = Regex::new(r"\s+(\d+)\s*$").unwrap();
}

pub struct FtpClient {
    stream: BufStream<Connection>,
    welcome_msg: Option<String>,
    _reply_code: u32,
    _reply_string: Option<String>,
    _reply_lines: Vec<String>,
    #[cfg(feature = "ftps")]
    ssl_cfg: Option<(ClientConfig, ServerName)>,
    features_map: HashMap<String, Vec<String>>,
}

impl FtpClient {
    fn new(stream: TcpStream) -> Self {
        FtpClient {
            stream: BufStream::new(Connection::Tcp(stream)),
            #[cfg(feature = "ftps")]
            ssl_cfg: None,
            welcome_msg: None,
            _reply_code: 0,
            _reply_string: None,
            features_map: HashMap::new(),
            _reply_lines: vec![],
        }
    }

    #[cfg(feature = "ftps")]
    fn new_tls_client(stream: TlsStream<TcpStream>) -> Self {
        FtpClient {
            stream: BufStream::new(Connection::Ssl(stream)),
            ssl_cfg: None,
            welcome_msg: None,
            _reply_code: 0,
            _reply_string: None,
            features_map: HashMap::new(),
            _reply_lines: vec![],
        }
    }

    pub fn init_default(&mut self) {}

    /// Creates an FTP Client.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpClient> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        let mut ftp_client = FtpClient::new(stream);
        ftp_client.read_reply().await?;
        ftp_client.check_response(ftp_reply::READY)?;
        ftp_client.welcome_msg = Some(ftp_client._reply_string.clone().unwrap());
        Ok(ftp_client)
    }

    /// Switch to a secure mode if possible, using a provided SSL configuration.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Panics
    ///
    /// Panics if the plain TCP connection cannot be switched to TLS mode.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    /// use std::path::Path;
    /// use ftp_rs::FtpClient;
    /// use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
    ///
    /// let mut root_store = RootCertStore::empty();
    /// // root_store.add_pem_file(...);
    /// let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    /// let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
    /// async {
    ///   let mut ftp_client = FtpClient::connect("192.168.32.204:21").await.unwrap();
    ///   let mut ftp_client = ftp_client.into_secure(conf, domain).await.unwrap();
    /// };
    /// ```
    #[cfg(feature = "ftps")]
    pub async fn into_secure(
        mut self,
        config: ClientConfig,
        domain: ServerName,
    ) -> Result<FtpClient> {
        self.send_command(Command::AUTH, Some("TLS")).await?;
        self.check_response(ftp_reply::AUTH_OK)?;

        let connector: TlsConnector = std::sync::Arc::new(config.clone()).into();
        let stream = connector
            .connect(domain.clone(), self.stream.into_inner().into_tcp_stream())
            .await
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;

        let mut ftps_client = FtpClient::new_tls_client(stream);
        ftps_client.ssl_cfg = Some((config, domain));

        // Set protection buffer size
        ftps_client.send_command(Command::PBSZ, Some("0")).await?;
        ftps_client.check_response(ftp_reply::COMMAND_OK)?;

        ftps_client.send_command(Command::PROT, Some("P")).await?;
        ftps_client.check_response(ftp_reply::COMMAND_OK)?;
        Ok(ftps_client)
    }

    /// Switch to insecure mode. If the connection is already
    /// insecure does nothing.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    /// use std::path::Path;
    /// use ftp_rs::FtpClient;
    /// use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerName};
    ///
    /// let mut root_store = RootCertStore::empty();
    /// // root_store.add_pem_file(...);
    /// let conf = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    /// let domain = ServerName::try_from("www.cert-domain.com").expect("invalid DNS name");
    /// async {
    ///   let mut ftp_client = FtpClient::connect("192.168.32.204:21").await.unwrap();
    ///   let mut ftp_client = ftp_client.into_secure(conf, domain).await.unwrap();
    ///   // Switch back to the insecure mode
    ///   let mut ftp_client = ftp_client.into_insecure().await.unwrap();
    ///   // Do all public things
    ///   let _ = ftp_client.quit();
    /// };
    /// ```
    #[cfg(feature = "ftps")]
    pub async fn into_insecure(mut self) -> Result<FtpClient> {
        self.send_command(Command::CCC, None).await?;
        if self._reply_code == ftp_reply::COMMAND_OK {
            Ok(FtpClient::new(self.stream.into_inner().into_tcp_stream()))
        }
        Err(FtpError::InvalidResponse(format!(
            "Expected code {:?}, got response: {}",
            ftp_reply::COMMAND_OK,
            self._reply_string.unwrap()
        )))
    }

    /// Execute command which send data back in a separate stream
    async fn data_command(&mut self, cmd: &str) -> Result<Connection> {
        let addr = self.pasv().await?;
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        #[cfg(feature = "ftps")]
        match &self.ssl_cfg {
            Some((config, domain)) => {
                let connector: TlsConnector = std::sync::Arc::new(config.clone()).into();
                return connector
                    .connect(domain.to_owned(), stream)
                    .await
                    .map(|stream| Connection::Ssl(stream))
                    .map_err(|e| FtpError::SecureError(format!("{}", e)));
            }
            _ => {}
        };
        self.write_str(cmd).await?;
        self.read_reply().await?;
        Ok(Connection::Tcp(stream))
    }

    /// Returns a reference to the underlying TcpStream.
    ///
    /// Example:
    /// ```no_run
    /// use tokio::net::TcpStream;
    /// use std::time::Duration;
    /// use ftp_rs::FtpClient;
    ///
    /// async {
    ///   let client = FtpClient::connect("192.168.32.204:21").await
    ///                          .expect("Couldn't connect to the server...");
    ///   let s: &TcpStream = client.get_ref();
    /// };
    /// ```
    pub fn get_ref(&self) -> &TcpStream {
        self.stream.get_ref().get_ref()
    }

    /// Get welcome message from the server on connect.
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Log in to the FTP server.
    pub async fn login(&mut self, user: &str, password: &str) -> Result<bool> {
        self.send_command(Command::USER, Some(user)).await?;
        if ftp_reply::is_positive_completion(self._reply_code) {
            return Ok(true);
        } else if !ftp_reply::is_positive_intermediate(self._reply_code) {
            return Ok(false);
        }
        self.send_command(Command::PASS, Some(password)).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// Change the current Directory to the path specified.
    pub async fn cwd(&mut self, path: &str) -> Result<bool> {
        self.send_command(Command::CWD, Some(path)).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// Move the current Directory to the parent Directory.
    pub async fn cdup(&mut self) -> Result<bool> {
        self.send_command(Command::CDUP, None).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// Gets the current Directory
    pub async fn pwd(&mut self) -> Result<String> {
        self.send_command(Command::PWD, None).await?;
        match &self._reply_string {
            None => {
                let cause = format!("Cannot get PWD Response from FTP server");
                Err(FtpError::InvalidResponse(cause))
            }
            Some(content) => match (content.find('"'), content.rfind('"')) {
                (Some(begin), Some(end)) if begin < end => Ok(content[begin + 1..end].to_string()),
                _ => {
                    let cause = format!("Invalid PWD Response: {}", content);
                    Err(FtpError::InvalidResponse(cause))
                }
            },
        }
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub async fn noop(&mut self) -> Result<bool> {
        self.send_command(Command::NOOP, None).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// This creates a new Directory on the server.
    pub async fn make_directory(&mut self, pathname: &str) -> Result<bool> {
        match ftp_reply::is_positive_completion(self.mkd(pathname).await?) {
            true => Ok(true),
            false => {
                return Err(FtpError::InvalidResponse(format!(
                    "Got error reply: {}",
                    self._reply_string.as_ref().unwrap()
                )));
            }
        }
    }

    /// A convenience method to send the FTP MKD command to the server, receive the reply, and return the reply code.
    pub async fn mkd(&mut self, pathname: &str) -> Result<u32> {
        Ok(self.send_command(Command::MKD, Some(pathname)).await?)
    }

    /// A convenience method to send the FTP ACCT command to the server, receive the reply, and return the reply code.
    pub async fn acct(&mut self, account: &str) -> Result<u32> {
        Ok(self.send_command(Command::ACCT, Some(account)).await?)
    }

    /// A convenience method to send the FTP ABOR command to the server, receive the reply, and return the reply code.
    pub async fn abor(&mut self) -> Result<u32> {
        Ok(self.send_command(Command::ABOR, None).await?)
    }

    /// A convenience method to send the FTP REIN command to the server, receive the reply, and return the reply code.
    pub async fn rein(&mut self) -> Result<u32> {
        Ok(self.send_command(Command::REIN, None).await?)
    }

    /// A convenience method to send the FTP SMNT command to the server, receive the reply, and return the reply code.
    pub async fn smnt(&mut self, dir: &str) -> Result<u32> {
        Ok(self.send_command(Command::SMNT, Some(dir)).await?)
    }

    /// A convenience method to send the FTP EPSV command to the server, receive the reply, and return the reply code.
    pub async fn epsv(&mut self) -> Result<u32> {
        Ok(self.send_command(Command::EPSV, None).await?)
    }

    /// A convenience method to send the FTP TYPE command to the server, receive the reply, and return the reply code.
    pub async fn type_cmd(&mut self, file_type: u32) -> Result<u32> {
        let s = MODES.substring(file_type as usize, (file_type + 1) as usize);
        Ok(self.send_command(Command::TYPE, Some(s)).await?)
    }

    /// A convenience method to send the FTP STRU command to the server, receive the reply, and return the reply code.
    pub async fn stru(&mut self, structure: u32) -> Result<u32> {
        let s = MODES.substring(structure as usize, (structure + 1) as usize);
        Ok(self.send_command(Command::STRU, Some(s)).await?)
    }

    /// A convenience method to send the FTP MODE command to the server, receive the reply, and return the reply code.
    pub async fn mode(&mut self, mode: u32) -> Result<u32> {
        let s = MODES.substring(mode as usize, (mode + 1) as usize);
        Ok(self.send_command(Command::MODE, Some(s)).await?)
    }

    /// A convenience method to send the FTP STOU command to the server, receive the reply, and return the reply code.
    pub async fn stou(&mut self) -> Result<u32> {
        Ok(self.send_command(Command::STOU, None).await?)
    }

    /// A convenience method to send the FTP STOU command to the server, receive the reply, and return the reply code.
    pub async fn stou_pathname(&mut self, pathname: &str) -> Result<u32> {
        Ok(self.send_command(Command::STOU, Some(pathname)).await?)
    }

    /// A convenience method to send the FTP APPE command to the server, receive the reply, and return the reply code.
    pub async fn appe(&mut self, pathname: &str) -> Result<u32> {
        Ok(self.send_command(Command::APPE, Some(pathname)).await?)
    }

    /// A convenience method to send the FTP ALLO command to the server, receive the reply, and return the reply code.
    pub async fn allo(&mut self, bytes: u32) -> Result<u32> {
        Ok(self
            .send_command(Command::ALLO, Some(bytes.to_string().as_str()))
            .await?)
    }

    /// A convenience method to send the FTP ALLO command to the server, receive the reply, and return the reply code.
    pub async fn allo_record_size(&mut self, bytes: u32, record_size: u32) -> Result<u32> {
        let args = format!(
            "{} R {}",
            bytes.to_string().as_str(),
            record_size.to_string().as_str()
        );
        Ok(self
            .send_command(Command::ALLO, Some(args.as_str()))
            .await?)
    }

    /// A convenience method to send the FTP PORT command to the server, receive the reply, and return the reply code.
    pub async fn port(&mut self, host: IpAddr, port: u16) -> Result<u32> {
        let mut args = String::with_capacity(24);
        args.push_str(host.to_string().replace('.', ",").as_str());
        args.push_str(",");
        args.push_str((port >> 8).to_string().as_str());
        args.push_str(",");
        args.push_str((port & 0xff).to_string().as_str());
        Ok(self
            .send_command(Command::PORT, Some(args.as_str()))
            .await?)
    }

    /// A convenience method to send the FTP EPRT command to the server, receive the reply, and return the reply code.
    /// * EPRT |1|132.235.1.2|6275|
    /// * EPRT |2|1080::8:800:200C:417A|5282|
    pub async fn eprt(&mut self, host: IpAddr, port: u16) -> Result<u32> {
        let mut args = String::new();
        let mut h = host.to_string();
        let n = h.find("%").unwrap_or(0);
        if n > 0 {
            h = h.substring(0, n).to_string();
        }
        args.push_str("|");
        match host {
            IpAddr::V4(addr) => args.push_str("1"),
            IpAddr::V6(addr) => args.push_str("2"),
        }
        args.push_str("|");
        args.push_str(h.as_str());
        args.push_str("|");
        args.push_str(port.to_string().as_str());
        args.push_str("|");
        Ok(self
            .send_command(Command::EPRT, Some(args.as_str()))
            .await?)
    }

    /// A convenience method to send the FTP MFMT command to the server, receive the reply, and return the reply code.
    pub async fn mfmt(&mut self, pathname: &str, timeval: &str) -> Result<u32> {
        Ok(self
            .send_command(
                Command::MFMT,
                Some(format!("{} {}", timeval, pathname).as_str()),
            )
            .await?)
    }

    /// Runs the PASV command.
    async fn pasv(&mut self) -> Result<SocketAddr> {
        self.send_command(Command::PASV, None).await?;
        self.check_response(ftp_reply::PASSIVE_MODE)?;
        let reply_str = self._reply_string.clone().unwrap();
        let reply_str = reply_str.as_str();
        PORT_RE
            .captures(reply_str)
            .ok_or_else(|| {
                FtpError::InvalidResponse(format!("Invalid PASV response: {}", reply_str))
            })
            .and_then(|caps| {
                // If the regex matches we can be sure groups contains numbers
                let (oct1, oct2, oct3, oct4) = (
                    caps[1].parse::<u8>().unwrap(),
                    caps[2].parse::<u8>().unwrap(),
                    caps[3].parse::<u8>().unwrap(),
                    caps[4].parse::<u8>().unwrap(),
                );
                let (msb, lsb) = (
                    caps[5].parse::<u8>().unwrap(),
                    caps[6].parse::<u8>().unwrap(),
                );
                let port = ((msb as u16) << 8) + lsb as u16;

                use std::net::{IpAddr, Ipv4Addr};

                let ip = if (oct1, oct2, oct3, oct4) == (0, 0, 0, 0) {
                    self.get_ref()
                        .peer_addr()
                        .map_err(FtpError::ConnectionError)?
                        .ip()
                } else {
                    IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
                };
                Ok(SocketAddr::new(ip, port))
            })
    }

    /// Sets the type of File to be transferred. That is the implementation
    /// of `TYPE` command.
    pub async fn transfer_type(&mut self, file_type: FileType) -> Result<bool> {
        // let type_command = format!("TYPE {}\r\n", file_type.to_string());
        // self.write_str(&type_command).await?;
        self.send_command(Command::TYPE, Some(file_type.to_string().as_str()))
            .await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// Quits the current FTP session.
    pub async fn logout(&mut self) -> Result<bool> {
        self.send_command(Command::QUIT, None).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// Sets the byte from which the transfer is to be restarted.
    pub async fn restart_from(&mut self, offset: u64) -> Result<bool> {
        self.send_command(Command::REST, Some(offset.to_string().as_str()))
            .await?;
        Ok(ftp_reply::is_positive_intermediate(self._reply_code))
    }

    /// Retrieves the File name specified from the server.
    /// This method is a more complicated way to retrieve a File.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    pub async fn get(&mut self, file_name: &str) -> Result<BufStream<Connection>> {
        let retr_command = format!("RETR {}\r\n", file_name);
        let data_stream = BufStream::new(self.data_command(&retr_command).await?);
        self.check_response_in(&[ftp_reply::ABOUT_TO_SEND, ftp_reply::ALREADY_OPEN])?;
        Ok(data_stream)
    }

    /// Renames the File from_name to to_name
    pub async fn rename(&mut self, from_name: &str, to_name: &str) -> Result<bool> {
        self.send_command(Command::RNFR, Some(from_name)).await?;
        if !ftp_reply::is_positive_intermediate(self._reply_code) {
            return Ok(false);
        }
        self.send_command(Command::RNTO, Some(to_name)).await?;
        Ok(ftp_reply::is_positive_completion(self._reply_code))
    }

    /// The implementation of `RETR` command where `filename` is the name of the File
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// ```
    /// use ftp_rs::{FtpClient, Connection, FtpError};
    /// use tokio::io::{AsyncReadExt, BufStream};
    /// use std::io::Cursor;
    /// async {
    ///   let mut conn = FtpClient::connect("192.168.32.204:21").await.unwrap();
    ///   conn.login("Doe", "mumble").await.unwrap();
    ///   let mut reader = Cursor::new("hello, world!".as_bytes());
    ///   conn.put("retr.txt", &mut reader).await.unwrap();
    ///
    ///   async fn lambda(mut reader: BufStream<Connection>) -> Result<Vec<u8>, FtpError> {
    ///     let mut buffer = Vec::new();
    ///     reader
    ///         .read_to_end(&mut buffer)
    ///         .await
    ///         .map_err(FtpError::ConnectionError)?;
    ///     assert_eq!(buffer, "hello, world!".as_bytes());
    ///     Ok(buffer)
    ///   };
    ///
    ///   assert!(conn.retr("retr.txt", lambda).await.is_ok());
    ///   assert!(conn.rm("retr.txt").await.is_ok());
    /// };
    /// ```
    pub async fn retr<F, T, P, E>(&mut self, filename: &str, reader: F) -> std::result::Result<T, E>
    where
        F: Fn(BufStream<Connection>) -> P,
        P: std::future::Future<Output = std::result::Result<T, E>>,
        E: From<FtpError>,
    {
        let retr_command = format!("{} {}\r\n", cmd::Command::RETR.cmd_name(), filename);
        let data_stream = BufStream::new(self.data_command(&retr_command).await?);
        self.check_response_in(&[ftp_reply::ABOUT_TO_SEND, ftp_reply::ALREADY_OPEN])?;
        let res = reader(data_stream).await?;
        Ok(res)
    }

    /// Simple way to retr a File from the server. This stores the File in memory.
    ///
    /// ```
    /// use ftp_rs::{FtpClient, FtpError};
    /// use std::io::Cursor;
    /// async {
    ///     let mut conn = FtpClient::connect("192.168.32.204:21").await?;
    ///     conn.login("Doe", "mumble").await?;
    ///     let mut reader = Cursor::new("hello, world!".as_bytes());
    ///     conn.put("simple_retr.txt", &mut reader).await?;
    ///
    ///     let cursor = conn.simple_retr("simple_retr.txt").await?;
    ///
    ///     assert_eq!(cursor.into_inner(), "hello, world!".as_bytes());
    ///     assert!(conn.rm("simple_retr.txt").await.is_ok());
    ///
    ///     Ok::<(), FtpError>(())
    /// };
    /// ```
    pub async fn simple_retr(&mut self, file_name: &str) -> Result<std::io::Cursor<Vec<u8>>> {
        async fn do_read(mut reader: BufStream<Connection>) -> Result<Vec<u8>> {
            let mut buffer = Vec::new();
            reader
                .read_to_end(&mut buffer)
                .await
                .map_err(FtpError::ConnectionError)?;

            Ok(buffer)
        }

        let buffer = self.retr(file_name, do_read).await?;
        Ok(std::io::Cursor::new(buffer))
    }

    pub async fn remove_directory(&mut self, pathname: &str) -> Result<bool> {
        Ok(ftp_reply::is_positive_completion(self.rmd(pathname).await?))
    }

    /// Removes the remote pathname from the server.
    pub async fn rmd(&mut self, pathname: &str) -> Result<u32> {
        Ok(self.send_command(Command::RMD, Some(pathname)).await?)
    }

    pub async fn delete_file(&mut self, filename: &str) -> Result<bool> {
        Ok(ftp_reply::is_positive_completion(
            self.dele(filename).await?,
        ))
    }

    /// Remove the remote File from the server.
    pub async fn dele(&mut self, filename: &str) -> Result<u32> {
        Ok(self.send_command(Command::DELE, Some(filename)).await?)
    }

    async fn put_file<R: AsyncRead + Unpin>(&mut self, filename: &str, r: &mut R) -> Result<()> {
        let stor_command = format!("{} {}\r\n", Command::STOR, filename);
        let mut data_stream = BufStream::new(self.data_command(&stor_command).await?);
        self.check_response_in(&[ftp_reply::ALREADY_OPEN, ftp_reply::ABOUT_TO_SEND])?;
        copy(r, &mut data_stream)
            .await
            .map_err(FtpError::ConnectionError)?;
        Ok(())
    }

    /// Sends an FTP command to the server, waits for a reply and returns the numerical response code.
    pub async fn send_command(&mut self, cmd: cmd::Command, agrs: Option<&str>) -> Result<u32> {
        let mut ftp_cmd = format!("{}\r\n", cmd.cmd_name());
        if agrs.is_some() {
            ftp_cmd = format!("{} {}\r\n", cmd.cmd_name(), agrs.unwrap());
        }
        self.write_str(ftp_cmd).await?;
        self.read_reply().await?;
        Ok(self._reply_code)
    }

    async fn read_reply(&mut self) -> Result<()> {
        self._reply_lines.clear();
        self._reply_string = None;
        let mut line = String::new();
        self.stream
            .read_line(&mut line)
            .await
            .map_err(FtpError::ConnectionError)?;

        if line.len() < REPLY_CODE_LEN {
            return Err(FtpError::InvalidResponse(format!(
                "Truncated server reply: {}",
                line
            )));
        }

        if line.len() < 5 {
            return Err(FtpError::InvalidResponse(
                "error: could not read reply code".to_owned(),
            ));
        }

        let reply_code: u32 = line[0..3].parse().map_err(|_err| {
            FtpError::InvalidResponse(format!(
                "Could not parse reply code. \n Server Reply: {}",
                line
            ))
        })?;
        self._reply_code = reply_code;
        self._reply_lines.push(line.as_str().to_string());
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            if let Err(e) = self.stream.read_line(&mut line).await {
                return Err(FtpError::ConnectionError(e));
            }
            self._reply_lines.push(line.as_str().to_string());
        }
        let mut s = String::new();
        for x in self._reply_lines.iter() {
            s.push_str(x.as_str())
        }
        self._reply_string = Some(s);
        Ok(())
    }

    /// This stores a File on the server.
    pub async fn put<R: AsyncRead + Unpin>(&mut self, filename: &str, r: &mut R) -> Result<()> {
        self.put_file(filename, r).await?;
        self.check_response_in(&[
            ftp_reply::CLOSING_DATA_CONNECTION,
            ftp_reply::REQUESTED_FILE_ACTION_OK,
        ])?;
        Ok(())
    }

    /// Execute a command which returns list of strings in a separate stream
    async fn list_command(
        &mut self,
        cmd: Cow<'_, str>,
        open_code: u32,
        close_code: &[u32],
    ) -> Result<Vec<String>> {
        let data_stream = BufStream::new(self.data_command(&cmd).await?);
        self.check_response_in(&[open_code, ftp_reply::ALREADY_OPEN])?;
        let lines = Self::get_lines_from_stream(data_stream).await?;
        self.check_response_in(close_code)?;
        Ok(lines)
    }

    /// Consume a stream and return a vector of lines
    async fn get_lines_from_stream<R>(data_stream: R) -> Result<Vec<String>>
    where
        R: AsyncBufRead + Unpin,
    {
        let mut lines: Vec<String> = Vec::new();

        let mut lines_stream = data_stream.lines();
        loop {
            let line = lines_stream
                .next_line()
                .await
                .map_err(FtpError::ConnectionError)?;

            match line {
                Some(line) => {
                    if line.is_empty() {
                        continue;
                    }
                    lines.push(line);
                }
                None => break Ok(lines),
            }
        }
    }

    /// Execute `LIST` command which returns the detailed File listing in human readable format.
    /// If `pathname` is omited then the list of files in the current Directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn list(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("LIST\r\n".into(), |path| {
            format!("LIST {}\r\n", path).into()
        });

        self.list_command(
            command,
            ftp_reply::ABOUT_TO_SEND,
            &[
                ftp_reply::CLOSING_DATA_CONNECTION,
                ftp_reply::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// Execute `NLST` command which returns the list of File names only.
    /// If `pathname` is omited then the list of files in the current Directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn nlst(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("NLST\r\n".into(), |path| {
            format!("NLST {}\r\n", path).into()
        });

        self.list_command(
            command,
            ftp_reply::ABOUT_TO_SEND,
            &[
                ftp_reply::CLOSING_DATA_CONNECTION,
                ftp_reply::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// Retrieves the modification time of the File at `pathname` if it exists.
    /// In case the File does not exist `None` is returned.
    pub async fn mdtm(&mut self, pathname: &str) -> Result<Option<DateTime<Utc>>> {
        self.send_command(Command::MDTM, Some(pathname)).await?;
        self.check_response(ftp_reply::FILE)?;
        let reply_str = self._reply_string.clone().unwrap();
        let reply_str = reply_str.as_str();
        match MDTM_RE.captures(reply_str) {
            Some(caps) => {
                let (year, month, day) = (
                    caps[1].parse::<i32>().unwrap(),
                    caps[2].parse::<u32>().unwrap(),
                    caps[3].parse::<u32>().unwrap(),
                );
                let (hour, minute, second) = (
                    caps[4].parse::<u32>().unwrap(),
                    caps[5].parse::<u32>().unwrap(),
                    caps[6].parse::<u32>().unwrap(),
                );
                Ok(Some(
                    Utc.ymd(year, month, day).and_hms(hour, minute, second),
                ))
            }
            None => Ok(None),
        }
    }

    /// Retrieves the size of the File in bytes at `pathname` if it exists.
    /// In case the File does not exist `None` is returned.
    pub async fn size(&mut self, pathname: &str) -> Result<Option<usize>> {
        self.send_command(Command::SIZE, Some(pathname)).await?;
        self.check_response(ftp_reply::FILE)?;
        let reply_str = self._reply_string.clone().unwrap();
        let reply_str = reply_str.as_str();
        match SIZE_RE.captures(reply_str) {
            Some(caps) => Ok(Some(caps[1].parse().unwrap())),
            None => Ok(None),
        }
    }

    pub async fn feat(&mut self) -> Result<u32> {
        self._reply_lines.clear();
        Ok(self.send_command(Command::FEAT, None).await?)
    }

    pub async fn features(&mut self, cmd: Command) -> Result<Option<Vec<String>>> {
        let features = Vec::new();
        if self.init_feature_map().await? {
            let values = self.features_map.get(cmd.cmd_name());
            if values.is_some() {
                return Ok(Some(values.unwrap().clone()));
            }
        }
        Ok(Some(features))
    }

    async fn init_feature_map(&mut self) -> Result<bool> {
        if self.features_map.is_empty() {
            let reply_code = self.feat().await?;
            if reply_code == ftp_reply::NOT_LOGGED_IN.into() {
                return Ok(false);
            }
            let success = ftp_reply::is_positive_completion(reply_code);
            if !success {
                return Ok(false);
            }
            for l in self._reply_lines.iter() {
                if l.starts_with(" ") {
                    let mut key = "";
                    let mut value = "";
                    let s = &l[1..l.len() - 1];
                    let varsep = s.find(' ');
                    if varsep.is_some() {
                        key = &l[1..varsep.unwrap() + 1];
                        value = &l[varsep.unwrap() + 1..l.len()];
                    } else {
                        key = &l[1..l.len() - 1]
                    }
                    let entries = self.features_map.get_mut(key);
                    match entries {
                        None => {
                            let mut features = vec![];
                            features.push(String::from(value));
                            self.features_map.insert(key.to_string(), features);
                        }
                        Some(features) => {
                            features.push(value.to_string());
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    async fn write_str<S: AsRef<str>>(&mut self, command: S) -> Result<()> {
        let conn = self.stream.get_mut();
        conn.write_all(command.as_ref().as_bytes())
            .await
            .map_err(FtpError::ConnectionError)
    }

    pub fn check_response(&mut self, expected_code: u32) -> Result<()> {
        self.check_response_in(&[expected_code])
    }

    /// Retrieve single line response
    pub fn check_response_in(&mut self, expected_code: &[u32]) -> Result<()> {
        let reply_string = self._reply_string.clone();
        if expected_code.iter().any(|ec| self._reply_code == *ec) {
            Ok(())
        } else {
            Err(FtpError::InvalidResponse(format!(
                "Expected code {:?}, got response: {}",
                expected_code,
                reply_string.unwrap().as_str()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio_stream::once;
    use tokio_util::io::StreamReader;

    use super::FtpClient;

    #[tokio::test]
    async fn list_command_dos_newlines() {
        let data_stream = StreamReader::new(once(Ok::<_, std::io::Error>(
            b"Hello\r\nWorld\r\n\r\nBe\r\nHappy\r\n" as &[u8],
        )));

        assert_eq!(
            FtpClient::get_lines_from_stream(data_stream).await.unwrap(),
            ["Hello", "World", "Be", "Happy"]
                .iter()
                .map(<&str>::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn list_command_unix_newlines() {
        let data_stream = StreamReader::new(once(Ok::<_, std::io::Error>(
            b"Hello\nWorld\n\nBe\nHappy\n" as &[u8],
        )));

        assert_eq!(
            FtpClient::get_lines_from_stream(data_stream).await.unwrap(),
            ["Hello", "World", "Be", "Happy"]
                .iter()
                .map(<&str>::to_string)
                .collect::<Vec<_>>()
        );
    }
}
