use ftp_rs::{FtpError, FtpClient, cmd};
use std::io::Cursor;
use std::str;

async fn test_ftp(addr: &str, user: &str, pass: &str) -> Result<(), FtpError> {
    let mut ftp_client = FtpClient::connect((addr, 21)).await?;
    ftp_client.login(user, pass).await?;
    println!("current dir: {}", ftp_client.pwd().await?);

    // ftp_stream.make_directory("test_data").await?;

    ftp_client.cwd("RCX/03021008-RCX/A00").await?;

    println!("current dir: {}", ftp_client.pwd().await?);
    // An easy way to retrieve a File
    let cursor = ftp_client.simple_retr("03021008-RCX_A00(0000).txt").await?;
    let vec = cursor.into_inner();
    let text = str::from_utf8(&vec).unwrap();
    println!("got data: {}", text);

    // Store a File
    // let file_data = format!("Some awesome File data man!!");
    // let mut reader = Cursor::new(file_data.into_bytes());
    // ftp_stream.put("my_random_file.txt", &mut reader).await?;

    ftp_client.logout().await?;
    Ok(())
}

fn main() {
    let future = test_ftp("10.32.243.204", "mestest01", "T6g6bx&NAA");

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
        .unwrap();

    println!("test successful")
}
