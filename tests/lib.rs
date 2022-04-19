use async_ftp::{FtpError, FtpClient};
#[cfg(test)]
use std::io::Cursor;

#[test]
fn test_ftp() {
    let future = async {
        let mut ftp_client = FtpClient::connect("192.168.1.60:21").await?;
        let _ = ftp_client.login("Doe", "mumble").await?;

        ftp_client.mkd("test_dir").await?;
        ftp_client.cwd("test_dir").await?;
        assert!(ftp_client.pwd().await?.ends_with("/test_dir"));

        // store a file
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        ftp_client.put("test_file.txt", &mut reader).await?;

        // retrieve file
        ftp_client
            .simple_retr("test_file.txt")
            .await
            .map(|bytes| assert_eq!(bytes.into_inner(), file_data.as_bytes()))?;

        // remove file
        ftp_client.rm("test_file.txt").await?;

        // cleanup: go up, remove folder, and quit
        ftp_client.cdup().await?;

        ftp_client.rmd("test_dir").await?;
        ftp_client.quit().await?;

        Ok(())
    };

    let result: Result<(), FtpError> = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);

    result.unwrap();
}
