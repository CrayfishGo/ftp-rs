use std::fmt;
use std::fmt::Formatter;
use std::path::Display;

#[derive(Debug)]
pub enum Command {
    ABOR,
    ACCT,
    ALLO,
    APPE,
    CDUP,
    CWD,
    DELE,
    EPRT,
    EPSV,
    FEAT,
    HELP,
    LIST,
    MDTM,
    MFMT,
    MKD,
    MLSD,
    MLST,
    MODE,
    NLST,
    NOOP,
    PASS,
    PASV,
    PORT,
    PWD,
    QUIT,
    REIN,
    REST,
    RETR,
    RMD,
    RNFR,
    RNTO,
    SITE,
    SIZE,
    SMNT,
    STAT,
    STOR,
    STOU,
    STRU,
    SYST,
    TYPE,
    USER,

    #[cfg(feature = "ftps")]
    AUTH,

    #[cfg(feature = "ftps")]
    ADAT,

    #[cfg(feature = "ftps")]
    PROT,

    #[cfg(feature = "ftps")]
    PBSZ,

    #[cfg(feature = "ftps")]
    MIC,

    #[cfg(feature = "ftps")]
    CONF,

    #[cfg(feature = "ftps")]
    ENC,

    #[cfg(feature = "ftps")]
    CCC,
}

impl Command {
    /// Returns the command name
    pub(crate) fn cmd_name(&self) -> &str {
        match self {
            Command::ABOR => "ABOR",
            Command::ACCT => "ACCT",
            Command::ALLO => "ALLO",
            Command::APPE => "APPE",
            Command::CDUP => "CDUP",
            Command::CWD => "CWD",
            Command::DELE => "DELE",
            Command::EPRT => "EPRT",
            Command::EPSV => "EPSV",
            Command::FEAT => "FEAT",
            Command::HELP => "HELP",
            Command::LIST => "LIST",
            Command::MDTM => "MDTM",
            Command::MFMT => "MFMT",
            Command::MKD => "MKD",
            Command::MLSD => "MLSD",
            Command::MLST => "MLST",
            Command::MODE => "MODE",
            Command::NLST => "NLST",
            Command::NOOP => "NOOP",
            Command::PASS => "PASS",
            Command::PASV => "PASV",
            Command::PORT => "PORT",
            Command::PWD => "PWD",
            Command::QUIT => "QUIT",
            Command::REIN => "REIN",
            Command::REST => "REST",
            Command::RETR => "RETR",
            Command::RMD => "RMD",
            Command::RNTO => "RNTO",
            Command::SIZE => "SIZE",
            Command::SITE => "SITE",
            Command::SMNT => "SMNT",
            Command::STAT => "STAT",
            Command::STOR => "STOR",
            Command::STOU => "STOU",
            Command::STRU => "STRU",
            Command::SYST => "SYST",
            Command::TYPE => "TYPE",
            Command::USER => "USER",

            #[cfg(feature = "ftps")]
            Command::AUTH => "AUTH",
            #[cfg(feature = "ftps")]
            Command::ADAT => "ADAT",
            #[cfg(feature = "ftps")]
            Command::PROT => "PROT",
            #[cfg(feature = "ftps")]
            Command::PBSZ => "PBSZ",
            #[cfg(feature = "ftps")]
            Command::MIC => "MIC",
            #[cfg(feature = "ftps")]
            Command::CONF => "CONF",
            #[cfg(feature = "ftps")]
            Command::ENC => "ENC",
            #[cfg(feature = "ftps")]
            Command::CCC => "CCC",
            _ => { "Unknown" }
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cmd_name())
    }
}