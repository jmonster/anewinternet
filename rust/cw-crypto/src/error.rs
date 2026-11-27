use core::fmt;

/// Why an input was refused. Every refusal names one of these; none carries secret data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Bytes or text that don't decode as the format requires.
    Malformed(&'static str),
    /// A size or count limit from the format's table.
    TooLarge(&'static str),
    /// A signature that doesn't verify.
    BadSignature,
    /// A valid signature by a key that isn't allowed to sign this.
    WrongSigner,
    /// Authenticated decryption failed, or padding was wrong.
    Decrypt,
    /// A version, revision or sequence lower than one already seen.
    Rollback,
    /// An item or nonce that was already processed.
    Replay,
    /// Sealed under a key generation the reader doesn't hold, or of another generation than the one asked for.
    WrongGeneration,
    /// Outside its allowed time window.
    Expired,
    /// A digest that doesn't match the bytes.
    Digest,
    /// The recipient has no device key that hasn't expired, so nothing can be sealed to them now.
    NoDeviceKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed: {what}"),
            Error::TooLarge(what) => write!(f, "too large: {what}"),
            Error::BadSignature => f.write_str("bad signature"),
            Error::WrongSigner => f.write_str("wrong signer"),
            Error::Decrypt => f.write_str("decryption failed"),
            Error::Rollback => f.write_str("rollback"),
            Error::Replay => f.write_str("replay"),
            Error::WrongGeneration => f.write_str("wrong generation"),
            Error::Expired => f.write_str("expired"),
            Error::Digest => f.write_str("digest mismatch"),
            Error::NoDeviceKey => f.write_str("no device key"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// A stable code for JavaScript callers and test vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "malformed",
            Error::TooLarge(_) => "too-large",
            Error::BadSignature => "bad-signature",
            Error::WrongSigner => "wrong-signer",
            Error::Decrypt => "decrypt",
            Error::Rollback => "rollback",
            Error::Replay => "replay",
            Error::WrongGeneration => "wrong-generation",
            Error::Expired => "expired",
            Error::Digest => "digest",
            Error::NoDeviceKey => "no-device-key",
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
