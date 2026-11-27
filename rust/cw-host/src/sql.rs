//! Synchronous SQL, the one storage interface: rusqlite natively, Durable Object SQL on Cloudflare.
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Int(v as i64)
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Int(v as i64)
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Value::Int(v as i64)
    }
}
impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::Blob(v.to_vec())
    }
}
impl<const N: usize> From<&[u8; N]> for Value {
    fn from(v: &[u8; N]) -> Self {
        Value::Blob(v.to_vec())
    }
}
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Blob(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_string())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Value::Null, Into::into)
    }
}

impl Value {
    pub fn int(&self) -> i64 {
        match self {
            Value::Int(v) => *v,
            _ => 0,
        }
    }
    pub fn u64(&self) -> u64 {
        self.int().max(0) as u64
    }
    pub fn blob(&self) -> Vec<u8> {
        match self {
            Value::Blob(v) => v.clone(),
            Value::Text(t) => t.as_bytes().to_vec(),
            _ => Vec::new(),
        }
    }
    pub fn opt_blob(&self) -> Option<Vec<u8>> {
        match self {
            Value::Null => None,
            v => Some(v.blob()),
        }
    }
    pub fn text(&self) -> String {
        match self {
            Value::Text(t) => t.clone(),
            Value::Blob(b) => String::from_utf8_lossy(b).into_owned(),
            Value::Int(v) => v.to_string(),
            Value::Null => String::new(),
        }
    }
    pub fn array<const N: usize>(&self) -> Option<[u8; N]> {
        match self {
            Value::Blob(v) => v.as_slice().try_into().ok(),
            _ => None,
        }
    }
}

pub type Row = Vec<Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// Rows of 1 MiB for objects kept in SQL.
pub const CHUNK: usize = 1024 * 1024;

/// One tenant's or the host's storage. Each request runs inside one transaction the runtime opens and
/// commits, or rolls back when the handler says so.
pub trait Store {
    fn exec(&mut self, sql: &str, params: &[Value]) -> StoreResult<Vec<Row>>;

    /// Object bytes. The default keeps them in SQL as 1 MiB rows (Cloudflare); `commonwire` keeps files.
    fn blob_put(&mut self, name: &str, bytes: &[u8]) -> StoreResult<()> {
        self.exec("DELETE FROM chunks WHERE name = ?1", &[name.into()])?;
        for (i, part) in bytes.chunks(CHUNK).enumerate() {
            self.exec(
                "INSERT INTO chunks (name, idx, data) VALUES (?1, ?2, ?3)",
                &[name.into(), i.into(), part.into()],
            )?;
        }
        Ok(())
    }
    fn blob_get(&mut self, name: &str) -> StoreResult<Option<Vec<u8>>> {
        let rows = self.exec("SELECT data FROM chunks WHERE name = ?1 ORDER BY idx", &[name.into()])?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(rows.iter().flat_map(|r| r[0].blob()).collect()))
    }
    fn blob_delete(&mut self, name: &str) -> StoreResult<()> {
        self.exec("DELETE FROM chunks WHERE name = ?1", &[name.into()]).map(|_| ())
    }
    fn blob_clear(&mut self) -> StoreResult<()> {
        self.exec("DELETE FROM chunks", &[]).map(|_| ())
    }
}
