//! cw-host's storage on rusqlite: one database per tenant and one for the host, objects as files.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use cw_host::sql::{Row, Store, StoreError, StoreResult, Value};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, OpenFlags, ToSql};

struct Param<'a>(&'a Value);

impl ToSql for Param<'_> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self.0 {
            Value::Null => ToSqlOutput::Borrowed(ValueRef::Null),
            Value::Int(v) => ToSqlOutput::Borrowed(ValueRef::Integer(*v)),
            Value::Text(t) => ToSqlOutput::Borrowed(ValueRef::Text(t.as_bytes())),
            Value::Blob(b) => ToSqlOutput::Borrowed(ValueRef::Blob(b)),
        })
    }
}

fn err(e: impl std::fmt::Display) -> StoreError {
    StoreError(e.to_string())
}

/// Opens a database with the pragmas every store uses. `create` allows a new file.
pub fn open(path: &Path, create: bool) -> rusqlite::Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags(path, flags)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA cache_size = -256; \
         PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = OFF;",
    )?;
    conn.set_prepared_statement_cache_capacity(64);
    Ok(conn)
}

pub struct Db<'a> {
    pub conn: &'a Connection,
    /// Where this tenant's objects live; `None` for the host store.
    pub objects: Option<PathBuf>,
}

impl Db<'_> {
    fn object_path(&self, name: &str) -> StoreResult<PathBuf> {
        let dir = self.objects.as_ref().ok_or_else(|| err("no object directory"))?;
        Ok(dir.join(name))
    }
}

impl Store for Db<'_> {
    fn exec(&mut self, sql: &str, params: &[Value]) -> StoreResult<Vec<Row>> {
        let mut stmt = self.conn.prepare_cached(sql).map_err(err)?;
        let columns = stmt.column_count();
        let params: Vec<Param> = params.iter().map(Param).collect();
        let mut rows = stmt.query(rusqlite::params_from_iter(params.iter())).map_err(err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(err)? {
            let mut values = Vec::with_capacity(columns);
            for i in 0..columns {
                values.push(match row.get_ref(i).map_err(err)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(v) => Value::Int(v),
                    ValueRef::Real(v) => Value::Int(v as i64),
                    ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => Value::Blob(b.to_vec()),
                });
            }
            out.push(values);
        }
        Ok(out)
    }

    fn blob_put(&mut self, name: &str, bytes: &[u8]) -> StoreResult<()> {
        let path = self.object_path(name)?;
        let dir = path.parent().ok_or_else(|| err("object path"))?;
        fs::create_dir_all(dir).map_err(err)?;
        let partial = dir.join(format!(".{name}.partial"));
        let mut file = fs::File::create(&partial).map_err(err)?;
        file.write_all(bytes).map_err(err)?;
        file.sync_all().map_err(err)?;
        fs::rename(&partial, &path).map_err(err)
    }

    fn blob_get(&mut self, name: &str) -> StoreResult<Option<Vec<u8>>> {
        match fs::read(self.object_path(name)?) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(err(e)),
        }
    }

    fn blob_delete(&mut self, name: &str) -> StoreResult<()> {
        match fs::remove_file(self.object_path(name)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(err(e)),
            _ => Ok(()),
        }
    }

    fn blob_clear(&mut self) -> StoreResult<()> {
        let dir = self.objects.as_ref().ok_or_else(|| err("no object directory"))?;
        match fs::remove_dir_all(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(err(e)),
            _ => Ok(()),
        }
    }
}

/// Runs `f` inside one transaction, committing when it says so. Each store has one connection, used by one
/// request at a time, so a deferred transaction never has to wait to upgrade to a write.
pub fn transaction<T>(conn: &Connection, f: impl FnOnce() -> (T, bool)) -> rusqlite::Result<T> {
    conn.execute_batch("BEGIN")?;
    let (value, commit) = f();
    conn.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })?;
    Ok(value)
}
