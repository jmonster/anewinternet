//! The statements that create each store. Both runtimes run exactly these.

pub const HOST: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS host (id INTEGER PRIMARY KEY CHECK (id = 1), admin BLOB, claimed_at INTEGER)",
    "CREATE TABLE IF NOT EXISTS tenants (id BLOB PRIMARY KEY, created_at INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS offers (id BLOB PRIMARY KEY, quota INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS nonces (device BLOB NOT NULL, nonce BLOB NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (device, nonce)) WITHOUT ROWID",
    // The admin's settings; without a row, the defaults in lib.rs.
    "CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id = 1), guests INTEGER NOT NULL, guest_limit INTEGER NOT NULL, member_budget INTEGER NOT NULL, guest_budget INTEGER NOT NULL)",
    // Unused guest offers, each removed when it is used.
    "CREATE TABLE IF NOT EXISTS guest_offers (id BLOB PRIMARY KEY, sponsor BLOB NOT NULL, expires_at INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS guest_offers_sponsor ON guest_offers (sponsor)",
    // Guests not yet approved or removed, with when they joined.
    "CREATE TABLE IF NOT EXISTS guests (tenant BLOB PRIMARY KEY, sponsor BLOB NOT NULL, joined_at INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS guests_sponsor ON guests (sponsor)",
    // The admin offer each tenant was made with, which tells the admin's devices whose profile it is.
    "CREATE TABLE IF NOT EXISTS offered (tenant BLOB PRIMARY KEY, offer BLOB NOT NULL) WITHOUT ROWID",
    // How many tenants an offer makes; without a row, 1. `offers.used` counts the places taken.
    "CREATE TABLE IF NOT EXISTS offer_places (id BLOB PRIMARY KEY, places INTEGER NOT NULL) WITHOUT ROWID",
    // A row once the admin destroyed the host: every table above is empty and every host request answers 410.
    "CREATE TABLE IF NOT EXISTS destroyed (id INTEGER PRIMARY KEY CHECK (id = 1))",
];
/// The host tables that `DELETE /admin/host` empties.
pub const HOST_DATA: &[&str] =
    &["host", "tenants", "offers", "nonces", "settings", "guest_offers", "guests", "offered", "offer_places"];

pub const TENANT: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS tenant (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        tenant BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        quota INTEGER NOT NULL,
        used INTEGER NOT NULL,
        state INTEGER NOT NULL,
        notice_until INTEGER NOT NULL,
        removed_at INTEGER NOT NULL,
        audience_counter INTEGER NOT NULL,
        requests_day INTEGER NOT NULL,
        requests INTEGER NOT NULL,
        last_write INTEGER NOT NULL,
        card BLOB NOT NULL,
        head BLOB,
        head_revision INTEGER NOT NULL,
        snapshot BLOB,
        snapshot_seq INTEGER NOT NULL,
        passkey BLOB,
        keyring BLOB,
        inbox_seq INTEGER NOT NULL,
        inbox_count INTEGER NOT NULL,
        inbox_bytes INTEGER NOT NULL,
        log_next INTEGER NOT NULL,
        log_tail BLOB NOT NULL,
        last_maintenance INTEGER NOT NULL
    )",
    // What the host's settings give this tenant: whether members may make guest offers, and the daily budget.
    "CREATE TABLE IF NOT EXISTS limits (id INTEGER PRIMARY KEY CHECK (id = 1), guests INTEGER NOT NULL, budget INTEGER NOT NULL)",
    // The contact token counter; without a row, 0.
    "CREATE TABLE IF NOT EXISTS contact (id INTEGER PRIMARY KEY CHECK (id = 1), counter INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS keyring_revision (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL)",
    // The group token counter; without a row, 0.
    "CREATE TABLE IF NOT EXISTS group_tokens (id INTEGER PRIMARY KEY CHECK (id = 1), counter INTEGER NOT NULL)",
    // The admin's daily budget for this tenant, which wins over the host setting in `limits`; without a row, none.
    "CREATE TABLE IF NOT EXISTS budget_override (id INTEGER PRIMARY KEY CHECK (id = 1), budget INTEGER NOT NULL)",
    // Access boxes and audience boxes, by lookup.
    "CREATE TABLE IF NOT EXISTS access (lookup BLOB PRIMARY KEY, bytes BLOB NOT NULL) WITHOUT ROWID",
    // Open slots, each with the inbox items it brought that are still in the inbox.
    "CREATE TABLE IF NOT EXISTS slots (slot INTEGER PRIMARY KEY, opened_at INTEGER NOT NULL, unread INTEGER NOT NULL)",
    // The next slot number; without a row, 1. Slot numbers are never reused.
    "CREATE TABLE IF NOT EXISTS slot_next (id INTEGER PRIMARY KEY CHECK (id = 1), next INTEGER NOT NULL)",
    // Inbox items that came through a slot, open or since closed, until they leave the inbox.
    "CREATE TABLE IF NOT EXISTS slot_items (seq INTEGER PRIMARY KEY, slot INTEGER NOT NULL, size INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS objects (name TEXT PRIMARY KEY, size INTEGER NOT NULL, created_at INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS chunks (name TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (name, idx)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS log (seq INTEGER PRIMARY KEY, bytes BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS owner_keys (generation INTEGER PRIMARY KEY, bytes BLOB NOT NULL)",
    // Each device's newest inbox key record (docs/format.md, Device inbox keys).
    "CREATE TABLE IF NOT EXISTS device_keys (device BLOB PRIMARY KEY, created_at INTEGER NOT NULL, bytes BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS inbox (seq INTEGER PRIMARY KEY, bytes BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS thread_heads (thread BLOB PRIMARY KEY, next INTEGER NOT NULL, count INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS threads (thread BLOB NOT NULL, seq INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY (thread, seq)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS invites (lookup BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, release BLOB, bytes BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS links (lookup BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, bytes BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS subscriptions (device BLOB PRIMARY KEY, endpoint TEXT NOT NULL, last_push INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS nonces (device BLOB NOT NULL, nonce BLOB NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (device, nonce)) WITHOUT ROWID",
    // The UTC day, as days since the epoch, each device in the card last opened a push socket.
    "CREATE TABLE IF NOT EXISTS seen (device BLOB PRIMARY KEY, day INTEGER NOT NULL) WITHOUT ROWID",
];

/// Tables whose rows a removal deletes; the tenant row stays for the forwarding card.
pub const TENANT_DATA: &[&str] = &[
    "objects",
    "chunks",
    "log",
    "owner_keys",
    "device_keys",
    "inbox",
    "thread_heads",
    "threads",
    "invites",
    "links",
    "subscriptions",
    "nonces",
    "seen",
    "contact",
    "group_tokens",
    "budget_override",
    "access",
    "slots",
    "slot_next",
    "slot_items",
];

pub fn create(store: &mut impl crate::Store, statements: &[&str]) -> crate::sql::StoreResult<()> {
    for s in statements {
        store.exec(s, &[])?;
    }
    Ok(())
}
