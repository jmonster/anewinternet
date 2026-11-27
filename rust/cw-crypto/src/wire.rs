//! Every binary structure in docs/format.md, in TLS presentation language with QUIC varint vectors.
use tls_codec::{DeserializeBytes, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use crate::{Error, Result};

/// Encodes a structure.
pub fn encode<T: tls_codec::Serialize>(value: &T) -> Vec<u8> {
    value.tls_serialize_detached().expect("in-memory encoding")
}

/// Decodes a structure, refusing trailing bytes and anything over `limit` bytes.
pub fn decode<T: DeserializeBytes>(bytes: &[u8], limit: usize, what: &'static str) -> Result<T> {
    if bytes.len() > limit {
        return Err(Error::TooLarge(what));
    }
    T::tls_deserialize_exact_bytes(bytes).map_err(|_| Error::Malformed(what))
}

pub fn vl(bytes: impl Into<Vec<u8>>) -> VLBytes {
    VLBytes::new(bytes.into())
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Signed {
    pub kind: u16,
    pub body: VLBytes,
    pub signer: [u8; 32],
    pub signature: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct DeviceEntry {
    /// The device ID: the Ed25519 half of its public key.
    pub device: [u8; 32],
    /// The ML-DSA-44 half of its public key.
    pub signing_key: [u8; 1312],
    pub added_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct CardBody {
    /// The profile's public key, whose profile ID is the card's profile.
    pub profile_key: [u8; 1344],
    pub version: u64,
    pub issued_at: u64,
    pub devices: Vec<DeviceEntry>,
    /// X-Wing public keys.
    pub inbox_key: [u8; 1216],
    pub recovery_key: [u8; 1216],
    pub hosts: Vec<VLBytes>,
}

/// A device's own record of its seal key, which owner keys are sealed to.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct SealKeyBody {
    pub profile: [u8; 32],
    pub seal_key: [u8; 1216],
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct SocketAuth {
    pub token: VLBytes,
    pub device: [u8; 32],
    pub time: u64,
    pub nonce: [u8; 16],
    pub signature: VLBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Token {
    pub tenant: [u8; 16],
    pub epoch: u64,
    pub kind: u8,
    pub serial: u32,
    pub mac: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct ObjectRef {
    pub digest: [u8; 32],
    pub key: [u8; 32],
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct HeadBody {
    pub profile: [u8; 32],
    pub group: VLBytes,
    pub generation: u64,
    pub revision: u64,
    pub published_at: u64,
    pub nonce: [u8; 12],
    pub sealed: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct HeadAad {
    pub profile: [u8; 32],
    pub group: VLBytes,
    pub generation: u64,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct HeadSecret {
    pub manifest: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct KeyringBox {
    pub generation: u64,
    pub nonce: [u8; 12],
    pub sealed: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct KeyringHost {
    pub read_token: VLBytes,
    pub write_token: VLBytes,
    pub contact_token: VLBytes,
}

/// One entry per host in the card, in card order.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Keyring {
    pub hosts: Vec<KeyringHost>,
}

/// An owner key sealed to one device's seal key.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct DeviceSeal {
    pub device: [u8; 32],
    pub sealed: HpkeBox,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct OwnerKeyBody {
    pub generation: u32,
    /// An `HpkeBox` to the recovery key.
    pub recovery: VLBytes,
    pub devices: Vec<DeviceSeal>,
}

/// What an audience box holds for one friend (docs/format.md, "Audience boxes").
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct AudienceBoxBody {
    pub generation: u32,
    pub key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct LogEntryBody {
    pub seq: u64,
    pub previous: [u8; 32],
    pub generation: u32,
    pub nonce: [u8; 12],
    pub sealed: VLBytes,
}

/// A snapshot has the same shape as a log entry; its plaintext is an `ObjectRef`.
pub type SnapshotBody = LogEntryBody;

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct SealedBox {
    pub nonce: [u8; 12],
    pub sealed: VLBytes,
}

/// A locked browser's local key, sealed under a passkey's PRF output and under the profile seed (docs/format.md,
/// "Locked browsers").
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct LocalLock {
    pub passkey: SealedBox,
    pub recovery: SealedBox,
}

/// Where a locked browser keeps a record: the additional data of its seal after `label("local record")`.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct LocalPlace {
    pub store: VLBytes,
    pub key: VLBytes,
}

/// What an access box holds for whoever has its access secret (docs/format.md, "Groups").
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct AccessBody {
    pub group: [u8; 16],
    /// The generation of the first key.
    pub generation: u32,
    /// 32-byte group keys, newest generation first.
    pub keys: VLBytes,
    pub read_token: VLBytes,
    pub write_token: VLBytes,
    pub name: VLBytes,
    pub tenant: VLBytes,
    /// Empty, or a `HostingOffer`.
    pub offer: VLBytes,
}

/// `access/<lookup>` of a group: an `AccessBody` sealed under a key derived from the access secret.
pub type AccessBox = SealedBox;

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct ThreadEntryBody {
    pub author: [u8; 32],
    pub thread: [u8; 16],
    pub created_at: u64,
    pub card: VLBytes,
    pub entry: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct HpkeBox {
    pub enc: VLBytes,
    pub ciphertext: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InboxItemBody {
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub id: [u8; 16],
    pub created_at: u64,
    pub kind: u16,
    pub payload: VLBytes,
    /// The sender's device key records, when they changed since the sender last carried them to this recipient.
    pub keys: Vec<VLBytes>,
}

/// A device's own record of the inbox key it holds alone (docs/format.md, "Device inbox keys").
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct DeviceKeyBody {
    pub profile: [u8; 32],
    pub created_at: u64,
    pub key: [u8; 1216],
}

/// An inbox item key wrapped for one device key.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct DeviceWrap {
    pub device: [u8; 32],
    pub created_at: u64,
    pub wrap: HpkeBox,
}

/// An inbox item: the signed body under an item key, and the key wrapped for each recipient device.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InboxBox {
    pub ciphertext: VLBytes,
    pub wraps: Vec<DeviceWrap>,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Acceptance {
    pub invite: [u8; 16],
    pub proof: [u8; 32],
    pub card: VLBytes,
    pub name: VLBytes,
    /// The friendship secret the sender chose.
    pub friendship: [u8; 32],
    /// The sender's audience box for the recipient.
    pub audience_box: VLBytes,
    /// The sender's keyring.
    pub keyring: VLBytes,
    /// The sender's signed head, or empty, and manifest parts it names, each an object's ciphertext.
    pub head: VLBytes,
    pub objects: Vec<VLBytes>,
}

/// Inbox kind 11: a private question through a post's slot, from someone the recipient may hold no card for.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Question {
    pub card: VLBytes,
    /// JSON, as the product defines it.
    pub body: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Invitation {
    pub expires_at: u64,
    pub nonce1: [u8; 12],
    pub public: VLBytes,
    pub nonce2: [u8; 12],
    pub keys: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InvitePublic {
    pub card: VLBytes,
    pub name: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct HostingOffer {
    pub tenant_host: VLBytes,
    pub secret: [u8; 32],
    pub quota: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InviteKeys {
    pub generation: u32,
    pub audience_key: [u8; 32],
    /// The inviter's `KeyringBox` for `generation`.
    pub keyring: VLBytes,
    pub offer: VLBytes,
    /// The inviter's signed head for `generation`, or empty, and manifest parts it names, each an object's ciphertext.
    pub head: VLBytes,
    pub objects: Vec<VLBytes>,
    /// The inviter's device key records.
    pub keys: Vec<VLBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct LinkRequest {
    pub device: [u8; 32],
    /// The ML-DSA-44 half of the new device's public key.
    pub signing_key: [u8; 1312],
    pub name: VLBytes,
    pub proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct OwnerKey {
    pub generation: u32,
    pub key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct LinkReplyBody {
    pub card: VLBytes,
    pub owner_keys: Vec<OwnerKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct TransferGrantBody {
    pub tenant: [u8; 16],
    pub new_host: VLBytes,
    pub expires_at: u64,
}

/// One item of a host list: its position (sequence, generation, …) and bytes.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Entry {
    pub position: u64,
    pub bytes: VLBytes,
}

/// A host list response (docs/hosts.md).
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Entries {
    pub entries: Vec<Entry>,
}

impl Entries {
    pub fn push(&mut self, position: u64, bytes: impl Into<Vec<u8>>) {
        self.entries.push(Entry { position, bytes: vl(bytes) });
    }
}

/// An entry of a tenant's inbox (docs/hosts.md): an item someone posted, or a note the host made of a thread entry.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InboxEntry {
    pub kind: u8,
    pub body: VLBytes,
}

/// `InboxEntry.kind`: an `HpkeBox` posted to `POST /inbox`.
pub const INBOX_ITEM: u8 = 1;
/// `InboxEntry.kind`: a `ThreadNote`.
pub const INBOX_THREAD: u8 = 2;

/// A thread entry a friend wrote, as the host notes it in the thread owner's inbox.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct ThreadNote {
    pub thread: [u8; 16],
    pub seq: u64,
    pub entry: VLBytes,
}

/// One request of a `POST /batch` (docs/hosts.md): a tenant path, its `If-Match` and its body.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct BatchRequest {
    pub method: VLBytes,
    pub path: VLBytes,
    pub if_match: Option<u64>,
    pub body: VLBytes,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Batch {
    pub requests: Vec<BatchRequest>,
}

/// One answer of a `POST /batch`: its status, the `CW-Epoch`, `CW-Seq` or `CW-Current` it carried (0 for none), and
/// its body.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct BatchAnswer {
    pub status: u16,
    pub value: u64,
    pub body: VLBytes,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct BatchAnswers {
    pub answers: Vec<BatchAnswer>,
}

/// `PUT invites/<lookup>`.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InviteUpload {
    pub invitation: VLBytes,
    pub release: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct ThreadExport {
    pub thread: [u8; 16],
    pub entry: VLBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct InviteExport {
    pub lookup: [u8; 16],
    pub invitation: VLBytes,
    pub release: VLBytes,
}

/// Everything a host holds for a tenant except objects' bytes, for a transfer (docs/hosts.md).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct Export {
    pub card: VLBytes,
    pub head: VLBytes,
    pub log: Entries,
    pub snapshot: VLBytes,
    pub owner_keys: Entries,
    pub passkey: VLBytes,
    pub keyring: VLBytes,
    pub inbox: Entries,
    pub threads: Entries,
    pub invites: Entries,
    pub objects: Entries,
    /// The group token counter.
    pub group_counter: u64,
    /// Each device's newest inbox key record.
    pub device_keys: Entries,
}
