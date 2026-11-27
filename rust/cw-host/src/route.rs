//! Method and path to route, and each route's request class (docs/hosts.md).
use cw_crypto::b64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Open,
    Signed,
    Read,
    Write,
    Owner,
    Grant,
    Admin,
    Claim,
    Offer,
    /// `GET /push`: owner, authenticated by `SocketAuth`.
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRoute {
    Claim,
    PushKey,
    OfferTenant,
    CreateTenant,
    ListTenants,
    Quota([u8; 16]),
    Notice([u8; 16]),
    Remove([u8; 16]),
    Approve([u8; 16]),
    CreateOffer,
    WithdrawOffer([u8; 16]),
    Budget([u8; 16]),
    GetSettings,
    PutSettings,
    /// `DELETE /admin/host`: deletes every tenant and the host's own state, for good.
    Destroy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRoute {
    GetCard,
    PutCard,
    Tokens,
    RotateContact,
    /// `POST /tokens/audience?to=<n>`: the audience counter's advance.
    AudienceTokens,
    /// `POST /tokens/group`: a group's read and write tokens, and with `to` the counter's advance.
    GroupTokens,
    Status,
    Remove,
    PutKeyring,
    GetKeyring,
    GetHead,
    PutHead,
    ListObjects,
    PutObject(String),
    GetObject(String),
    DeleteObject(String),
    PostLog,
    GetLog,
    PutSnapshot,
    GetSnapshot,
    PutOwnerKey,
    GetOwnerKeys,
    DeleteOwnerKey(u64),
    PutDeviceKey,
    GetDeviceKeys,
    PutPasskey,
    GetPasskey,
    PostInbox,
    GetInbox,
    DeleteInbox,
    PostThread([u8; 16]),
    GetThread([u8; 16]),
    DeleteThreadEntry([u8; 16], u64),
    DeleteThread([u8; 16]),
    /// An empty thread a group write token may append to.
    OpenThread([u8; 16]),
    PutAccess([u8; 16]),
    GetAccess([u8; 16]),
    DeleteAccess([u8; 16]),
    OpenSlot,
    ListSlots,
    CloseSlot(u64),
    PutInvite([u8; 16]),
    GetInvite([u8; 16]),
    RedeemInvite([u8; 16]),
    DeleteInvite([u8; 16]),
    PutLink([u8; 16]),
    GetLink([u8; 16]),
    PostGuest,
    DeleteGuest([u8; 16]),
    PutSubscription,
    DeleteSubscription,
    Socket,
    Export,
    Import,
    Restore,
    /// `POST /batch`: several requests to the tenant in one transaction.
    Batch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Host(HostRoute),
    Tenant([u8; 16], TenantRoute),
}

fn id(text: &str) -> Option<[u8; 16]> {
    (text.len() == 22).then(|| b64::decode_array::<16>(text).ok()).flatten()
}

fn object(text: &str) -> Option<String> {
    cw_crypto::object::parse_name(text).ok().map(|_| text.to_string())
}

fn number(text: &str) -> Option<u64> {
    (!text.is_empty() && text.len() <= 19 && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok())?
}

pub fn route(method: &str, path: &str) -> Option<Route> {
    let parts: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    use HostRoute as H;
    use TenantRoute as T;
    let host = |r| Some(Route::Host(r));
    match (method, parts.as_slice()) {
        ("POST", ["claim"]) => host(H::Claim),
        ("GET", ["push", "key"]) => host(H::PushKey),
        ("POST", ["tenants"]) => host(H::OfferTenant),
        ("POST", ["admin", "tenants"]) => host(H::CreateTenant),
        ("GET", ["admin", "tenants"]) => host(H::ListTenants),
        ("PUT", ["admin", "tenants", t, "quota"]) => host(H::Quota(id(t)?)),
        ("POST", ["admin", "tenants", t, "notice"]) => host(H::Notice(id(t)?)),
        ("DELETE", ["admin", "tenants", t]) => host(H::Remove(id(t)?)),
        ("POST", ["admin", "tenants", t, "approve"]) => host(H::Approve(id(t)?)),
        ("POST", ["admin", "offers"]) => host(H::CreateOffer),
        ("DELETE", ["admin", "offers", o]) => host(H::WithdrawOffer(id(o)?)),
        ("PUT", ["admin", "tenants", t, "budget"]) => host(H::Budget(id(t)?)),
        ("GET", ["admin", "settings"]) => host(H::GetSettings),
        ("PUT", ["admin", "settings"]) => host(H::PutSettings),
        ("DELETE", ["admin", "host"]) => host(H::Destroy),
        (_, ["t", t, rest @ ..]) => {
            let tenant = id(t)?;
            let r = match (method, rest) {
                ("DELETE", []) => T::Remove,
                ("GET", ["card"]) => T::GetCard,
                ("PUT", ["card"]) => T::PutCard,
                ("POST", ["tokens"]) => T::Tokens,
                ("POST", ["tokens", "contact"]) => T::RotateContact,
                ("POST", ["tokens", "audience"]) => T::AudienceTokens,
                ("POST", ["tokens", "group"]) => T::GroupTokens,
                ("GET", ["status"]) => T::Status,
                ("PUT", ["keyring"]) => T::PutKeyring,
                ("GET", ["keyring"]) => T::GetKeyring,
                ("GET", ["head"]) => T::GetHead,
                ("PUT", ["head"]) => T::PutHead,
                ("GET", ["objects"]) => T::ListObjects,
                ("PUT", ["objects", n]) => T::PutObject(object(n)?),
                ("GET", ["objects", n]) => T::GetObject(object(n)?),
                ("DELETE", ["objects", n]) => T::DeleteObject(object(n)?),
                ("POST", ["log"]) => T::PostLog,
                ("GET", ["log"]) => T::GetLog,
                ("PUT", ["snapshot"]) => T::PutSnapshot,
                ("GET", ["snapshot"]) => T::GetSnapshot,
                ("PUT", ["ownerkeys"]) => T::PutOwnerKey,
                ("GET", ["ownerkeys"]) => T::GetOwnerKeys,
                ("DELETE", ["ownerkeys", g]) => T::DeleteOwnerKey(number(g)?),
                ("PUT", ["devicekeys"]) => T::PutDeviceKey,
                ("GET", ["devicekeys"]) => T::GetDeviceKeys,
                ("PUT", ["recovery", "passkey"]) => T::PutPasskey,
                ("GET", ["recovery", "passkey"]) => T::GetPasskey,
                ("POST", ["inbox"]) => T::PostInbox,
                ("GET", ["inbox"]) => T::GetInbox,
                ("DELETE", ["inbox"]) => T::DeleteInbox,
                ("POST", ["threads", th]) => T::PostThread(id(th)?),
                ("GET", ["threads", th]) => T::GetThread(id(th)?),
                ("DELETE", ["threads", th, seq]) => T::DeleteThreadEntry(id(th)?, number(seq)?),
                ("DELETE", ["threads", th]) => T::DeleteThread(id(th)?),
                ("PUT", ["threads", th]) => T::OpenThread(id(th)?),
                ("PUT", ["access", l]) => T::PutAccess(id(l)?),
                ("GET", ["access", l]) => T::GetAccess(id(l)?),
                ("DELETE", ["access", l]) => T::DeleteAccess(id(l)?),
                ("POST", ["slots"]) => T::OpenSlot,
                ("GET", ["slots"]) => T::ListSlots,
                ("DELETE", ["slots", n]) => T::CloseSlot(number(n)?),
                ("PUT", ["invites", l]) => T::PutInvite(id(l)?),
                ("GET", ["invites", l]) => T::GetInvite(id(l)?),
                ("POST", ["invites", l, "redeem"]) => T::RedeemInvite(id(l)?),
                ("DELETE", ["invites", l]) => T::DeleteInvite(id(l)?),
                ("PUT", ["links", l]) => T::PutLink(id(l)?),
                ("GET", ["links", l]) => T::GetLink(id(l)?),
                ("POST", ["guests"]) => T::PostGuest,
                ("DELETE", ["guests", o]) => T::DeleteGuest(id(o)?),
                ("PUT", ["push", "subscription"]) => T::PutSubscription,
                ("DELETE", ["push", "subscription"]) => T::DeleteSubscription,
                ("GET", ["push"]) => T::Socket,
                ("GET", ["export"]) => T::Export,
                ("POST", ["import"]) => T::Import,
                ("POST", ["restore"]) => T::Restore,
                ("POST", ["batch"]) => T::Batch,
                _ => return None,
            };
            Some(Route::Tenant(tenant, r))
        }
        _ => None,
    }
}

pub fn class(route: &Route) -> Class {
    use HostRoute as H;
    use TenantRoute as T;
    match route {
        Route::Host(H::Claim) => Class::Claim,
        Route::Host(H::PushKey) => Class::Open,
        Route::Host(H::OfferTenant) => Class::Offer,
        Route::Host(_) => Class::Admin,
        Route::Tenant(_, r) => match r {
            T::GetCard
            | T::GetKeyring
            | T::GetPasskey
            | T::GetInvite(_)
            | T::RedeemInvite(_)
            | T::GetLink(_)
            | T::GetAccess(_)
            | T::GetDeviceKeys => Class::Open,
            T::PutCard | T::Tokens => Class::Signed,
            T::GetHead | T::GetObject(_) | T::GetThread(_) => Class::Read,
            T::PostInbox | T::PostThread(_) => Class::Write,
            T::Export => Class::Grant,
            T::Socket => Class::Socket,
            _ => Class::Owner,
        },
    }
}
