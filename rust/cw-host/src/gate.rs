//! Checks every request needs before storage is touched: route, tenant ID MAC, token MAC, claim and offer
//! secrets. The Worker runs it before calling a Durable Object; `commonwire` before opening a database.
use cw_crypto::b64;
use cw_crypto::token::{self, Checked, TokenKind};

use crate::http::{preflight, Request, Response};
use crate::limit;
use crate::route::{class, route, Class, Route};
use crate::Config;

#[derive(Debug, Clone)]
pub struct Gated {
    pub route: Route,
    pub class: Class,
    pub token: Option<Checked>,
}

impl Gated {
    /// The per-IP limit that applies, as the window's ID and its requests per minute.
    pub fn ip_limit(&self) -> Option<(u8, u32)> {
        match self.token.map(|t| t.kind) {
            Some(TokenKind::GroupRead) => Some((1, limit::GROUP_READ_PER_IP)),
            Some(TokenKind::GroupWrite) => Some((2, limit::GROUP_WRITE_PER_IP)),
            Some(TokenKind::Slot) => Some((3, limit::SLOT_PER_IP)),
            _ if matches!(self.class, Class::Open | Class::Signed | Class::Grant | Class::Offer) => {
                Some((0, limit::PER_IP))
            }
            _ => None,
        }
    }
    /// The tenant the request is for.
    pub fn tenant(&self) -> Option<[u8; 16]> {
        match self.route {
            Route::Tenant(t, _) => Some(t),
            Route::Host(_) => None,
        }
    }
}

/// The token text of a request: `Authorization: CW <token>`, or `t=` on `GET` and `POST`.
pub fn token_text(req: &Request) -> Option<String> {
    if let Some(v) = req.header("authorization") {
        return v.strip_prefix("CW ").map(str::to_string);
    }
    if matches!(req.method.as_str(), "GET" | "POST" | "HEAD") {
        return req.query("t").map(str::to_string);
    }
    None
}

/// The `cw1.` subprotocol of a socket request.
pub fn socket_protocol(req: &Request) -> Option<String> {
    req.header("sec-websocket-protocol")?.split(',').map(str::trim).find(|p| p.starts_with("cw1.")).map(str::to_string)
}

pub fn gate(config: &Config, req: &Request) -> Result<Gated, Response> {
    if req.method == "OPTIONS" {
        return Err(preflight());
    }
    let method = if req.method == "HEAD" { "GET" } else { req.method.as_str() };
    let route = route(method, req.path()).ok_or_else(|| Response::error(404, "not-found"))?;
    let mut class = class(&route);
    if matches!(route, Route::Tenant(_, crate::route::TenantRoute::GetObject(_))) && req.header("cw-grant").is_some() {
        class = Class::Grant;
    }
    if let Route::Tenant(t, _) = &route {
        if !token::check_tenant(&config.secret, t) {
            return Err(Response::error(404, "not-found"));
        }
    }
    let unauthorized = || Response::error(401, "unauthorized");
    let checked = |text: Option<String>, kinds: &[TokenKind]| -> Result<Checked, Response> {
        let c = token::check(&config.secret, &text.ok_or_else(unauthorized)?).map_err(|_| unauthorized())?;
        let tenant_ok = match &route {
            Route::Tenant(t, _) => &c.tenant == t,
            Route::Host(_) => c.tenant == token::ADMIN_TENANT,
        };
        if !tenant_ok || !kinds.contains(&c.kind) {
            return Err(unauthorized());
        }
        Ok(c)
    };
    use crate::route::TenantRoute as T;
    let tenant_route = match &route {
        Route::Tenant(_, r) => Some(r),
        Route::Host(_) => None,
    };
    // Contact tokens read objects and post inbox items; group read tokens read the head, threads and objects;
    // group write tokens append to threads and put objects; slot tokens post inbox items. Nothing else.
    let mut kinds: Vec<TokenKind> = match class {
        Class::Read => vec![TokenKind::Read, TokenKind::Owner],
        Class::Write => vec![TokenKind::Write, TokenKind::Owner],
        _ => vec![TokenKind::Owner],
    };
    match tenant_route {
        Some(T::GetObject(_)) => kinds.extend([TokenKind::Contact, TokenKind::GroupRead]),
        Some(T::GetHead | T::GetThread(_)) => kinds.push(TokenKind::GroupRead),
        Some(T::PostInbox) => kinds.extend([TokenKind::Contact, TokenKind::Slot]),
        Some(T::PostThread(_)) => kinds.push(TokenKind::GroupWrite),
        Some(T::PutObject(_)) => kinds.push(TokenKind::GroupWrite),
        _ => {}
    }
    let token = match class {
        Class::Open | Class::Signed | Class::Grant => None,
        Class::Read | Class::Write | Class::Owner => Some(checked(token_text(req), &kinds)?),
        Class::Admin => Some(checked(token_text(req), &[TokenKind::Admin])?),
        Class::Socket => {
            let protocol = socket_protocol(req).ok_or_else(unauthorized)?;
            let auth: cw_crypto::wire::SocketAuth = protocol
                .strip_prefix("cw1.")
                .and_then(|t| b64::decode(t).ok())
                .and_then(|b| cw_crypto::wire::decode(&b, cw_crypto::request::SOCKET_AUTH_LIMIT, "socket auth").ok())
                .ok_or_else(unauthorized)?;
            let text = String::from_utf8(auth.token.as_slice().to_vec()).map_err(|_| unauthorized())?;
            Some(checked(Some(text), &[TokenKind::Owner])?)
        }
        Class::Claim => {
            let claim =
                req.header("cw-claim").and_then(|v| b64::decode_array::<32>(v).ok()).ok_or_else(unauthorized)?;
            if !token::check_claim(&config.claim, &claim) {
                return Err(unauthorized());
            }
            None
        }
        Class::Offer => {
            let offer =
                req.header("cw-offer").and_then(|v| b64::decode_array::<32>(v).ok()).ok_or_else(unauthorized)?;
            token::check_offer(&config.secret, &offer).map_err(|_| unauthorized())?;
            None
        }
    };
    Ok(Gated { route, class, token })
}
