# ============================================================
# api/index.py  —  ICF Anime Firebase Gateway (FastAPI / Vercel)
# ============================================================
# Converted from Supabase Edge Function (TypeScript/Deno) to
# Production-Ready Python FastAPI for Vercel Serverless.
#
# Secrets required (set in Vercel Dashboard → Settings → Environment Variables):
#   FIREBASE_SERVICE_ACCOUNT_JSON  — raw service-account JSON string
#   FIREBASE_CLIENT_CONFIG_JSON    — raw web-app client config JSON string
#   OWNER_GMAIL                    — owner gmail(s), comma-separated
#   APP_SECRET_KEY                 — Android HMAC secret (optional)
#   ALLOWED_DOMAINS                — override allowed origins (optional)
#   ALLOW_LOCAL_DEV                — "true" to allow localhost (optional)
#
# SECURITY MODEL (identical to the original TypeScript implementation):
#   * GET / browser visit            -> 404 "Not Found"
#   * { action: "boot" }             -> { token, uid, e }
#   * { action: "session" }          -> { token, uid }
#   * { action: "cfg", token }       -> { e: "<base64 AES-GCM blob>" }
#   * { action: "adminStatus" }      -> { exists }
#   * { action: "adminGoogle", idToken } -> { gid, email, isOwner, pinExists }
#   * { action: "adminPin", gid, pin }   -> { sid, email, isOwner }
#   * { action: "adminSetPin", sid|gid, code, enabled } -> { ok }
#   * { action: "adminOwners", sid }     -> { owners: [...] }
#   * { action: "adminManage", sid, op, email|sessionId } -> { ok }
#   * { action: "adminDb", sid, op, path, value }   -> { data }
#   * { action: "authDelete" | "authWipeAll" }
#   * { action: "clientAuth" }       -> { cid, uid, exp }
#   * { action: "db", cid, ... }     -> { data }
#   * { action: "dlMeta", cid, urls } -> { meta }
#   * { action: "dlSign", cid, url } -> { blob, expires }
# ============================================================

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

# ╔════════════════════════════════════════════════════════════════════╗
# ║  ⚙️  SITE CONFIG BLOCK  (override via environment variables)        ║
# ╚════════════════════════════════════════════════════════════════════╝
CONFIG = {
    # "*" = সব domain allowed (testing mode)
    # পরে secure করতে চাইলে এখানে specific domain list দাও
    "ALLOWED_DOMAINS": ["*"],
    "OWNER_GMAIL": [
        "tamimlegendaryboy@gmail.com",
    ],
    "APP_SECRET_KEY": "",
}

# ============================================================
# TIMING CONSTANTS
# ============================================================
TOKEN_TTL_SECONDS = 15 * 60        # 15 min — Firebase custom token lifetime
CFG_PROOF_WINDOW  = 15 * 60        # 15 min — token age window for /cfg
ADMIN_SID_TTL     = 12 * 60 * 60   # 12 h  — admin session lifetime
CLIENT_TTL        = 15 * 60        # 15 min — client ticket lifetime
GOOGLE_TICKET_TTL = 30 * 60        # 30 min — Google OAuth intermediate ticket

# ============================================================
# ENVIRONMENT HELPERS
# ============================================================
def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# ============================================================
# SERVICE-ACCOUNT / CLIENT-CONFIG CACHE
# ============================================================
_sa_raw: str = ""
_sa: Optional[Dict] = None
_cc_raw: str = ""
_cc: Optional[Dict] = None


def service_account() -> Dict:
    global _sa_raw, _sa
    raw = _env("FIREBASE_SERVICE_ACCOUNT_JSON")
    if not raw:
        raise PermissionError("unauthorized")
    if _sa is None or _sa_raw != raw:
        # Vercel sometimes wraps value in extra quotes — strip them
        raw2 = raw.strip().lstrip('"').rstrip('"').lstrip("'").rstrip("'")
        try:
            _sa = json.loads(raw2)
        except Exception:
            _sa = json.loads(raw)
        _sa_raw = raw
    return _sa


def client_config() -> Dict:
    global _cc_raw, _cc
    raw = _env("FIREBASE_CLIENT_CONFIG_JSON")
    if not raw:
        raise PermissionError("unauthorized")
    if _cc is None or _cc_raw != raw:
        raw2 = raw.strip().lstrip('"').rstrip('"').lstrip("'").rstrip("'")
        try:
            _cc = json.loads(raw2)
        except Exception:
            _cc = json.loads(raw)
        _cc_raw = raw
    return _cc


# ============================================================
# PRIVATE-KEY CACHE  (RSA key parsed once per warm instance)
# ============================================================
_pk_pem: str = ""
_pk = None


def _load_private_key(pem: str):
    global _pk_pem, _pk
    if _pk is None or _pk_pem != pem:
        clean = pem.replace("\\n", "\n").encode()
        _pk = serialization.load_pem_private_key(clean, password=None)
        _pk_pem = pem
    return _pk


def private_key():
    return _load_private_key(service_account()["private_key"])


# ============================================================
# CORS / ORIGIN SECURITY
# ============================================================
def _allowed_origins() -> List[str]:
    env_val = _env("ALLOWED_DOMAINS")
    if env_val:
        raw_list = re.split(r"[,;\s]+", env_val)
    else:
        raw_list = CONFIG["ALLOWED_DOMAINS"]
    return [d.strip().rstrip("/").lower() for d in raw_list if d.strip()]


def _origin_allowed(origin: str) -> bool:
    o = str(origin or "").strip().rstrip("/").lower()
    if not o:
        return False
    entries = _allowed_origins()
    if "*" in entries:
        return True
    if o in entries:
        return True
    for entry in entries:
        if "*" not in entry:
            continue
        pattern = "^" + re.escape(entry).replace(r"\*", "[a-z0-9-]*") + "$"
        if re.match(pattern, o):
            return True
    if _env("ALLOW_LOCAL_DEV") == "true" and re.match(
        r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", o
    ):
        return True
    return False


def _cors_headers(origin: str) -> Dict[str, str]:
    entries = _allowed_origins()
    if "*" in entries:
        allowed_origin = "*"
    else:
        allowed_origin = str(origin).rstrip("/") if _origin_allowed(origin) else "null"
    return {
        "Access-Control-Allow-Origin": allowed_origin,
        "Access-Control-Allow-Headers": (
            "authorization, x-client-info, apikey, content-type, "
            "x-app-timestamp, x-app-signature"
        ),
        "Access-Control-Allow-Methods": "POST, OPTIONS",
    }


def _secure_equal(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac_module.compare_digest(a.encode(), b.encode())


async def _verify_app_hmac(request: Request, raw_body: str) -> bool:
    secret = _env("APP_SECRET_KEY") or CONFIG.get("APP_SECRET_KEY", "")
    timestamp = request.headers.get("x-app-timestamp", "")
    sent = request.headers.get("x-app-signature", "")
    if not secret or not timestamp or not sent:
        return False
    try:
        ms = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() * 1000 - ms) > 5 * 60 * 1000:
        return False
    if not re.match(r"^[a-f0-9]{64}$", sent, re.IGNORECASE):
        return False
    expected = hmac_module.new(
        secret.encode(),
        f"{timestamp}.{raw_body}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return _secure_equal(expected, sent.lower())


async def _guard_request(request: Request, raw_body: str) -> Optional[str]:
    """
    Open mode: সব origin allow।
    শুধু browser navigate block।
    """
    if request.headers.get("sec-fetch-mode") == "navigate":
        return "forbidden"
    return None


# ============================================================
# OWNER EMAILS
# ============================================================
def _owner_emails() -> List[str]:
    env_val = _env("OWNER_GMAIL") or _env("ADMIN_OWNER_EMAIL")
    if env_val:
        raw = re.split(r"[,;\s]+", env_val)
    else:
        raw = CONFIG["OWNER_GMAIL"]
    return [e.strip().lower() for e in raw if "@" in e.strip()]


def is_owner(email: str) -> bool:
    return str(email or "").lower() in _owner_emails()


# ============================================================
# B64 UTILITIES
# ============================================================
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s = str(s).replace("-", "+").replace("_", "/")
    padding_needed = 4 - len(s) % 4
    if padding_needed != 4:
        s += "=" * padding_needed
    return base64.b64decode(s)


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ============================================================
# RSA SIGNING  (RS256 — same as the original RSASSA-PKCS1-v1_5)
# ============================================================
def _rsa_sign(data: bytes) -> bytes:
    key = private_key()
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _make_jwt_data(header: Dict, payload: Dict) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}"


def _sign_jwt(payload: Dict) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    data = _make_jwt_data(header, payload)
    sig = _rsa_sign(data.encode())
    return f"{data}.{_b64url_encode(sig)}"


def _verify_own_token(token: str) -> bool:
    """Re-sign header.payload and compare — deterministic RS256 verifies authorship."""
    try:
        parts = str(token or "").split(".")
        if len(parts) != 3:
            return False
        payload = json.loads(_b64url_decode(parts[1]))
        now = int(time.time())
        iat = payload.get("iat")
        if not isinstance(iat, (int, float)) or abs(now - iat) > CFG_PROOF_WINDOW:
            return False
        data = f"{parts[0]}.{parts[1]}"
        expected_sig = _b64url_encode(_rsa_sign(data.encode()))
        return _secure_equal(expected_sig, parts[2])
    except Exception:
        return False


# ============================================================
# FIREBASE CUSTOM TOKEN
# ============================================================
def _create_custom_token(uid: str) -> str:
    acct = service_account()
    now = int(time.time())
    return _sign_jwt(
        {
            "iss": acct["client_email"],
            "sub": acct["client_email"],
            "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
            "uid": uid,
        }
    )


# ============================================================
# AES-GCM ENCRYPTION  (config envelope — never plain text to client)
# ============================================================
def _derive_key_from_token(token: str) -> bytes:
    """Key = SHA-256 of the JWT signature segment."""
    sig = str(token).split(".")[2] if "." in token else ""
    return hashlib.sha256(sig.encode()).digest()


def _encrypt_for_token(token: str, plaintext: str) -> str:
    key_bytes = _derive_key_from_token(token)
    iv = os.urandom(12)
    aesgcm = AESGCM(key_bytes)
    ct = aesgcm.encrypt(iv, plaintext.encode(), None)
    out = iv + ct
    return _b64_encode(out)


def _decrypt_for_token(token: str, ciphertext_b64: str) -> str:
    key_bytes = _derive_key_from_token(token)
    raw = base64.b64decode(ciphertext_b64)
    iv, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(iv, ct, None).decode()


# ============================================================
# SEALED DOWNLOAD TICKETS  (AES-GCM, key derived from private key)
# ============================================================
def _seal_key() -> bytes:
    pem = service_account()["private_key"].replace("\\n", "\n")
    return hashlib.sha256(f"{pem}|dl".encode()).digest()


def _seal(obj: Dict, ttl_sec: int) -> str:
    key_bytes = _seal_key()
    iv = os.urandom(12)
    payload = json.dumps({**obj, "exp": int(time.time()) + ttl_sec}).encode()
    aesgcm = AESGCM(key_bytes)
    ct = aesgcm.encrypt(iv, payload, None)
    out = iv + ct
    return _b64url_encode(out)


def _unseal(blob: str) -> Optional[Dict]:
    try:
        raw = _b64url_decode(blob)
        key_bytes = _seal_key()
        iv, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(key_bytes)
        plain = aesgcm.decrypt(iv, ct, None)
        data = json.loads(plain)
        if not isinstance(data.get("exp"), (int, float)) or time.time() >= data["exp"]:
            return None
        return data
    except Exception:
        return None


# ============================================================
# OPAQUE SIGNED TICKETS
# (kind "g" = google stage 30min, "s" = admin session 12h, "c" = client 15min)
# ============================================================
def _issue_ticket(kind: str, claims: Dict, ttl: int) -> str:
    now = int(time.time())
    payload = _b64url_encode(
        json.dumps({"k": kind, **claims, "iat": now, "exp": now + ttl}, separators=(",", ":")).encode()
    )
    sig = _b64url_encode(_rsa_sign(payload.encode()))
    return f"{payload}.{sig}"


def _read_ticket(value: str, kind: Optional[str] = None) -> Optional[Dict]:
    try:
        parts = str(value or "").split(".")
        if len(parts) != 2:
            return None
        payload_b64, signature_b64 = parts
        expected_sig = _b64url_encode(_rsa_sign(payload_b64.encode()))
        if not _secure_equal(expected_sig, signature_b64):
            return None
        data = json.loads(_b64url_decode(payload_b64))
        if kind and data.get("k") != kind:
            return None
        if not isinstance(data.get("exp"), (int, float)) or time.time() >= data["exp"]:
            return None
        return data
    except Exception:
        return None


def _issue_admin_sid(email: str, owner: bool) -> str:
    return _issue_ticket("s", {"s": email, "o": owner}, ADMIN_SID_TTL)


def _verify_admin_sid(sid: str) -> bool:
    return _read_ticket(sid, "s") is not None


def _admin_session(sid: str) -> Optional[Dict]:
    return _read_ticket(sid, "s")


# ============================================================
# CONSUMED ACTION TICKET REGISTRY  (in-memory replay prevention)
# ============================================================
_consumed_tickets: Dict[str, float] = {}


def _consume_action_ticket(ticket: Dict) -> bool:
    jid = str(ticket.get("j", ""))
    if not jid or jid in _consumed_tickets:
        return False
    now = time.time()
    _consumed_tickets[jid] = now + CLIENT_TTL
    # Prune expired entries periodically
    if len(_consumed_tickets) > 5000:
        for k in [k for k, v in _consumed_tickets.items() if v <= now]:
            del _consumed_tickets[k]
    return True


# ============================================================
# GOOGLE OAUTH ACCESS TOKEN (service-account JWT flow)
# ============================================================
_token_cache: Optional[Dict] = None


async def _access_token() -> str:
    global _token_cache
    now = int(time.time())
    if _token_cache and _token_cache["exp"] > now + 60:
        return _token_cache["token"]
    acct = service_account()
    assertion = _sign_jwt(
        {
            "iss": acct["client_email"],
            "scope": " ".join(
                [
                    "https://www.googleapis.com/auth/firebase.database",
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/identitytoolkit",
                    "https://www.googleapis.com/auth/cloud-platform",
                ]
            ),
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        }
    )
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
        )
    if not r.is_success:
        raise RuntimeError("oauth failed")
    body = r.json()
    _token_cache = {"token": body["access_token"], "exp": now + body.get("expires_in", 3600)}
    return _token_cache["token"]


# ============================================================
# FIREBASE IDENTITY TOOLKIT (IDP) REST CALLS
# ============================================================
def _idp_url(method: str) -> str:
    project_id = service_account()["project_id"]
    return f"https://identitytoolkit.googleapis.com/v1/projects/{project_id}/accounts:{method}"


async def _idp(method: str, body: Dict) -> Dict:
    token = await _access_token()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            _idp_url(method),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
        )
    if not r.is_success:
        raise RuntimeError(f"idp {method} failed")
    return r.json()


async def _idp_batch_get(max_results: int = 500, next_page_token: Optional[str] = None) -> Dict:
    token = await _access_token()
    project_id = service_account()["project_id"]
    url = f"https://identitytoolkit.googleapis.com/v1/projects/{project_id}/accounts:batchGet"
    params: Dict[str, Any] = {"maxResults": max_results}
    if next_page_token:
        params["nextPageToken"] = next_page_token
    async with httpx.AsyncClient() as client:
        r = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
    return r.json() if r.is_success else {}


# ============================================================
# FIREBASE RTDB REST (service account = full access)
# ============================================================
def _db_url(path: str) -> str:
    cfg = client_config()
    base = str(cfg.get("databaseURL", "")).rstrip("/")
    clean = path.lstrip("/")
    return f"{base}/{clean}.json"


async def _db_fetch(path: str, method: str = "GET", body: Any = None) -> Any:
    token = await _access_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with httpx.AsyncClient() as client:
        kwargs: Dict[str, Any] = {"headers": headers}
        if body is not None:
            kwargs["content"] = json.dumps(body)
        r = await client.request(method, _db_url(path), **kwargs)
    if not r.is_success:
        raise RuntimeError("db request failed")
    try:
        return r.json()
    except Exception:
        return None


async def db_get(path: str) -> Any:
    return await _db_fetch(path, "GET")


async def db_set(path: str, value: Any) -> Any:
    return await _db_fetch(path, "PUT", value if value is not None else None)


async def db_update(path: str, value: Dict) -> Any:
    return await _db_fetch(path, "PATCH", value or {})


async def db_delete(path: str) -> Any:
    return await _db_fetch(path, "DELETE")


def _safe_path(p: Any) -> str:
    clean = str(p or "").strip("/")
    if not clean or ".." in clean or "#" in clean or "$" in clean:
        raise ValueError("bad request")
    return clean


# ============================================================
# CLIENT PATH ACCESS CONTROL
# ============================================================
_CLIENT_DENY = [
    re.compile(r"^admin(/|$)", re.IGNORECASE),
    re.compile(r"^settings/secrets(/|$)", re.IGNORECASE),
    re.compile(r"^serviceAccounts?(/|$)", re.IGNORECASE),
    re.compile(r"^private(/|$)", re.IGNORECASE),
]

_CLIENT_WRITE = [
    re.compile(r"^users/\{uid\}(/|$)", re.IGNORECASE),
    re.compile(r"^guests/\{uid\}(/|$)", re.IGNORECASE),
    re.compile(r"^devices/\{uid\}(/|$)", re.IGNORECASE),
    re.compile(r"^watchTime/\{uid\}(/|$)", re.IGNORECASE),
    re.compile(r"^coins/\{uid\}(/|$)", re.IGNORECASE),
    re.compile(r"^requests(/|$)", re.IGNORECASE),
    re.compile(r"^support(/|$)", re.IGNORECASE),
    re.compile(r"^engagement(/|$)", re.IGNORECASE),
    re.compile(r"^views(/|$)", re.IGNORECASE),
    re.compile(r"^likes(/|$)", re.IGNORECASE),
    re.compile(r"^comments(/|$)", re.IGNORECASE),
    re.compile(r"^notificationsRead(/|$)", re.IGNORECASE),
]


def _client_can_read(path: str) -> bool:
    return not any(p.match(path) for p in _CLIENT_DENY)


def _client_can_write(path: str, uid: str) -> bool:
    for pattern in _CLIENT_WRITE:
        resolved = re.compile(
            pattern.pattern.replace(r"\{uid\}", re.escape(uid)),
            re.IGNORECASE,
        )
        if resolved.match(path):
            return True
    return False


# ============================================================
# LITE PROJECTION  (strip episodes / links / audio for catalog)
# ============================================================
def _season_summary(seasons: Any) -> List[Dict]:
    if isinstance(seasons, list):
        items = seasons
    elif isinstance(seasons, dict):
        items = list(seasons.values())
    else:
        items = []
    result = []
    for s in items:
        if not isinstance(s, dict):
            continue
        eps = s.get("episodes", {})
        ep_count = len(eps) if isinstance(eps, (list, dict)) else 0
        result.append({"name": s.get("name", ""), "episodeCount": ep_count})
    return result


def _lite_item(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if k in ("seasons", "seasonsByLanguage", "audioTracks"):
            continue
        if k.startswith("movieLink"):
            continue
        out[k] = v
    if "seasons" in item:
        out["seasonsLite"] = _season_summary(item["seasons"])
    if "seasonsByLanguage" in item and isinstance(item["seasonsByLanguage"], dict):
        out["seasonsByLanguageLite"] = {
            lang: _season_summary(s)
            for lang, s in item["seasonsByLanguage"].items()
        }
    if "audioTracks" in item:
        tracks = item["audioTracks"]
        if isinstance(tracks, dict):
            tracks = list(tracks.values())
        out["audioLangs"] = [
            a.get("language") or a.get("label") or ""
            for a in tracks
            if isinstance(a, dict)
        ]
        out["audioLangs"] = [l for l in out["audioLangs"] if l]
    out["__lite"] = True
    return out


def _lite_collection(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    return {k: _lite_item(v) for k, v in data.items()}


# ============================================================
# SAFE FILENAME
# ============================================================
def _safe_file_name(name: Any) -> str:
    s = re.sub(r'[\\/:*?"<>|]+', " ", str(name or "video.mp4"))
    s = re.sub(r"\s+", " ", s).strip()[:160]
    return s or "video.mp4"


# ============================================================
# MEDIA PROBE  (HEAD then ranged GET fallback)
# ============================================================
async def _probe_media(url: str) -> Dict:
    async def attempt(method: str, headers: Optional[Dict] = None):
        async with httpx.AsyncClient(follow_redirects=True) as client:
            r = await client.request(method, url, headers=headers or {})
        size = 0
        cr = r.headers.get("content-range", "")
        cl = r.headers.get("content-length", "")
        if cr and re.search(r"/(\d+)$", cr):
            size = int(re.search(r"/(\d+)$", cr).group(1))
        elif cl:
            size = int(cl)
        ar = r.headers.get("accept-ranges", "")
        return {
            "ok": r.is_success or r.status_code == 206,
            "size": size if size > 0 else 0,
            "type": r.headers.get("content-type", "video/mp4"),
            "resumable": "bytes" in ar or r.status_code == 206,
        }

    try:
        result = await attempt("HEAD")
        if result["ok"] and result["size"] > 0:
            return result
    except Exception:
        pass
    try:
        return await attempt("GET", {"Range": "bytes=0-0"})
    except Exception:
        return {"ok": False, "size": 0, "type": "", "resumable": False}


# ============================================================
# ACTION HANDLER  (mirrors handle() in the original TypeScript)
# ============================================================
async def handle(body: Dict) -> Dict:
    action = str(body.get("action", "session"))

    # ── boot ──────────────────────────────────────────────────────────
    if action == "boot":
        uid = str(body.get("uid", "")).strip()[:120] or f"guest_{uuid.uuid4()}"
        token = _create_custom_token(uid)
        return {
            "token": token,
            "uid": uid,
            "e": _encrypt_for_token(token, json.dumps(client_config())),
        }

    # ── session / token ───────────────────────────────────────────────
    if action in ("session", "token"):
        uid = str(body.get("uid", "")).strip()[:120] or f"guest_{uuid.uuid4()}"
        token = _create_custom_token(uid)
        return {"token": token, "uid": uid}

    # ── cfg ───────────────────────────────────────────────────────────
    if action == "cfg":
        if not _verify_own_token(body.get("token", "")):
            raise PermissionError("unauthorized")
        token = body["token"]
        return {"e": _encrypt_for_token(token, json.dumps(client_config()))}

    # ── appConfig ─────────────────────────────────────────────────────
    if action == "appConfig":
        branding = (await db_get("settings/branding")) or {}
        legacy = (await db_get("settings/appBranding")) or {}
        managed = (await db_get("settings/appManagement")) or {}
        app = {**legacy, **managed}
        title = str(app.get("appName") or app.get("appTitle") or branding.get("siteName") or "ICF Anime").strip()
        icon_url = str(app.get("logoUrl") or app.get("appIconUrl") or branding.get("logoUrl") or "").strip()
        icon_variant = str(app.get("iconVariant") or "default").strip()
        domains = app.get("appDomains") or {}
        domains_list = list(domains.values()) if isinstance(domains, dict) else (domains if isinstance(domains, list) else [])
        first_domain = str(domains_list[0] if domains_list else "").strip().lstrip("https://").lstrip("http://").split("/")[0]
        site_url = str(
            app.get("appWebUrl") or (f"https://{first_domain}" if first_domain else "") or branding.get("siteUrl") or ""
        ).strip()
        return {
            "app": {
                "title": title,
                "iconUrl": icon_url,
                "iconVariant": icon_variant,
                "siteUrl": site_url,
                "updatedAt": int(app.get("updatedAt") or branding.get("updatedAt") or 0),
                "version": str(app.get("version") or f"{title}|{icon_url}|{icon_variant}"),
            }
        }

    # ── adminStatus ───────────────────────────────────────────────────
    if action == "adminStatus":
        pin = await db_get("admin/pin")
        exists = bool(pin and pin.get("enabled") and pin.get("code"))
        return {"exists": exists}

    # ── adminOwners ───────────────────────────────────────────────────
    if action == "adminOwners":
        if not _verify_admin_sid(body.get("sid", "")):
            raise PermissionError("unauthorized")
        return {"owners": _owner_emails()}

    # ── adminGoogle ───────────────────────────────────────────────────
    if action == "adminGoogle":
        id_token = str(body.get("idToken", ""))
        if not id_token:
            raise PermissionError("unauthorized")
        info = await _idp("lookup", {"idToken": id_token})
        users = info.get("users") or []
        user = users[0] if users else None
        email = str(user.get("email") or "" if user else "").lower()
        if not email or user.get("emailVerified") is False:
            raise PermissionError("unauthorized")
        owner = is_owner(email)
        ok = owner
        if not ok:
            auth_list = (await db_get("admin/authorizedEmails")) or {}
            ok = any(str(v or "").lower() == email for v in auth_list.values())
        if not ok:
            raise PermissionError("unauthorized")
        pin = await db_get("admin/pin")
        return {
            "gid": _issue_ticket("g", {"s": email, "o": owner}, GOOGLE_TICKET_TTL),
            "email": email,
            "isOwner": owner,
            "pinExists": bool(pin and pin.get("enabled") and pin.get("code")),
        }

    # ── adminPin ──────────────────────────────────────────────────────
    if action == "adminPin":
        stage = _read_ticket(body.get("gid", ""), "g")
        if not stage:
            raise PermissionError("unauthorized")
        email = str(stage.get("s", "")).lower()
        still_ok = is_owner(email)
        if not still_ok:
            auth_list = (await db_get("admin/authorizedEmails")) or {}
            still_ok = any(str(v or "").lower() == email for v in auth_list.values())
        if not still_ok:
            raise PermissionError("unauthorized")
        pin = await db_get("admin/pin")
        code = str(body.get("pin", ""))
        if not pin or not pin.get("enabled") or not pin.get("code") or not code:
            raise PermissionError("unauthorized")
        if str(pin["code"]) != code:
            raise PermissionError("unauthorized")
        owner = is_owner(email)
        return {
            "sid": _issue_admin_sid(email, owner),
            "email": email,
            "isOwner": owner,
        }

    # ── adminSetPin ───────────────────────────────────────────────────
    if action == "adminSetPin":
        code = str(body.get("code", ""))
        enabled = body.get("enabled", True) is not False
        by_session = _admin_session(body.get("sid", ""))
        by_google = _read_ticket(body.get("gid", ""), "g")
        if not by_session and not by_google:
            raise PermissionError("unauthorized")
        if enabled and len(code) < 4:
            raise ValueError("bad request")
        pin_value = {"enabled": True, "code": code} if enabled else {"enabled": False, "code": ""}
        await db_set("admin/pin", pin_value)
        sessions = (await db_get("admin/sessions")) or {}
        for sid_key, s in sessions.items():
            if isinstance(s, dict) and not s.get("revoked"):
                await db_update(f"admin/sessions/{sid_key}", {"revoked": True, "revokedAt": int(time.time() * 1000)})
        return {"ok": True}

    # ── adminManage ───────────────────────────────────────────────────
    if action == "adminManage":
        session = _admin_session(body.get("sid", ""))
        if not session:
            raise PermissionError("unauthorized")
        if not session.get("o") or not is_owner(session.get("s", "")):
            raise PermissionError("unauthorized")
        op = str(body.get("op", ""))
        email = str(body.get("email", "")).lower()
        sessions = (await db_get("admin/sessions")) or {}

        if op == "logoutSession":
            sid_target = str(body.get("sessionId", ""))
            if not sid_target or "/" in sid_target:
                raise ValueError("bad request")
            await db_update(f"admin/sessions/{sid_target}", {"revoked": True, "revokedAt": int(time.time() * 1000)})
            return {"ok": True}

        if op in ("logoutEmail", "removeAdminEmail"):
            if not email:
                raise ValueError("bad request")
            if is_owner(email):
                raise PermissionError("unauthorized")
            for sid_key, s in sessions.items():
                if isinstance(s, dict) and str(s.get("email", "")).lower() == email:
                    await db_update(f"admin/sessions/{sid_key}", {"revoked": True, "revokedAt": int(time.time() * 1000)})
            if op == "removeAdminEmail":
                auth_list = (await db_get("admin/authorizedEmails")) or {}
                for key, val in auth_list.items():
                    if str(val or "").lower() == email:
                        await db_delete(f"admin/authorizedEmails/{key}")
            return {"ok": True}

        raise ValueError("bad request")

    # ── adminDb ───────────────────────────────────────────────────────
    if action == "adminDb":
        session = _admin_session(body.get("sid", ""))
        if not session:
            raise PermissionError("unauthorized")
        path = _safe_path(body.get("path"))
        op = str(body.get("op", "get"))
        owner_only = bool(re.match(r"^admin/(pin|authorizedEmails)", path))
        if owner_only and op != "get" and not (session.get("o") and is_owner(session.get("s", ""))):
            raise PermissionError("unauthorized")
        if op == "get":
            return {"data": await db_get(path)}
        if op == "set":
            return {"data": await db_set(path, body.get("value"))}
        if op == "update":
            return {"data": await db_update(path, body.get("value") or {})}
        if op == "remove":
            return {"data": await db_delete(path)}
        raise ValueError("bad request")

    # ── authDelete ────────────────────────────────────────────────────
    if action == "authDelete":
        data = body.get("data") or {}
        uid = data.get("uid")
        email = data.get("email")
        target = uid
        if not target and email:
            found = await _idp("lookup", {"email": [email]})
            users = found.get("users") or []
            target = users[0].get("localId") if users else None
        if not target:
            return {"result": {"deleted": 0}}
        await _idp("delete", {"localId": target})
        return {"result": {"deleted": 1}}

    # ── authWipeAll ───────────────────────────────────────────────────
    if action == "authWipeAll":
        paths = body.get("data", {}).get("paths") or []
        if not isinstance(paths, list):
            paths = []
        auth_deleted = 0
        next_page_token: Optional[str] = None
        while True:
            page = await _idp_batch_get(500, next_page_token)
            ids = [u["localId"] for u in (page.get("users") or [])]
            if ids:
                await _idp("batchDelete", {"localIds": ids, "force": True})
                auth_deleted += len(ids)
            next_page_token = page.get("nextPageToken")
            if not next_page_token:
                break
        db_wiped: List[str] = []
        for p in paths:
            try:
                await db_delete(p)
                db_wiped.append(p)
            except Exception:
                pass
        return {"result": {"authDeleted": auth_deleted, "dbWiped": db_wiped}}

    # ── clientAuth ────────────────────────────────────────────────────
    if action == "clientAuth":
        uid_raw = str(body.get("uid", "")).strip()[:120]
        uid = uid_raw or f"g_{uuid.uuid4()}"
        cid = _issue_ticket("c", {"u": uid, "j": str(uuid.uuid4())}, CLIENT_TTL)
        return {"cid": cid, "uid": uid, "exp": int(time.time() * 1000) + CLIENT_TTL * 1000}

    # ── db ────────────────────────────────────────────────────────────
    if action == "db":
        ticket = _read_ticket(body.get("cid", ""), "c")
        if not ticket:
            raise PermissionError("unauthorized")
        path = _safe_path(body.get("path"))
        op = str(body.get("op", "get"))
        if op == "get":
            if not _client_can_read(path):
                raise PermissionError("unauthorized")
            raw = await db_get(path)
            return {"data": _lite_collection(raw) if body.get("lite") else raw}
        if not _consume_action_ticket(ticket):
            raise PermissionError("unauthorized")
        if not _client_can_write(path, ticket.get("u", "")):
            raise PermissionError("unauthorized")
        if op == "set":
            return {"data": await db_set(path, body.get("value"))}
        if op == "update":
            return {"data": await db_update(path, body.get("value") or {})}
        if op == "remove":
            return {"data": await db_delete(path)}
        if op == "push":
            import random, string
            key = f"-{int(time.time()*1000):x}{''.join(random.choices(string.ascii_lowercase + string.digits, k=7))}"
            await db_set(f"{path}/{key}", body.get("value"))
            return {"data": {"key": key}}
        raise ValueError("bad request")

    # ── dlMeta ────────────────────────────────────────────────────────
    if action == "dlMeta":
        ticket = _read_ticket(body.get("cid", ""), "c")
        if not ticket:
            raise PermissionError("unauthorized")
        urls_raw = body.get("urls")
        if isinstance(urls_raw, list):
            urls = [u for u in urls_raw[:40] if re.match(r"^https?://", str(u or ""), re.IGNORECASE)]
        else:
            single = str(body.get("url", ""))
            urls = [single] if re.match(r"^https?://", single, re.IGNORECASE) else []
        import asyncio
        async def probe_one(u: str) -> tuple:
            try:
                info = await _probe_media(u)
                return u, {"size": info.get("size", 0), "type": info.get("type", ""), "resumable": bool(info.get("resumable")), "ok": bool(info.get("ok"))}
            except Exception:
                return u, {"size": 0, "type": "", "resumable": False, "ok": False}
        results = await asyncio.gather(*[probe_one(u) for u in urls])
        return {"meta": dict(results)}

    # ── dlSign ────────────────────────────────────────────────────────
    if action == "dlSign":
        ticket = _read_ticket(body.get("cid", ""), "c")
        if not ticket:
            raise PermissionError("unauthorized")
        url = str(body.get("url", ""))
        if not re.match(r"^https?://", url, re.IGNORECASE):
            raise ValueError("bad request")
        ttl_hours = min(max(int(body.get("ttlHours") or 24), 1), 48)
        ttl_sec = ttl_hours * 3600
        blob = _seal({"u": url, "n": _safe_file_name(body.get("name"))}, ttl_sec)
        return {"blob": blob, "expires": int(time.time() * 1000) + ttl_sec * 1000}

    raise ValueError("bad request")


# ============================================================
# SEALED MEDIA STREAMING  (GET /d/<blob>)
# ============================================================
async def _serve_sealed(request: Request, blob: str) -> Response:
    data = _unseal(blob)
    if not data:
        return Response(content="Link expired", status_code=410)
    upstream_url = data["u"]
    file_name = data.get("n", "video.mp4")
    range_header = request.headers.get("range")
    req_method = request.method

    headers_out: Dict[str, str] = {}
    if range_header:
        upstream_headers = {"Range": range_header}
    else:
        upstream_headers = {}

    async with httpx.AsyncClient(follow_redirects=True) as client:
        upstream_req = client.build_request(
            "HEAD" if req_method == "HEAD" else "GET",
            upstream_url,
            headers=upstream_headers,
        )
        upstream_resp = await client.send(upstream_req, stream=True)

    for k in ["content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified"]:
        v = upstream_resp.headers.get(k)
        if v:
            headers_out[k] = v
    if "accept-ranges" not in headers_out:
        headers_out["accept-ranges"] = "bytes"
    headers_out["content-disposition"] = f'attachment; filename="{file_name}"'
    headers_out["cache-control"] = "no-store"
    headers_out["access-control-allow-origin"] = "*"

    if req_method == "HEAD":
        await upstream_resp.aclose()
        return Response(status_code=upstream_resp.status_code, headers=headers_out)

    async def stream_body():
        async for chunk in upstream_resp.aiter_bytes():
            yield chunk

    return StreamingResponse(
        stream_body(),
        status_code=upstream_resp.status_code,
        headers=headers_out,
    )


# ============================================================
# FASTAPI APPLICATION
# ============================================================
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/{full_path:path}")
async def catch_get(full_path: str, request: Request):
    """
    Browser GET / navigator visit → 404. No information leaks.
    Sealed download links are served from /d/<blob>.
    """
    origin = request.headers.get("origin", "")
    cors = _cors_headers(origin)

    # Sealed download proxy
    m = re.match(r"^d/([A-Za-z0-9_\-]+)$", full_path)
    if m and request.method in ("GET", "HEAD"):
        try:
            resp = await _serve_sealed(request, m.group(1))
            for k, v in cors.items():
                resp.headers[k] = v
            return resp
        except Exception:
            return Response(content="Not Found", status_code=404, headers=cors)

    return Response(content="Not Found", status_code=404, headers=cors)


@app.head("/{full_path:path}")
async def catch_head(full_path: str, request: Request):
    return await catch_get(full_path, request)


@app.options("/{full_path:path}")
async def catch_options(full_path: str, request: Request):
    origin = request.headers.get("origin", "")
    return Response(content="ok", headers=_cors_headers(origin))


@app.post("/{full_path:path}")
async def catch_post(full_path: str, request: Request):
    origin = request.headers.get("origin", "")
    cors = _cors_headers(origin)

    # Sealed download proxy (POST with /d/<blob> is unusual but kept for parity)
    m = re.match(r"^d/([A-Za-z0-9_\-]+)$", full_path)
    if m:
        try:
            resp = await _serve_sealed(request, m.group(1))
            for k, v in cors.items():
                resp.headers[k] = v
            return resp
        except Exception:
            return JSONResponse({"error": "not found"}, status_code=404, headers=cors)

    raw_body = (await request.body()).decode("utf-8", errors="replace")
    denied = await _guard_request(request, raw_body)
    if denied:
        status = 401 if denied == "unauthorized" else 403
        return JSONResponse({"error": denied}, status_code=status, headers=cors)

    try:
        body = json.loads(raw_body or "{}")
    except json.JSONDecodeError:
        return JSONResponse({"error": "bad request"}, status_code=400, headers=cors)

    try:
        result = await handle(body)
        return JSONResponse(
            result,
            headers={**cors, "Cache-Control": "no-store"},
        )
    except PermissionError as e:
        msg = str(e)
        return JSONResponse(
            {"error": "unauthorized" if "unauthorized" in msg else "bad request"},
            status_code=401 if "unauthorized" in msg else 400,
            headers=cors,
        )
    except (ValueError, RuntimeError) as e:
        msg = str(e)
        unauthorized = "unauthorized" in msg
        return JSONResponse(
            {"error": "unauthorized" if unauthorized else "bad request"},
            status_code=401 if unauthorized else 400,
            headers=cors,
        )
    except Exception:
        return JSONResponse({"error": "bad request"}, status_code=400, headers=cors)


# ============================================================
# VERCEL ASGI HANDLER
# Vercel Python runtime calls `handler` — we wrap FastAPI's
# ASGI app so it works as a serverless function.
# ============================================================
from mangum import Mangum

handler = Mangum(app, lifespan="off")
