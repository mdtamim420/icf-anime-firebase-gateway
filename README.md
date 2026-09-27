# ICF Anime — Firebase Gateway (FastAPI / Vercel)

A **zero-trust Firebase Gateway** converted from the original Supabase Edge Function
(TypeScript/Deno) to a production-ready **Python FastAPI** project deployed on
**Vercel Serverless Functions**.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Prerequisites](#prerequisites)
4. [Environment Variables](#environment-variables)
5. [Local Development](#local-development)
6. [Deployment to Vercel](#deployment-to-vercel)
   - [Option A — Vercel CLI](#option-a--vercel-cli-recommended)
   - [Option B — GitHub Integration](#option-b--github-integration)
   - [Option C — Manual ZIP Upload](#option-c--manual-zip-upload)
7. [Setting Environment Variables in Vercel](#setting-environment-variables-in-vercel)
8. [API Reference](#api-reference)
9. [Security Model](#security-model)
10. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
Browser / Android App
        │
        │  POST /  (JSON body with { action, ... })
        ▼
┌─────────────────────────────┐
│  Vercel Serverless Function │   api/index.py  (FastAPI)
│  ─────────────────────────  │
│  • CORS + HMAC guard        │
│  • AES-GCM config envelope  │
│  • RS256 signed tickets      │
│  • Admin PIN two-factor      │
│  • RTDB proxy (read/write)   │
│  • Sealed download proxy     │
└────────────┬────────────────┘
             │  Service-account JWT (never leaves server)
             ▼
     Firebase / Google APIs
```

**What the client NEVER sees:**
- Raw Firebase service-account credentials
- Admin PIN value
- Real media-host URLs (sealed, AES-GCM encrypted)

---

## Project Structure

```
icf-anime-firebase-gateway/
├── api/
│   └── index.py          # FastAPI app — all gateway logic
├── requirements.txt      # Python dependencies
├── vercel.json           # Vercel routing + function config
└── README.md             # This file
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| Python | ≥ 3.11 |
| pip | latest |
| Vercel CLI | ≥ 33.x  (`npm i -g vercel`) |
| Firebase project | with Realtime Database enabled |

---

## Environment Variables

Set **all** of these in Vercel (see [Setting Environment Variables](#setting-environment-variables-in-vercel)).

### Required

| Variable | Description |
|----------|-------------|
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Full JSON string of your Firebase service-account key. Download from Firebase Console → Project Settings → Service accounts → Generate new private key. Paste the entire JSON as one line (or with literal `\n` in the key). |
| `FIREBASE_CLIENT_CONFIG_JSON` | Your Firebase web app's client config JSON string. Found in Firebase Console → Project Settings → Your apps → SDK setup and configuration → Config. Example: `{"apiKey":"...","authDomain":"...","databaseURL":"...","projectId":"...","storageBucket":"...","messagingSenderId":"...","appId":"..."}` |

### Optional but Recommended

| Variable | Description | Default |
|----------|-------------|---------|
| `OWNER_GMAIL` | Comma-separated list of owner/super-admin Gmail addresses. These accounts bypass the `admin/authorizedEmails` check. | Value in `CONFIG` block |
| `ALLOWED_DOMAINS` | Comma-separated list of allowed CORS origins. Supports `*` wildcard subdomain syntax, e.g. `https://*.lovable.app`. | Value in `CONFIG` block |
| `APP_SECRET_KEY` | HMAC secret for Android app requests (no `Origin` header). 32+ random bytes recommended. Generate with: `python -c "import secrets; print(secrets.token_hex(32))"` | empty (HMAC check skipped) |
| `ALLOW_LOCAL_DEV` | Set to `"true"` to allow `localhost` origins during development. **Never set in production.** | `""` |

---

## Local Development

```bash
# 1. Clone / extract the project
cd icf-anime-firebase-gateway

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables (create a .env file or export manually)
export FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"service_account","project_id":"...","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"...@....iam.gserviceaccount.com",...}'
export FIREBASE_CLIENT_CONFIG_JSON='{"apiKey":"...","authDomain":"...","databaseURL":"https://your-project-default-rtdb.firebaseio.com","projectId":"..."}'
export OWNER_GMAIL="you@gmail.com"
export ALLOW_LOCAL_DEV="true"

# 5. Run the development server
uvicorn api.index:app --reload --port 8000
```

Test the server:
```bash
# Should return 404 (browser visit protection)
curl http://localhost:8000/

# Should return a Firebase custom token
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3000" \
  -d '{"action":"session","uid":"test-user-123"}'
```

---

## Deployment to Vercel

### Option A — Vercel CLI (Recommended)

```bash
# 1. Install Vercel CLI globally
npm install -g vercel

# 2. Log in
vercel login

# 3. From inside the project folder
cd icf-anime-firebase-gateway

# 4. Deploy (first-time — follow the interactive prompts)
vercel

# 5. For subsequent production deployments
vercel --prod
```

During the first `vercel` run you will be asked:
- **Set up and deploy?** → `Y`
- **Which scope?** → select your account / team
- **Link to existing project?** → `N` (create new)
- **Project name** → `icf-anime-firebase-gateway` (or any name)
- **In which directory is your code located?** → `.` (current directory)
- **Override settings?** → `N` (vercel.json handles everything)

After deploy, Vercel will print your production URL, e.g.:
`https://icf-anime-firebase-gateway.vercel.app`

---

### Option B — GitHub Integration

1. Push the project folder to a GitHub repository.
2. Go to [vercel.com/new](https://vercel.com/new).
3. Import the repository.
4. Vercel auto-detects `vercel.json` — no framework preset needed.
5. **Before clicking Deploy**, add all environment variables (see below).
6. Click **Deploy**.

Every `git push` to `main` will automatically redeploy.

---

### Option C — Manual ZIP Upload

If you cannot use the CLI or GitHub:

#### Step 1 — Create the ZIP

**macOS / Linux:**
```bash
cd icf-anime-firebase-gateway
zip -r ../icf-anime-firebase-gateway.zip . \
  --exclude "*.pyc" \
  --exclude "__pycache__/*" \
  --exclude ".venv/*" \
  --exclude ".git/*" \
  --exclude ".DS_Store"
```

**Windows (PowerShell):**
```powershell
cd icf-anime-firebase-gateway
Compress-Archive -Path . -DestinationPath ..\icf-anime-firebase-gateway.zip
```

The ZIP must include exactly:
```
api/index.py
requirements.txt
vercel.json
README.md          (optional)
```

#### Step 2 — Upload via Vercel CLI

```bash
vercel deploy --prebuilt   # or drag-drop in Vercel Dashboard
```

Or using the Vercel Dashboard:
1. Go to [vercel.com/dashboard](https://vercel.com/dashboard)
2. Click **Add New → Project**
3. Choose **Upload** and drag in the ZIP file

---

## Setting Environment Variables in Vercel

### Via Dashboard (recommended for secrets)

1. Open your project in [vercel.com/dashboard](https://vercel.com/dashboard)
2. Go to **Settings → Environment Variables**
3. For each variable:
   - **Name**: e.g. `FIREBASE_SERVICE_ACCOUNT_JSON`
   - **Value**: paste the full JSON string (Vercel stores it encrypted)
   - **Environments**: check ✅ Production, ✅ Preview, ✅ Development as needed
4. Click **Save**
5. **Redeploy** the project for changes to take effect: go to **Deployments → ⋯ → Redeploy**

### Via Vercel CLI

```bash
# Set a secret (prompts for value — good for long JSON strings)
vercel env add FIREBASE_SERVICE_ACCOUNT_JSON production

# Or pass inline (be careful with shell escaping)
vercel env add OWNER_GMAIL production <<< "you@gmail.com,other@gmail.com"
```

### Important notes on JSON values

When pasting the service-account JSON, Vercel stores it as-is.
The `private_key` field inside the JSON contains literal `\n` sequences —
**do not convert them**; the gateway handles both `\n` and real newlines.

**Correct format** (paste the entire file contents as one value):
```
{"type":"service_account","project_id":"my-project","private_key_id":"abc123","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq...\n-----END PRIVATE KEY-----\n","client_email":"firebase-adminsdk-xxx@my-project.iam.gserviceaccount.com",...}
```

---

## API Reference

All requests are `POST /` with a JSON body `{ "action": "...", ... }`.

### Public actions (no auth required)

| Action | Body | Response |
|--------|------|----------|
| `boot` | `{ uid? }` | `{ token, uid, e }` — custom token + encrypted config |
| `session` | `{ uid? }` | `{ token, uid }` — custom token only |
| `cfg` | `{ token }` | `{ e }` — encrypted config (verifies token was issued by this gateway) |
| `appConfig` | `{}` | `{ app: { title, iconUrl, ... } }` |
| `adminStatus` | `{}` | `{ exists: bool }` — is a PIN configured? |
| `clientAuth` | `{ uid? }` | `{ cid, uid, exp }` — client ticket |

### Client-scoped actions (require `cid`)

| Action | Body | Response |
|--------|------|----------|
| `db` (get) | `{ cid, path, lite? }` | `{ data }` |
| `db` (write) | `{ cid, path, op, value }` | `{ data }` |
| `dlMeta` | `{ cid, urls[] \| url }` | `{ meta: { url: { size, type, resumable, ok } } }` |
| `dlSign` | `{ cid, url, name?, ttlHours? }` | `{ blob, expires }` |

### Admin actions

| Action | Body | Response |
|--------|------|----------|
| `adminGoogle` | `{ idToken }` | `{ gid, email, isOwner, pinExists }` |
| `adminPin` | `{ gid, pin }` | `{ sid, email, isOwner }` |
| `adminSetPin` | `{ sid \| gid, code, enabled }` | `{ ok }` |
| `adminOwners` | `{ sid }` | `{ owners[] }` |
| `adminManage` | `{ sid, op, email \| sessionId }` | `{ ok }` |
| `adminDb` | `{ sid, op, path, value? }` | `{ data }` |
| `authDelete` | `{ data: { uid \| email } }` | `{ result }` |
| `authWipeAll` | `{ data: { paths[] } }` | `{ result }` |

### Sealed download streaming

`GET /d/<blob>` — streams the upstream media file with full `Range` / resume support.
The `blob` token is obtained from `dlSign`. Expires after `ttlHours` (default 24h, max 48h).

---

## Security Model

| Threat | Mitigation |
|--------|------------|
| Unauthorized origins | CORS `originAllowed()` — wildcard pattern matching, constant-time comparison |
| Android spoofing | HMAC-SHA256 over `timestamp.body` with `APP_SECRET_KEY`, 5-minute replay window |
| Admin PIN brute-force | PIN is compared server-side only; never stored in JWT or returned to client |
| Config leakage | Client config is AES-GCM encrypted with a key derived from the JWT signature — only the token holder can decrypt |
| RTDB privilege escalation | `CLIENT_DENY` path list blocks `admin/*`, `settings/secrets/*`, etc. Write paths are allow-listed per UID |
| Replay attacks | Action tickets are single-use (`consumeActionTicket` in-memory registry) |
| Media URL leakage | Real URLs are AES-GCM sealed server-side; client only receives an opaque `blob` token |
| Token forgery | All tickets are RS256-signed with the Firebase service-account private key |
| Browser navigation | Non-POST requests return `404 Not Found` with no body |

---

## Troubleshooting

### `FIREBASE_SERVICE_ACCOUNT_JSON not set`
Verify the environment variable is saved in Vercel and the project has been **redeployed** after adding it.

### `401 unauthorized` on every request
- Check that your domain is in `ALLOWED_DOMAINS` (either via env var or the `CONFIG` block in `api/index.py`).
- For local dev, set `ALLOW_LOCAL_DEV=true`.
- For Android without `Origin`, ensure `APP_SECRET_KEY` is set and the HMAC headers are correct.

### `db request failed`
- Confirm `FIREBASE_CLIENT_CONFIG_JSON` contains a valid `databaseURL` field.
- Ensure the Firebase Realtime Database is created and the region matches.
- Check that the service account has the **Firebase Admin SDK** role.

### `oauth failed`
- Your service-account JSON may be malformed or the `private_key` field may have lost its newlines. Re-download from Firebase Console.

### Large responses are slow
- Enable the `lite` flag in `db` GET requests for catalog listings. This strips episode data and audio tracks server-side.

### Vercel function timeout
- The default `maxDuration` is 30 seconds (set in `vercel.json`). For `authWipeAll` on large user sets this may be insufficient. Increase to 60 on Pro plans: `"maxDuration": 60`.

---

## License

MIT — use freely in your own projects.

---

## v3.2 changes (ICF site parity)

- Responses now match the Supabase / Cloudflare gateway 1:1 (added `watchView`, `watchReaction`, `uids/{uid}` write, same lite catalog fields, crash-safe `appConfig` / admin reads).
- Env JSON accepted as plain JSON, quoted JSON, or base64 — paste the same `FIREBASE_SERVICE_ACCOUNT_JSON`, `FIREBASE_CLIENT_CONFIG_JSON`, `OWNER_GMAIL` (and `APP_SECRET_KEY` if used) as on Supabase, then **Redeploy**.
- Sealed download streaming fixed; allowed domains synced with Supabase gateway (+ `*.vercel.app`).
- Runs as native Vercel ASGI (`app`); Mangum removed.
- Site switch: `src/firebase-setup/gateway.config.ts` → set `VERCEL_GATEWAY.status = "on"` and the others `"off"`.
