<div align="center">
  
<img style="width:60px" src="https://raw.githubusercontent.com/link9596/FlyPaste/refs/heads/main/public/favicon.png" alt=""><h1>FlyPaste</h1>

**A self-hosted, end-to-end encrypted clipboard board on the Cloudflare edge.**

Share text and files across your devices in real time. One password unlocks your own private, encrypted workspace.

English · [简体中文](./README.md)

[![GitHub license](https://img.shields.io/github/license/link9596/FlyPaste)](https://github.com/link9596/FlyPaste/blob/main/LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/link9596/FlyPaste)

[**⌨️ Quick Start**](#quick-start) · [**☁️ Live Demo**](https://r2-file.lkin.cn/web/demo/FlyPaste-demo.html) · [**💬 Issues**](https://github.com/link9596/FlyPaste/issues) · [**🛡️ Security**](#security-notes)

</div>
---

## ✨ Feature

- **End-to-end encryption by design** — text messages are AES-256-GCM encrypted in the browser before being uploaded; the key is derived from your password via PBKDF2 (310,000 iterations), never leaves your device, and only encrypted text is stored on the server.
- **Real-time sync** — Cloudflare Durable Objects broadcast changes over WebSocket to keep multiple devices in sync in real time.
- **Multi-tenant isolation** — via `ACCESS_TOKENS`, multiple passwords are mapped to isolated tenants, so different passwords enter different isolated environments.
- **Completely free** — relies only on Workers + R2 + Durable Objects, runs within the free tier, globally distributed with ultra-low latency.

---
## 🚀 Core Functions

**Text & File Paste Board**
- Multi-conversation panels.
- One-click copy for text; drag & drop, paste or file-picker upload and download.
- **R2 multipart upload** for large files (8 MiB parts); files support **custom expiration** (up to permanent retention).
- Each conversation automatically keeps the latest **300** messages; overflow is trimmed from the oldest (files are cleaned up too).

**Sync & Sessions**
- WebSocket push + polling fallback keeps multiple devices in lockstep.
- 7-day sliding sessions with HttpOnly / Secure / SameSite=Strict cookies and "log out all devices".

**Security Hardening**
- IP-based login rate limiting with exponential backoff to prevent brute-force attacks (5 consecutive failures → 1-minute lockout, up to 30 minutes).
- Timing-safe password comparison; strict CSP, `X-Frame-Options: DENY`, nosniff and `Permissions-Policy` response headers.
- A scheduled job sweeps expired sessions, files and rate-limit records every 6 hours.

**PWA**
- Installable as a web app.

---

## 🧱 Tech Stack

| Layer | Tech |
| --- | --- |
| Runtime | Cloudflare Workers |
| Storage | Cloudflare R2 |
| Real-time sync | Durable Object `SyncHub` |
| Frontend | Vanilla HTML, PWA |

---

## Quick Start
1. **One-click deploy**: click the Deploy to Cloudflare button above and follow the flow.
2. **Configure secrets**: set an environment variable — either a single `ACCESS_TOKEN` (one shared space) or `ACCESS_TOKENS` (a JSON `password → tenant` map for multiple isolated spaces).
> For example, the environment variable `ACCESS_TOKEN` with the value `{"password123":"userid"}` or the multi-password form: `{"password123":"userid","password2":"username2"}`
3. **Visit & unlock**: open your Worker domain and enter the password — it is used both for authentication and for deriving the encryption key.
4. **Start pasting**: create a conversation, paste text or drag in files; other devices see changes in real time.

⚠️⚠️ We recommended to use HTTPS to access, otherwise login may fail.

It's suggested to enable 'Always Use HTTPS' under SSL/TLS > Edge Certificates.

---

## Security Notes
- Text messages are end-to-end encrypted; **files are not encrypted** — keep the deployment private, and set an expiration for sensitive material.
- Your password is your master key: losing it means text data can never be decrypted.

## License

GPL-3.0 license
