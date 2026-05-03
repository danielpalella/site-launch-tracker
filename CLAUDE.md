# site-launch-tracker

## Documentation

Before exploring or modifying the codebase, read `docs/conventions/DOCUMENTATION.md` to understand how documentation is organized and where to find information.

**Do not edit files matching `docs/features/**/RFC-*.md` or `docs/features/**/TRD-*.md` without explicit user approval.** These are design docs with stakeholders — propose changes in chat first and wait for confirmation before writing.

## Project Overview

Internal tool for tracking contractor site launches, managing onboarding interviews, and coordinating rep workflows. Runs as a single Express server on Cloud Run with a Firestore backend.

## Tech Stack

- **Runtime:** Node 20 (ES modules), Bun for container builds
- **Framework:** Express
- **Database:** Firestore (Firebase Admin SDK)
- **AI:** Gemini 2.5 Flash (generativelanguage API, direct REST)
- **File storage:** Google Drive API (googleapis SDK)
- **Speech:** Web Speech API (client-side), Google Cloud Speech-to-Text (server-side via WebSocket)
- **Real-time:** Server-Sent Events (SSE) for live state sync, WebSocket (ws) for audio streaming
- **Hosting:** Cloud Run (Dockerfile uses Bun)
- **Frontend:** Vanilla HTML/CSS/JS in `public/`, no build step

## Project Structure

```
server.js          ← all backend logic (single file)
database.js        ← placeholder (Firestore initialized in server.js)
public/            ← frontend pages served statically
  index.html       ← main dashboard
  onboarding.html  ← rep interview chat UI
  present.html     ← rep presentation view (TV/screen share)
  join.html        ← contractor interview page (public, token-auth)
  meet-addon.html  ← Google Meet integration
  login.html       ← authentication
docs/              ← documentation (conventions, features, SOPs)
chrome-extension/  ← browser extension
```

## Key Patterns

- **Authentication:** Cookie or Bearer token validated against Firestore `sessions` collection. Contractor-facing pages use UUID join tokens instead.
- **Real-time sync:** SSE via in-memory `sseClients` Map keyed by session ID. Events: `state`, `question_change`, `transcript`, `summary`, `complete`.
- **Transcript extraction:** Three paths (live Q&A, transcript upload, Meet import) all use the same Gemini extraction prompt and JSON profile schema. The schema is currently duplicated across all three endpoints.
- **Rate limiting:** Unauthenticated join endpoints limited to 30 requests/60s per session via in-memory Map.

## Development

```bash
npm run dev          # start with --watch
```

No test suite. No build step for frontend. Server restarts on file change.

## Git Workflow

Prefer merge-and-resolve over rebase when integrating branches. Avoid force-push.
