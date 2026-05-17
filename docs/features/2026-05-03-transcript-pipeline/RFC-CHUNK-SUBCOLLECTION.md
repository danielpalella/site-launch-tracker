---
Name: Chunk subcollection
Summary: Move transcript chunks from a parent-doc array to a Firestore subcollection with deterministic document IDs, dual-write migration, and feature-flagged rollout.
Keywords: firestore, subcollection, transcript, chunks, idempotent, dual-write, migration, feature-flag, sse, onboarding
Source: docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md
---

# Chunk Subcollection

## Context

Transcript chunks are currently appended to a `transcript_chunks` array on the `onboarding_interviews/{sessionId}` parent document via `FieldValue.arrayUnion`. This creates a hard ceiling at 1 MiB per document, read amplification on every state fetch, and no idempotency on retries. See `docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md` for full motivation.

This RFC covers the live-tier storage change: moving chunks to a subcollection, making writes idempotent, and migrating without breaking in-flight interviews. It corresponds to migration phases 0-2 in the TRD.

## Change

### Subcollection schema

Create a subcollection under each session document:

```
onboarding_interviews/{sessionId}/transcript_chunks/{chunkId}
```

Each chunk document:

| Field | Type | Description |
|-------|------|-------------|
| `text` | string (max 5000) | Transcript text |
| `ts` | string (ISO 8601) | Timestamp when chunk was finalized |
| `source` | string | `'contractor'`, `'rep'`, or `'system'` |
| `questionIndex` | number | Index of the current question at time of capture |
| `seq` | number | Monotonically increasing per session, assigned client-side |
| `skipped` | boolean (optional) | `true` when contractor skipped the question |

### Deterministic chunk IDs

The `chunkId` is derived deterministically so retries produce the same document ID:

```
chunkId = sha1(sessionId + ':' + source + ':' + seq).substring(0, 20)
```

Using Firestore `set()` instead of `arrayUnion` means a retry overwrites the same document — no duplicates.

### Client-side seq counter

`join.html` maintains a `let chunkSeq = 0` counter, incremented on each finalized (non-interim) transcript submission. The `seq` value is sent alongside `text` in the POST body:

```
POST /api/join/{sessionId}/{token}/transcript
{ "text": "...", "seq": 12 }
```

Interim updates continue writing to the parent doc's `contractor_interim` field (unchanged).

### Server-side changes

**Transcript endpoint** (`POST /api/join/:sessionId/:token/transcript`, server.js:6024):

- Read the feature flag `TRANSCRIPT_SUBCOLLECTION_ENABLED` (environment variable, default `false`).
- When enabled: compute `chunkId`, write to subcollection via `set()`, increment parent doc's `chunk_count` via `FieldValue.increment(1)`.
- During dual-write phase: also write to the parent array via `arrayUnion` (existing behavior).
- SSE broadcast is unchanged — `emitSseEvent()` fires regardless of storage path.

**Skip endpoint** (`POST /api/join/:sessionId/:token/skip`, server.js:6049):

- Same pattern: write skip chunk to subcollection with `skipped: true`, `seq` derived from current `chunk_count + 1` server-side (skip has no client seq).

**State/stream endpoints** (server.js:5960, 6005):

- When reading session state for SSE initial payload or REST response, stop including `transcript_chunks` from the parent array.
- Chunk history is only needed for extraction — not for live state sync.
- `chunk_count` on the parent doc provides the count without reading the subcollection.

**Extraction endpoint** (`POST /api/onboarding/sessions/:id/extract`):

- Read chunks from subcollection ordered by `seq` instead of from the parent array.
- Group by `questionIndex` to build the Q&A pairs for Gemini extraction.
- Fall back to parent array if subcollection is empty (legacy sessions).

### Parent document changes

| Field | Change |
|-------|--------|
| `transcript_chunks` | Removed (after phase 2 for new sessions) |
| `chunk_count` | Added — denormalized count, incremented atomically on each chunk write |
| `contractor_interim` | Unchanged — still on parent for real-time display |

### Feature flag

Environment variable: `TRANSCRIPT_SUBCOLLECTION_ENABLED`

| Value | Behavior |
|-------|----------|
| `false` (default) | Legacy path only. Array writes, array reads. |
| `dual-write` | Write to both array and subcollection. Read from array. Phase 0. |
| `dual-read` | Write to both. Read from subcollection with array fallback. Phase 1. |
| `true` | Subcollection only for new sessions. Legacy sessions still use array. Phase 2. |

The flag is checked once at request time, not cached. Changing the environment variable and restarting the Cloud Run revision flips the phase.

### Migration phases covered

**Phase 0 — Dual-write (~1 week):**
- Set `TRANSCRIPT_SUBCOLLECTION_ENABLED=dual-write`.
- Server writes every chunk to both array and subcollection.
- Reads use array (no change in read path).
- Validate: compare `chunk_count` against `transcript_chunks.length` for drift.
- Alert if drift exceeds 0 for any session.

**Phase 1 — Dual-read (~1 week):**
- Set `TRANSCRIPT_SUBCOLLECTION_ENABLED=dual-read`.
- Writes still go to both.
- Extraction endpoint reads from subcollection, falls back to array if subcollection is empty.
- Validate: extraction produces identical profiles from both sources (sample comparison).

**Phase 2 — Subcollection only (new sessions):**
- Set `TRANSCRIPT_SUBCOLLECTION_ENABLED=true`.
- New sessions: subcollection writes only, no array.
- In-flight sessions started before the flag change: continue on their original path (determined by whether `chunk_count` field exists on the doc).
- Parent doc's `transcript_chunks` field is not written for new sessions.

## Affected Areas

- `server.js` — transcript POST handler (line ~6024), skip handler (line ~6049), state endpoints (line ~5960), extraction endpoint, section summary endpoint.
- `public/join.html` — add `chunkSeq` counter, send `seq` in POST body.
- `public/present.html` — no change (receives chunks via SSE, does not read from Firestore).
- `public/onboarding.html` — no change (reads chunks via SSE events and session state).

## Alternatives Considered

**Paginated array reads with Firestore queries on the parent doc.** Firestore does not support querying into array elements. Would require restructuring the array into a map, which still hits the 1 MiB ceiling.

**Cloud Function to offload writes.** Adds latency on the hot path (cold starts during live interviews). The subcollection approach keeps writes synchronous in the request handler with no new infrastructure.

**Client-side deduplication with UUIDs.** Each chunk gets a random UUID as its ID. Simpler but does not prevent duplicates on retry — two different UUIDs for the same speech segment. Deterministic IDs from `seq` are strictly better.
