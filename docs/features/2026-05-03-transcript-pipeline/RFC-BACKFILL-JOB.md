---
Name: Backfill job
Summary: Cloud Run job to archive historical completed interviews to GCS and apply the 90-day chunk retention policy, with rate limiting and resumability.
Keywords: backfill, cloud-run-job, archive, gcs, retention, cleanup, rate-limit, resumable, firestore, migration
Source: docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md
Dependencies: docs/features/2026-05-03-transcript-pipeline/RFC-ARCHIVE-CLOUD-FUNCTION.md
---

# Backfill Job

## Context

The archive Cloud Function only triggers on new interview completions. Completed interviews from before the Cloud Function deployment need to be archived retroactively. After archival, chunk subcollection documents older than 90 days should be garbage-collected to reduce Firestore storage costs. See `docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md` for full motivation.

This RFC covers migration phases 3 (backfill) and 4 (cleanup) from the TRD. It depends on RFC-ARCHIVE-CLOUD-FUNCTION for the GCS bucket, archive object schemas, and IAM configuration.

## Change

### Cloud Run job

Deploy a Cloud Run job (`archive-backfill`) that processes completed interviews in batches. The job is invoked manually or via Cloud Scheduler — it is not a persistent service.

**Runtime configuration:**

| Setting | Value |
|---------|-------|
| Runtime | Node 20 |
| Memory | 1 GB |
| Timeout | 3600 seconds (1 hour) |
| Max retries | 3 |
| Parallelism | 1 (single instance to avoid Firestore contention) |
| Region | Same as Firestore |

### Backfill logic

The job queries Firestore for sessions matching:

```
status == 'extracted' AND archive_uri == null
```

Ordered by `created_at` ascending (oldest first). Processes in pages of 50 documents.

For each session:

1. **Read chunks.** If the session has a `transcript_chunks` subcollection, read from there. Otherwise fall back to the parent doc's `transcript_chunks` array (pre-migration sessions).
2. **Assemble archive.** Same logic as the Cloud Function: build `transcript.json`, `profile.json`, `manifest.json`.
3. **Write to GCS.** Same bucket and path layout: `gs://rwl-onboarding-archive/{clientId}/{sessionId}/`.
4. **Update parent doc.** Set `archive_uri` and `archived_at`.
5. **Log progress.** Structured log with `session_id`, `client_id`, `chunk_count`, `duration_ms`, `batch_index`.

### Rate limiting

- **Token bucket:** 10 sessions per minute sustained, burst of 20.
- **Inter-batch pause:** 2 seconds between batches of 50.
- **Firestore read rate:** bounded by page size (50 parent docs + their chunks per page).
- **GCS write rate:** 3 objects per session, capped at ~30 objects/minute.

### Resumability

The job is resumable across invocations:

- Each successfully archived session gets `archive_uri` set on its parent doc.
- The query filter (`archive_uri == null`) naturally skips already-processed sessions.
- If the job times out or crashes, re-running it picks up where it left off.
- No external cursor or checkpoint needed — Firestore is the checkpoint.

### Scope boundary

- **Included:** Completed sessions (`status == 'extracted'`) from the last 12 months.
- **Excluded:** Sessions older than 12 months, in-progress sessions, sessions that failed extraction.
- The 12-month boundary is a `created_at` filter, configurable via environment variable `BACKFILL_MONTHS` (default: 12).

### Chunk retention cleanup

After all backfill is complete (verified by: zero sessions matching `status == 'extracted' AND archive_uri == null` within the 12-month window), run a second pass:

1. Query sessions where `archived_at` is older than 90 days.
2. For each session, delete all documents in the `transcript_chunks` subcollection.
3. Remove the `transcript_chunks` array from the parent doc if still present.
4. Log each cleanup with `session_id` and `chunks_deleted`.

This pass uses the same rate limiting as backfill. It runs as a separate Cloud Run job execution (same job, different `BACKFILL_MODE` env var).

**Environment variable:**

| Variable | Values | Description |
|----------|--------|-------------|
| `BACKFILL_MODE` | `archive` (default), `cleanup` | `archive` runs the backfill. `cleanup` runs the retention pass. |
| `BACKFILL_MONTHS` | number (default: 12) | How far back to look for sessions to archive. |
| `BACKFILL_DRY_RUN` | `true`, `false` (default) | Log what would be done without writing. |

### Shared archive logic

The archive assembly logic (building `transcript.json`, `profile.json`, `manifest.json` from a session document and its chunks) is identical between the Cloud Function and this backfill job. Extract it into a shared module:

```
lib/archive.js
  - assembleArchive(sessionDoc, chunks) → { transcript, profile, manifest }
  - writeArchiveToGCS(bucket, clientId, sessionId, archive) → gs:// URI
```

Both the Cloud Function and the backfill job import from this module.

### Observability

- **Progress logging:** After each batch, log: `{ batch: N, processed: M, remaining: R, elapsed_ms: T }`.
- **Completion log:** When the query returns zero results, log `{ status: 'complete', total_archived: N }`.
- **Dry run output:** When `BACKFILL_DRY_RUN=true`, log each session that would be archived with its `session_id`, `client_id`, `chunk_count`, and estimated archive size.
- **Alert:** Cloud Monitoring alert if the job fails after max retries.

### Phase 4 — Code cleanup

After backfill and retention cleanup are verified complete:

1. Remove the `dual-write` and `dual-read` code paths from server.js — only the subcollection path remains.
2. Remove the `TRANSCRIPT_SUBCOLLECTION_ENABLED` environment variable.
3. Remove the `transcript_chunks` array fallback from the extraction endpoint.
4. The `transcript_chunks` field on parent docs becomes permanently unused. Existing values remain as inert data (no migration needed to remove them).

## Affected Areas

- New Cloud Run job (new directory or file, TBD alongside the Cloud Function from RFC-ARCHIVE-CLOUD-FUNCTION).
- New shared module `lib/archive.js` for archive assembly logic.
- Cloud Function from RFC-ARCHIVE-CLOUD-FUNCTION refactored to use `lib/archive.js`.
- `server.js` — removal of legacy array code paths (phase 4 only).
- GCP project — Cloud Run job deployment, optional Cloud Scheduler trigger.

## Alternatives Considered

**Trigger backfill by temporarily updating every completed session's status.** Relies on the Cloud Function to process each one. Risky — mass-updating documents could cause rate limiting, and the Cloud Function has a 120-second timeout per invocation. A dedicated job with its own rate limiting is safer and more observable.

**Skip backfill entirely and only archive new interviews going forward.** Leaves historical data without a structured archive. Since the archive enables analytics and future AI/ML pipelines, having the full history is valuable.

**Delete chunk subcollection documents immediately after archival instead of 90-day retention.** Removes the safety net for debugging or re-extraction. 90 days provides a window to catch archive issues before the source data is gone.
