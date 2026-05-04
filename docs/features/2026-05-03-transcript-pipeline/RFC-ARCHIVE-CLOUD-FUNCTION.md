---
Name: Archive Cloud Function
Summary: Deploy a Firestore document trigger Cloud Function that assembles completed interview transcripts into a canonical archive on GCS with signed-URL read access.
Keywords: cloud-function, gcs, archive, firestore-trigger, transcript, profile, signed-url, iam, bucket, onboarding
Source: docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md
Dependencies: docs/features/2026-05-03-transcript-pipeline/RFC-CHUNK-SUBCOLLECTION.md
---

# Archive Cloud Function

## Context

After an interview completes and the profile is extracted, the full transcript, profile, and session metadata need to be archived to a durable, programmatically accessible store. The current system only writes to Google Drive (human-readable) and retains operational data in Firestore. There is no structured archive suitable for analytics or downstream services. See `docs/features/2026-05-03-transcript-pipeline/TRD-TRANSCRIPT-PIPELINE.md` for full motivation.

This RFC depends on RFC-CHUNK-SUBCOLLECTION — the Cloud Function reads chunks from the subcollection, not the parent array.

## Change

### Cloud Function trigger

Deploy a 2nd-gen Cloud Function with a Firestore document trigger on `onboarding_interviews/{sessionId}`. The function fires on document updates and checks:

1. `status` changed to `'extracted'`.
2. `archive_uri` is not already set (prevents re-archival on subsequent updates).

If both conditions are met, the function proceeds with archival. Otherwise it returns early.

**Runtime configuration:**

| Setting | Value |
|---------|-------|
| Runtime | Node 20 |
| Memory | 512 MB |
| Timeout | 120 seconds |
| Region | Same as Firestore |
| Trigger | Firestore document update on `onboarding_interviews/{sessionId}` |
| Retry | Enabled (at-least-once delivery) |
| Service account | Dedicated SA with Firestore read + GCS write |

### Archive assembly

When triggered, the function:

1. **Read session document** — extract `client_id`, `client_name`, `answers`, `extracted_profile`, `completed_summaries`, `created_at`, `updated_at`.
2. **Read chunks subcollection** — `orderBy('seq', 'asc')`, paginate in batches of 500 to handle large interviews.
3. **Build transcript.json** — group chunks by `questionIndex`, attach to the corresponding question from the `ONBOARDING_QUESTIONS` array. Include the answer, section, label, and skip status for each question.
4. **Build profile.json** — the `extracted_profile` object as-is.
5. **Build manifest.json** — session metadata: `session_id`, `client_id`, `client_name`, `started_at`, `completed_at`, `chunk_count`, `question_count`, `sections_completed`, `archive_created_at`, `schema_version: 1`.

### Archive object schemas

**transcript.json:**

```json
{
  "schema_version": 1,
  "session_id": "abc123",
  "client_id": "def456",
  "client_name": "Acme Plumbing",
  "started_at": "2026-05-03T10:00:00Z",
  "completed_at": "2026-05-03T10:35:00Z",
  "questions": [
    {
      "question_id": "origin_1",
      "section": "Origin Story",
      "label": "Tell us your story...",
      "answer": "We started in 2008...",
      "skipped": false,
      "chunks": [
        { "seq": 0, "ts": "2026-05-03T10:02:15Z", "text": "So we started..." },
        { "seq": 1, "ts": "2026-05-03T10:02:28Z", "text": "back in 2008..." }
      ]
    }
  ],
  "section_summaries": [
    {
      "section_name": "Origin Story",
      "section_index": 0,
      "narrative": "...",
      "unlocks": ["..."]
    }
  ]
}
```

**profile.json:** The `extracted_profile` object verbatim.

**manifest.json:**

```json
{
  "schema_version": 1,
  "session_id": "abc123",
  "client_id": "def456",
  "client_name": "Acme Plumbing",
  "started_at": "2026-05-03T10:00:00Z",
  "completed_at": "2026-05-03T10:35:00Z",
  "chunk_count": 47,
  "question_count": 17,
  "sections_completed": 7,
  "archive_created_at": "2026-05-03T10:36:02Z"
}
```

### GCS bucket configuration

**Bucket name:** `rwl-onboarding-archive`

| Setting | Value |
|---------|-------|
| Location | Same region as Firestore |
| Storage class | Standard |
| Access control | Uniform bucket-level access |
| Public access | Prevented (enforced) |
| Object versioning | Enabled |
| Soft delete | 30 days |
| Lifecycle rule | None (archives are permanent) |

**Object layout:**

```
gs://rwl-onboarding-archive/
  {clientId}/
    {sessionId}/
      transcript.json
      profile.json
      manifest.json
```

### IAM and access

- **Cloud Function service account:** `roles/datastore.viewer` (Firestore read), `roles/storage.objectCreator` (GCS write), custom role for Firestore update on `archive_uri` field only.
- **Application service account (Cloud Run):** `roles/storage.objectViewer` for signed-URL generation.
- **No public access.** All reads go through signed URLs generated server-side.

### Signed-URL read access

Add a new endpoint to server.js for generating signed URLs:

```
GET /api/onboarding/sessions/:id/archive-url?file=transcript.json
```

- Requires `requireAuth`.
- Reads `archive_uri` from the session document.
- Generates a signed URL with 15-minute expiry using the Cloud Run service account.
- Returns `{ url: "https://storage.googleapis.com/..." }`.

### Parent document updates

After successful GCS writes, the Cloud Function updates the parent document:

| Field | Value |
|-------|-------|
| `archive_uri` | `gs://rwl-onboarding-archive/{clientId}/{sessionId}/` |
| `archived_at` | Server timestamp |

The `archive_uri` field also serves as the idempotency guard — if it is already set, the function skips archival on subsequent triggers.

### Error handling

- **Chunk read failure:** Log error, do not write partial archive, allow retry.
- **GCS write failure:** Log error, allow retry. Manifest is written last — its absence indicates incomplete archival.
- **Parent doc update failure:** Log error, allow retry. The GCS objects are already written; the next trigger will see `archive_uri` is missing and re-run (idempotent since GCS overwrites are atomic per object).
- **DLQ:** Configure Cloud Functions retry with exponential backoff. After max retries, the failed event lands in Cloud Logging with `severity=ERROR`.

### Observability

- Cloud Logging: structured logs with `session_id`, `client_id`, `chunk_count`, `duration_ms`.
- Alert: Cloud Monitoring alert on `severity=ERROR` logs from the function.
- Dashboard metric: count of sessions where `status = 'extracted'` but `archive_uri` is null for more than 5 minutes.

## Affected Areas

- New Cloud Function project/directory (to be determined — could live alongside server.js or in a separate `functions/` directory).
- `server.js` — new `/api/onboarding/sessions/:id/archive-url` endpoint.
- GCP project — new GCS bucket, new Cloud Function deployment, IAM bindings.
- No frontend changes.

## Alternatives Considered

**Archive in the same request handler as extraction.** Keeps everything in server.js but makes the extraction endpoint slower (GCS writes add latency to the user-facing response). The contractor and rep are waiting for the completion screen — archival should not block it.

**Cloud Run job instead of Cloud Function.** Cloud Run jobs are better for batch work (backfill). For single-document event-driven triggers, Cloud Functions are the natural fit — no polling, no scheduler, built-in retry.

**Write a single combined archive file instead of three.** A single file is simpler but harder to consume selectively. Analysts wanting just profiles should not need to download full transcripts. Three files with a manifest allows targeted access.
