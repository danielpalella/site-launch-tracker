import { Storage } from '@google-cloud/storage';

const storage = new Storage();
const SCHEMA_VERSION = 1;

/**
 * Assemble archive artifacts from session data + chunks.
 * @param {object} sessionData  — parent Firestore document data
 * @param {object[]} chunks     — ordered transcript chunks
 * @param {object[]} questions  — ONBOARDING_QUESTIONS array
 * @returns {{ transcript: object, profile: object, manifest: object }}
 */
export function assembleArchive(sessionData, chunks, questions) {
  // Group chunks by questionIndex
  const grouped = {};
  for (const c of chunks) {
    const qi = c.questionIndex ?? 0;
    if (!grouped[qi]) grouped[qi] = [];
    grouped[qi].push({
      text: c.text,
      ts: c.ts,
      source: c.source,
      skipped: c.skipped || false,
    });
  }

  // Build per-question transcript sections
  const sections = questions.map((q, idx) => ({
    questionIndex: idx,
    questionId: q.id,
    section: q.section,
    label: q.label,
    chunks: grouped[idx] || [],
  }));

  const transcript = {
    schema_version: SCHEMA_VERSION,
    session_id: sessionData._id,
    client_id: sessionData.client_id,
    client_name: sessionData.client_name,
    created_at: sessionData.created_at?.toDate?.()?.toISOString() || sessionData.created_at || null,
    sections,
    total_chunks: chunks.length,
  };

  const profile = {
    schema_version: SCHEMA_VERSION,
    session_id: sessionData._id,
    client_id: sessionData.client_id,
    client_name: sessionData.client_name,
    extracted_profile: sessionData.extracted_profile || null,
    answers: sessionData.answers || {},
    skipped: sessionData.skipped || [],
  };

  const manifest = {
    schema_version: SCHEMA_VERSION,
    session_id: sessionData._id,
    archived_at: new Date().toISOString(),
    files: ['transcript.json', 'profile.json', 'manifest.json'],
    chunk_count: chunks.length,
    question_count: questions.length,
    status: sessionData.status,
  };

  return { transcript, profile, manifest };
}

/**
 * Write archive files to a GCS bucket.
 * @param {string} bucketName
 * @param {string} clientId
 * @param {string} sessionId
 * @param {{ transcript: object, profile: object, manifest: object }} archive
 * @returns {Promise<string>} gs:// URI prefix
 */
export async function writeArchiveToGCS(bucketName, clientId, sessionId, archive) {
  const bucket = storage.bucket(bucketName);
  const prefix = `onboarding-archives/${clientId || '_no_client'}/${sessionId}`;

  const writes = Object.entries(archive).map(([name, data]) => {
    const file = bucket.file(`${prefix}/${name}.json`);
    return file.save(JSON.stringify(data, null, 2), {
      contentType: 'application/json',
      resumable: false,
    });
  });

  await Promise.all(writes);
  return `gs://${bucketName}/${prefix}`;
}
