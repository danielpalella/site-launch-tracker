import { onDocumentUpdated } from 'firebase-functions/v2/firestore';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { ONBOARDING_QUESTIONS } from '../../lib/questions.js';
import { assembleArchive, writeArchiveToGCS } from '../../lib/archive.js';

if (!getApps().length) initializeApp();
const db = getFirestore();

const ARCHIVE_BUCKET = process.env.ARCHIVE_BUCKET || `${process.env.GCLOUD_PROJECT}-onboarding-archives`;

export const archiveInterview = onDocumentUpdated(
  'onboarding_interviews/{sessionId}',
  async (event) => {
    const before = event.data.before.data();
    const after = event.data.after.data();
    const sessionId = event.params.sessionId;

    // Guard: only fire when status transitions to 'extracted'
    if (before.status === after.status || after.status !== 'extracted') return;
    // Guard: don't re-archive
    if (after.archive_uri) return;

    // Read chunks — subcollection first, fall back to parent array
    let chunks;
    const subcollSnap = await db
      .collection('onboarding_interviews')
      .doc(sessionId)
      .collection('transcript_chunks')
      .orderBy('seq', 'asc')
      .get();

    if (!subcollSnap.empty) {
      chunks = subcollSnap.docs.map(d => d.data());
    } else {
      chunks = after.transcript_chunks || [];
    }

    if (chunks.length === 0) {
      console.log(`archiveInterview: no chunks for ${sessionId}, skipping`);
      return;
    }

    const sessionData = { ...after, _id: sessionId };
    const archive = assembleArchive(sessionData, chunks, ONBOARDING_QUESTIONS);
    const archiveUri = await writeArchiveToGCS(ARCHIVE_BUCKET, after.client_id, sessionId, archive);

    await event.data.after.ref.update({
      archive_uri: archiveUri,
      archived_at: FieldValue.serverTimestamp(),
    });

    console.log(`archiveInterview: archived ${sessionId} → ${archiveUri}`);
  }
);
