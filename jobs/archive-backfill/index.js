import { initializeApp, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { ONBOARDING_QUESTIONS } from '../../lib/questions.js';
import { assembleArchive, writeArchiveToGCS } from '../../lib/archive.js';

if (!getApps().length) initializeApp();
const db = getFirestore();

const ARCHIVE_BUCKET = process.env.ARCHIVE_BUCKET || `${process.env.GCLOUD_PROJECT}-onboarding-archives`;
const BACKFILL_MODE = process.env.BACKFILL_MODE || 'archive';  // 'archive' | 'cleanup'
const DRY_RUN = process.env.BACKFILL_DRY_RUN === 'true';
const PAGE_SIZE = 50;
const RATE_LIMIT_MS = 6000; // ~10 per minute

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function readChunks(sessionId) {
  const subcollSnap = await db
    .collection('onboarding_interviews')
    .doc(sessionId)
    .collection('transcript_chunks')
    .orderBy('seq', 'asc')
    .get();
  if (!subcollSnap.empty) return subcollSnap.docs.map(d => d.data());
  const parent = await db.collection('onboarding_interviews').doc(sessionId).get();
  return parent.data()?.transcript_chunks || [];
}

async function archiveMode() {
  console.log(`[backfill] mode=archive dry_run=${DRY_RUN}`);
  let processed = 0;
  let lastDoc = null;

  while (true) {
    let query = db.collection('onboarding_interviews')
      .where('status', '==', 'extracted')
      .where('archive_uri', '==', null)
      .limit(PAGE_SIZE);

    if (lastDoc) query = query.startAfter(lastDoc);
    const snap = await query.get();
    if (snap.empty) break;

    for (const doc of snap.docs) {
      const sessionId = doc.id;
      const data = doc.data();
      const chunks = await readChunks(sessionId);

      if (chunks.length === 0) {
        console.log(`  [skip] ${sessionId}: no chunks`);
        continue;
      }

      if (DRY_RUN) {
        console.log(`  [dry-run] would archive ${sessionId} (${chunks.length} chunks)`);
      } else {
        const sessionData = { ...data, _id: sessionId };
        const archive = assembleArchive(sessionData, chunks, ONBOARDING_QUESTIONS);
        const uri = await writeArchiveToGCS(ARCHIVE_BUCKET, data.client_id, sessionId, archive);
        await doc.ref.update({
          archive_uri: uri,
          archived_at: FieldValue.serverTimestamp(),
        });
        console.log(`  [archived] ${sessionId} → ${uri}`);
      }

      processed++;
      await sleep(RATE_LIMIT_MS);
    }

    lastDoc = snap.docs[snap.docs.length - 1];
  }

  console.log(`[backfill] archive complete. processed=${processed}`);
}

async function cleanupMode() {
  console.log(`[backfill] mode=cleanup dry_run=${DRY_RUN}`);
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  let processed = 0;
  let lastDoc = null;

  while (true) {
    let query = db.collection('onboarding_interviews')
      .where('archived_at', '<=', cutoff)
      .limit(PAGE_SIZE);

    if (lastDoc) query = query.startAfter(lastDoc);
    const snap = await query.get();
    if (snap.empty) break;

    for (const doc of snap.docs) {
      const sessionId = doc.id;

      if (DRY_RUN) {
        console.log(`  [dry-run] would clean up ${sessionId}`);
      } else {
        // Delete subcollection docs in batches
        const subSnap = await doc.ref.collection('transcript_chunks').get();
        const batch = db.batch();
        for (const sub of subSnap.docs) batch.delete(sub.ref);
        if (!subSnap.empty) await batch.commit();

        // Remove array field from parent
        await doc.ref.update({ transcript_chunks: FieldValue.delete() });
        console.log(`  [cleaned] ${sessionId}: removed ${subSnap.size} subcoll docs + array`);
      }

      processed++;
      await sleep(RATE_LIMIT_MS);
    }

    lastDoc = snap.docs[snap.docs.length - 1];
  }

  console.log(`[backfill] cleanup complete. processed=${processed}`);
}

(async () => {
  try {
    if (BACKFILL_MODE === 'cleanup') await cleanupMode();
    else await archiveMode();
    process.exit(0);
  } catch (err) {
    console.error('[backfill] fatal error:', err);
    process.exit(1);
  }
})();
