// RealWork Onboarding Audio Capture Extension
// Captures Meet tab audio and streams it to the transcription server

let activeStream = null;
let activeWs = null;
let audioContext = null;
let processor = null;

// Listen for messages from the Meet add-on sidebar (externally_connectable)
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log('[rw-ext] Received message:', message.type);

  if (message.type === 'start-capture') {
    startCapture(message.token, message.serverUrl)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // async response
  }

  if (message.type === 'stop-capture') {
    stopCapture();
    sendResponse({ ok: true });
  }

  if (message.type === 'ping') {
    sendResponse({ ok: true, active: !!activeStream });
  }
});

async function startCapture(token, serverUrl) {
  // Stop any existing capture
  stopCapture();

  // Get the active tab (should be the Meet tab)
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) throw new Error('No active tab found');
  if (!tab.url?.includes('meet.google.com')) throw new Error('Active tab is not Google Meet');

  console.log('[rw-ext] Capturing tab:', tab.id, tab.url);

  // Capture the tab's audio
  const streamId = await new Promise((resolve, reject) => {
    chrome.tabCapture.capture(
      { audio: true, video: false },
      (stream) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!stream) {
          reject(new Error('Failed to capture tab audio'));
          return;
        }
        resolve(stream);
      }
    );
  });

  activeStream = streamId;

  // Create AudioContext to process the audio
  audioContext = new AudioContext({ sampleRate: 16000 });
  const source = audioContext.createMediaStreamSource(activeStream);

  // ScriptProcessor to extract PCM Int16 chunks
  processor = audioContext.createScriptProcessor(4096, 1, 1);
  processor.onaudioprocess = (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return;
    const float32 = e.inputBuffer.getChannelData(0);
    const int16 = new Int16Array(float32.length);
    for (let i = 0; i < float32.length; i++) {
      int16[i] = Math.max(-32768, Math.min(32767, Math.round(float32[i] * 32768)));
    }
    activeWs.send(int16.buffer);
  };

  source.connect(processor);
  processor.connect(audioContext.destination);

  // Connect WebSocket to the transcription server
  const wsUrl = serverUrl.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws/transcribe';
  activeWs = new WebSocket(wsUrl);

  activeWs.onopen = () => {
    console.log('[rw-ext] WebSocket connected');
    // Authenticate
    activeWs.send(JSON.stringify({ type: 'auth', token }));
  };

  activeWs.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'auth_ok') {
        console.log('[rw-ext] Authenticated, streaming audio...');
        // Notify the sidebar that capture is active
        broadcastToSidebar({ type: 'capture-started' });
      } else if (msg.type === 'transcript') {
        // Forward transcript to the sidebar
        broadcastToSidebar({ type: 'transcript', text: msg.text, isFinal: msg.isFinal });
      } else if (msg.type === 'error') {
        console.error('[rw-ext] Server error:', msg.message);
        broadcastToSidebar({ type: 'error', message: msg.message });
      }
    } catch {}
  };

  activeWs.onclose = (evt) => {
    console.log('[rw-ext] WebSocket closed:', evt.code, evt.reason);
    broadcastToSidebar({ type: 'stopped', code: evt.code });
  };

  activeWs.onerror = () => {
    console.error('[rw-ext] WebSocket error');
    broadcastToSidebar({ type: 'error', message: 'WebSocket connection failed' });
  };

  // Monitor the audio stream for ending (tab closed, etc.)
  activeStream.getAudioTracks()[0]?.addEventListener('ended', () => {
    console.log('[rw-ext] Audio track ended');
    stopCapture();
    broadcastToSidebar({ type: 'stopped' });
  });

  console.log('[rw-ext] Capture started');
}

function stopCapture() {
  if (processor) {
    try { processor.disconnect(); } catch {}
    processor = null;
  }
  if (audioContext) {
    try { audioContext.close(); } catch {}
    audioContext = null;
  }
  if (activeStream) {
    try { activeStream.getTracks().forEach(t => t.stop()); } catch {}
    activeStream = null;
  }
  if (activeWs) {
    try { activeWs.close(); } catch {}
    activeWs = null;
  }
  console.log('[rw-ext] Capture stopped');
}

// Broadcast messages to any connected tabs from our app
function broadcastToSidebar(msg) {
  // Send to all tabs that match our app URL (the Meet sidebar iframe)
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.url?.includes('meet.google.com')) {
        // The sidebar is inside Meet — we can't message it directly
        // Instead, use a shared BroadcastChannel approach via an offscreen document
        // For now, store the message and let the sidebar poll for it
      }
    });
  });

  // Store latest transcript in chrome.storage.session for the sidebar to poll
  if (msg.type === 'transcript') {
    chrome.storage.session.get('transcriptBuffer', (result) => {
      const buffer = result.transcriptBuffer || [];
      buffer.push(msg);
      // Keep last 100 entries
      if (buffer.length > 100) buffer.splice(0, buffer.length - 100);
      chrome.storage.session.set({ transcriptBuffer: buffer });
    });
  } else {
    chrome.storage.session.set({ extensionStatus: msg });
  }
}
