// AudioWorklet processor: captures PCM audio, downsamples to 16kHz mono Int16
// Runs on the audio rendering thread (not the main thread)

class PCMWorkletProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this._buffer = [];
    this._chunkSize = 1600; // 100ms at 16kHz
  }

  process(inputs) {
    const input = inputs[0];
    if (!input || !input.length) return true;

    const channelData = input[0]; // mono
    if (!channelData) return true;

    // The AudioContext sampleRate may not be exactly 16kHz.
    // If it is (because we requested 16kHz), just convert directly.
    // If not, we'd need to resample — but we request 16kHz in the AudioContext.
    for (let i = 0; i < channelData.length; i++) {
      // Convert float32 [-1, 1] to Int16 [-32768, 32767]
      const s = Math.max(-1, Math.min(1, channelData[i]));
      this._buffer.push(s < 0 ? s * 32768 : s * 32767);
    }

    // Compute RMS level for the level meter
    let sum = 0;
    for (let i = 0; i < channelData.length; i++) {
      sum += channelData[i] * channelData[i];
    }
    const rms = Math.sqrt(sum / channelData.length);

    // When buffer reaches chunk size, post it to the main thread
    while (this._buffer.length >= this._chunkSize) {
      const chunk = this._buffer.splice(0, this._chunkSize);
      const int16 = new Int16Array(chunk.length);
      for (let i = 0; i < chunk.length; i++) {
        int16[i] = Math.round(chunk[i]);
      }
      this.port.postMessage({ type: 'audio', buffer: int16.buffer, level: rms }, [int16.buffer]);
    }

    return true; // keep processing
  }
}

registerProcessor('pcm-worklet-processor', PCMWorkletProcessor);
