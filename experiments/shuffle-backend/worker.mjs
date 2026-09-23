import init, * as wasm from "./pkg/shuffle_backend_evaluation.js";

self.onmessage = async ({ data: { nativeFixtures, adapterInputs, candidateCrs, candidateTranscript, proofCodecInputs } }) => {
  try {
    await init();
    const crsVectors = candidateCrs ? JSON.parse(wasm.evaluate_crs_vectors()) : null;
    const transcriptVectors = candidateTranscript ? JSON.parse(wasm.evaluate_transcript_vectors()) : null;
    const proofCodecResults = (proofCodecInputs ?? []).map((bytes) => {
      try { return { accepted: true, bytes: Array.from(wasm.roundtrip_candidate_proof36(new Uint8Array(bytes))) }; }
      catch { return { accepted: false, bytes: null }; }
    });
    const adapterResults = adapterInputs === null ? null
      : JSON.parse(wasm.evaluate_adapter_vectors(JSON.stringify(adapterInputs)));
    const results = [];
    for (const native of nativeFixtures) {
      const { rows, cols, initial_identity_a: initial } = native.report;
      const started = performance.now();
      const nativeReport = JSON.parse(wasm.evaluate_fixture(new Uint8Array(native.fixture)));
      const nativeAssessMs = performance.now() - started;
      const proveStarted = performance.now();
      const fixture = wasm.generate_fixture(rows, cols, initial);
      const prepareAndProveMs = performance.now() - proveStarted;
      const assessStarted = performance.now();
      const report = JSON.parse(wasm.evaluate_fixture(fixture));
      const assessMs = performance.now() - assessStarted;
      results.push({
        proof_wire: candidateCrs ? Array.from(wasm.candidate_proof_from_fixture(fixture)) : null,
        native_proof_wire: candidateCrs ? Array.from(wasm.candidate_proof_from_fixture(new Uint8Array(native.fixture))) : null,
        native_report: nativeReport,
        native_assess_ms: nativeAssessMs,
        fixture: Array.from(fixture),
        report,
        prepare_and_prove_ms: prepareAndProveMs,
        assess_ms: assessMs,
      });
    }
    self.postMessage({ results, adapterResults, crsVectors, transcriptVectors, proofCodecResults, userAgent: navigator.userAgent });
  } catch (error) {
    self.postMessage({ error: String(error), stack: error?.stack });
  }
};
