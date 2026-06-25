// src/progressState.js

function ensureProgress(req) {
  if (!req.session.progress) {
    req.session.progress = {
      solvedCtfs: [],
      solvedLabs: [],
      xp: 0,
      launchedSandboxes: {}, // id -> expiry timestamp (ms)
    };
  }
  return req.session.progress;
}

module.exports = { ensureProgress };
