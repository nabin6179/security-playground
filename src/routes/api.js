// src/routes/api.js
const express = require("express");
const rateLimit = require("express-rate-limit");
const { challengeExists, xpFor, checkSubmission, getPlainFlag } = require("../flagStore");
const { ensureProgress } = require("../progressState");

const router = express.Router();

// Slow down brute-forcing of flag submissions and reveal probing.
const submitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Slow down and try again shortly." },
});

const revealLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many reveal requests. Slow down." },
});

const LAUNCH_TTL_MS = 1000 * 60 * 30; // a launched sandbox stays "active" 30 min

// ---------------------------------------------------------------------------
// GET /api/progress  -> current session's solved challenges, xp (never flags)
// ---------------------------------------------------------------------------
router.get("/progress", (req, res) => {
  const progress = ensureProgress(req);
  res.json({
    solvedCtfs: progress.solvedCtfs,
    solvedLabs: progress.solvedLabs,
    xp: progress.xp,
  });
});

// ---------------------------------------------------------------------------
// POST /api/sandbox/:id/launch -> marks a challenge as "in progress" for this
// session. Required before /api/reveal/:id will release anything. This is
// NOT a substitute for real exploit verification (the simulated labs check
// their fake conditions purely client-side) — it just means a player has to
// at minimum open the relevant sandbox before they can pull a flag, rather
// than being able to fetch every flag in one shot with no interaction at all.
// ---------------------------------------------------------------------------
router.post("/sandbox/:id/launch", (req, res) => {
  const { id } = req.params;
  if (!challengeExists(id)) return res.status(404).json({ error: "Unknown challenge" });
  const progress = ensureProgress(req);
  progress.launchedSandboxes[id] = Date.now() + LAUNCH_TTL_MS;
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /api/reveal/:id -> used ONLY by the simulated (non-real) labs to
// render the "captured" flag text in the fake browser/devtools once the
// player triggers the matching fake condition client-side. Gated behind
// having launched the sandbox, plus rate limited.
// ---------------------------------------------------------------------------
router.get("/reveal/:id", revealLimiter, (req, res) => {
  const { id } = req.params;
  if (!challengeExists(id)) return res.status(404).json({ error: "Unknown challenge" });

  const progress = ensureProgress(req);
  const expiry = progress.launchedSandboxes[id];
  if (!expiry || expiry < Date.now()) {
    return res.status(403).json({ error: "Launch this sandbox first." });
  }

  const flag = getPlainFlag(id);
  if (!flag) return res.status(404).json({ error: "No flag for this challenge" });
  res.json({ flag });
});

// ---------------------------------------------------------------------------
// POST /api/submit-flag { id, value } -> the ONLY place "solved" is decided.
// ---------------------------------------------------------------------------
router.post("/submit-flag", submitLimiter, (req, res) => {
  const { id, value } = req.body || {};
  if (typeof id !== "string" || typeof value !== "string") {
    return res.status(400).json({ error: "Missing id or value" });
  }
  if (!challengeExists(id)) return res.status(404).json({ error: "Unknown challenge" });

  const progress = ensureProgress(req);
  const alreadySolved = progress.solvedCtfs.includes(id) || progress.solvedLabs.includes(id);

  const correct = checkSubmission(id, value);
  if (!correct) {
    return res.json({ correct: false });
  }

  let xpAwarded = 0;
  if (!alreadySolved) {
    progress.solvedCtfs.push(id);
    xpAwarded = xpFor(id);
    progress.xp += xpAwarded;
  }

  res.json({
    correct: true,
    alreadySolved,
    xpAwarded,
    totalXp: progress.xp,
  });
});

module.exports = router;
