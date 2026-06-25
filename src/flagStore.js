// src/flagStore.js
//
// Single source of truth for flag verification. Nothing in this module
// is ever sent to the browser as-is — only true/false (submit) or a
// flag string gated behind a "launched" check (reveal).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PEPPER = process.env.FLAG_PEPPER || "sp-dev-pepper-change-me";
const DB_PATH = path.join(__dirname, "data", "flags.db.json");
const PRIVATE_PATH = path.join(__dirname, "data", "extracted-flags.private.json");

const hashedDb = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
// Plaintext only ever lives in server memory, loaded once at boot, for the
// /api/reveal endpoint (used by the simulated, non-real labs to render the
// "captured" value in the fake browser/devtools UI once a player triggers it).
const plainDb = {};
for (const { id, flag } of JSON.parse(fs.readFileSync(PRIVATE_PATH, "utf8"))) {
  plainDb[id] = flag;
}

function hashFlag(value) {
  return crypto.createHash("sha256").update(PEPPER + ":" + value).digest("hex");
}

function timingSafeEqualHex(a, b) {
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function challengeExists(id) {
  return Object.prototype.hasOwnProperty.call(hashedDb, id);
}

function xpFor(id) {
  return hashedDb[id] ? hashedDb[id].xp : 0;
}

// Returns true/false only. Never leaks the real flag.
function checkSubmission(id, submittedValue) {
  const entry = hashedDb[id];
  if (!entry || typeof submittedValue !== "string") return false;
  const normalized = submittedValue.trim();
  if (!normalized) return false;
  return timingSafeEqualHex(hashFlag(normalized), entry.hash);
}

// Only call this after confirming the session "launched" this challenge's
// sandbox. Used solely to drive the simulated reveal UI.
function getPlainFlag(id) {
  return plainDb[id] || null;
}

module.exports = { challengeExists, xpFor, checkSubmission, getPlainFlag };
