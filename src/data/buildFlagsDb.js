// src/data/buildFlagsDb.js
//
// One-time build script: takes the plaintext flags extracted from the
// original script.js (extracted-flags.json, kept OUTSIDE the public/
// folder and never served) and writes a hashed flags database that the
// running server actually reads from.
//
// Run with: node src/data/buildFlagsDb.js
//
// Why hash instead of just keeping plaintext server-side? Defense in depth.
// If the flags.db.json file is ever accidentally exposed (misconfigured
// static route, backup leak, etc.) the hashes alone aren't directly
// reusable as flags. Submission still works because we hash whatever the
// player types and compare hashes.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PEPPER = process.env.FLAG_PEPPER || "sp-dev-pepper-change-me";

function hashFlag(flag) {
  return crypto.createHash("sha256").update(PEPPER + ":" + flag).digest("hex");
}

const sourcePath = path.join(__dirname, "extracted-flags.private.json");
const outPath = path.join(__dirname, "flags.db.json");

const raw = JSON.parse(fs.readFileSync(sourcePath, "utf8"));

const db = {};
for (const { id, flag, xp } of raw) {
  db[id] = { hash: hashFlag(flag), xp };
}

fs.writeFileSync(outPath, JSON.stringify(db, null, 2));
console.log(`Built ${Object.keys(db).length} hashed flag entries -> ${outPath}`);
