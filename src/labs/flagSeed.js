// src/labs/flagSeed.js
// Server-only helper: pulls plaintext flags purely to seed the REAL
// vulnerable lab apps' own databases/cookies. Never exposed via any route
// directly — only retrievable by actually exploiting the lab.
const fs = require("fs");
const path = require("path");

const data = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "data", "extracted-flags.private.json"), "utf8")
);
const map = {};
for (const { id, flag } of data) map[id] = flag;

function getRawFlagForSeeding(id) {
  if (!map[id]) throw new Error(`No flag found to seed lab for id: ${id}`);
  return map[id];
}

module.exports = { getRawFlagForSeeding };
