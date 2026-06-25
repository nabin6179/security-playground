// src/labs/sqli.js
//
// A REAL, working SQL-injection-vulnerable mini-app. This is not a
// simulation: it runs an actual SQLite query built via raw string
// concatenation, and a correctly crafted UNION payload genuinely returns
// rows from a real "secret_flags" table.
//
// Deliberately vulnerable. Do not copy this query-building pattern into
// real applications — see the parameterized version in the comment below
// for what the fix looks like.

const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const { getRawFlagForSeeding } = require("./flagSeed");

const router = express.Router();
const db = new DatabaseSync(":memory:");

db.exec(`
  CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT);
  CREATE TABLE secret_flags (id INTEGER PRIMARY KEY, flag_token TEXT);
`);

const seedProducts = db.prepare("INSERT INTO products (name, price) VALUES (?, ?)");
[
  ["Wireless Mouse", "$19.99"],
  ["Mechanical Keyboard", "$59.99"],
  ["USB-C Hub", "$24.99"],
  ["4K Webcam", "$45.00"],
  ["Noise Cancelling Headphones", "$89.00"],
].forEach((row) => seedProducts.run(...row));

db.prepare("INSERT INTO secret_flags (flag_token) VALUES (?)").run(
  getRawFlagForSeeding("sqli-ctf")
);

router.get("/", (req, res) => {
  res.send(renderPage(""));
});

// VULNERABLE: raw string concatenation, no parameterization, no input
// validation. A query like:
//   ' UNION SELECT 1, flag_token FROM secret_flags --
// will be appended directly into the SQL text and executed as-is.
router.get("/search", (req, res) => {
  const q = req.query.q || "";
  const sql = `SELECT name, price FROM products WHERE name LIKE '%${q}%'`;

  let rows = [];
  let errorMessage = null;
  try {
    rows = db.prepare(sql).all();
  } catch (err) {
    errorMessage = err.message;
  }

  res.send(renderPage(q, rows, sql, errorMessage));
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderPage(q, rows = [], sql = "", errorMessage = null) {
  const rowsHtml = rows
    .map(
      (r) => `<tr><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.price)}</td></tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VulnShop — Product Search</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#0f1117; color:#e5e7eb; padding:32px; max-width:760px; margin:0 auto;}
    h1 { color:#8b5cf6; }
    input[type=text] { width:60%; padding:8px; border-radius:6px; border:1px solid #333; background:#1a1d27; color:#fff; }
    button { padding:8px 16px; border-radius:6px; border:none; background:#3b82f6; color:#fff; cursor:pointer; }
    table { width:100%; border-collapse: collapse; margin-top:16px; }
    td, th { padding:8px; border-bottom:1px solid #333; text-align:left; }
    .sql-debug { margin-top:20px; font-family:monospace; font-size:12px; color:#888; background:#1a1d27; padding:10px; border-radius:6px; white-space: pre-wrap; word-break: break-all;}
    .error { color:#f87171; margin-top:12px; }
    .hint { color:#9ca3af; font-size:13px; margin-top:24px; }
  </style>
</head>
<body>
  <h1>🛒 VulnShop Product Search</h1>
  <p>This is a real, deliberately vulnerable app — no simulation. The search box below builds a SQL query with raw string concatenation.</p>
  <form method="get" action="/labs/sqli/search">
    <input type="text" name="q" value="${escapeHtml(q)}" placeholder="Search products...">
    <button type="submit">Search</button>
  </form>
  ${rows.length ? `<table><tr><th>Name</th><th>Price</th></tr>${rowsHtml}</table>` : ""}
  ${errorMessage ? `<p class="error">SQL Error: ${escapeHtml(errorMessage)}</p>` : ""}
  ${sql ? `<div class="sql-debug">Executed query (debug mode left on — also a vuln!):<br>${escapeHtml(sql)}</div>` : ""}
  <p class="hint">There's a hidden table called <code>secret_flags</code> with a column <code>flag_token</code>. Can you get the search query to return data from it?</p>
</body>
</html>`;
}

module.exports = router;
