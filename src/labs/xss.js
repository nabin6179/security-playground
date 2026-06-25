// src/labs/xss.js
//
// A REAL, working stored-XSS-vulnerable mini-app. Feedback comments are
// stored and rendered back WITHOUT any escaping. If you submit a payload
// that runs JavaScript, it will genuinely execute in whatever browser tab
// loads the admin page — including stealing the real admin cookie, which
// is intentionally not HttpOnly so the exfiltration actually works.
//
// Deliberately vulnerable. Real fix: escape output (or use a templating
// engine that auto-escapes) and set the session cookie HttpOnly.

const express = require("express");
const cookieParser = require("cookie-parser");
const { getRawFlagForSeeding } = require("./flagSeed");

const router = express.Router();
router.use(cookieParser());
router.use(express.urlencoded({ extended: true }));

const ADMIN_FLAG = getRawFlagForSeeding("xss-ctf");

let feedback = [
  { author: "system", comment: "Welcome to CyberBlog! Leave us your feedback below." },
];
let exfilLog = [];

router.get("/", (req, res) => {
  res.send(renderPublicPage());
});

// VULNERABLE: stores raw HTML with zero sanitization.
router.post("/feedback", (req, res) => {
  const comment = (req.body.comment || "").slice(0, 500);
  const author = (req.body.author || "guest").slice(0, 50);
  feedback.push({ author, comment });
  res.redirect("/labs/xss/");
});

// The "admin" page. Sets a real, readable (not HttpOnly) cookie and
// renders every stored comment UNESCAPED. Open this in a tab after
// submitting a payload to see whether it fires.
router.get("/admin", (req, res) => {
  res.cookie("admin_session", ADMIN_FLAG, { httpOnly: false, sameSite: "lax" });
  res.send(renderAdminPage());
});

// Exfiltration sink — a script payload can fetch() the victim's cookie
// here. This is what a real attacker-controlled logging endpoint looks like.
router.get("/collect", (req, res) => {
  exfilLog.push({ at: new Date().toISOString(), cookie: req.query.cookie || "(none)" });
  res.json({ ok: true });
});

router.get("/logs", (req, res) => {
  res.json({ logs: exfilLog });
});

function escapeHtmlAttr(str) {
  return String(str).replace(/"/g, "&quot;");
}

function renderPublicPage() {
  const items = feedback
    .map(
      // INTENTIONALLY UNESCAPED — this is the vulnerability.
      (f) => `<div class="comment"><strong>${f.author}</strong>: ${f.comment}</div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CyberBlog — Feedback</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#0f1117; color:#e5e7eb; padding:32px; max-width:760px; margin:0 auto;}
    h1 { color:#8b5cf6; }
    textarea, input[type=text] { width:100%; padding:8px; border-radius:6px; border:1px solid #333; background:#1a1d27; color:#fff; margin-bottom:8px; box-sizing:border-box;}
    button { padding:8px 16px; border-radius:6px; border:none; background:#3b82f6; color:#fff; cursor:pointer; }
    .comment { border-bottom:1px solid #333; padding:10px 0; }
    .hint { color:#9ca3af; font-size:13px; margin-top:24px; }
    a { color:#60a5fa; }
  </style>
</head>
<body>
  <h1>📝 CyberBlog Feedback Wall</h1>
  <p>Comments are stored and displayed with zero output sanitization — this is a real, deliberately vulnerable app.</p>
  <form method="post" action="/labs/xss/feedback">
    <input type="text" name="author" placeholder="Your name" value="">
    <textarea name="comment" rows="3" placeholder="Your feedback..."></textarea>
    <button type="submit">Post Feedback</button>
  </form>
  <h3>Recent Feedback</h3>
  ${items}
  <p class="hint">
    There's an admin who periodically reviews <a href="/labs/xss/admin" target="_blank">the admin dashboard</a> with a privileged session cookie.
    A logging endpoint is exposed at <code>/labs/xss/collect?cookie=...</code>. After your payload fires, check
    <a href="/labs/xss/logs" target="_blank">/labs/xss/logs</a> for anything captured.
  </p>
</body>
</html>`;
}

function renderAdminPage() {
  const items = feedback
    .map(
      // INTENTIONALLY UNESCAPED — admin views render raw HTML/JS too.
      (f) => `<div class="comment"><strong>${f.author}</strong>: ${f.comment}</div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CyberBlog — Admin Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#1e1b2e; color:#e5e7eb; padding:32px; max-width:760px; margin:0 auto;}
    h1 { color:#10b981; }
    .comment { border-bottom:1px solid #333; padding:10px 0; }
    .badge { background:#10b981; color:#0f1117; padding:2px 8px; border-radius:4px; font-size:12px;}
  </style>
</head>
<body>
  <h1>🛠 Admin Dashboard <span class="badge">privileged session</span></h1>
  <p>You are viewing this page as an authenticated administrator with a real session cookie (<code>admin_session</code>).</p>
  <h3>Moderate Feedback</h3>
  ${items}
</body>
</html>`;
}

module.exports = router;
