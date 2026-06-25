// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");

const sessionMiddleware = require("./src/session");
const apiRouter = require("./src/routes/api");
const sqliLab = require("./src/labs/sqli");
const xssLab = require("./src/labs/xss");

const app = express();
const PORT = process.env.PORT || 3000;

// Make sure the session store's directory exists.
fs.mkdirSync(path.join(__dirname, "data", "sessions"), { recursive: true });

app.use(express.json());
app.use(sessionMiddleware);

// --- API (flag submission, progress, reveal — all session-gated) ---------
app.use("/api", apiRouter);

// --- Real, working vulnerable mini-apps (proof of concept labs) ----------
app.use("/labs/sqli", sqliLab);
app.use("/labs/xss", xssLab);

// --- Frontend (the Security Playground UI itself) ------------------------
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Security Playground running at http://localhost:${PORT}`);
  console.log(`Real SQLi lab:  http://localhost:${PORT}/labs/sqli/`);
  console.log(`Real XSS lab:   http://localhost:${PORT}/labs/xss/`);
});
