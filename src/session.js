// src/session.js
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const path = require("path");

const SESSION_SECRET = process.env.SESSION_SECRET || "sp-dev-session-secret-change-me";

module.exports = session({
  store: new FileStore({
    path: path.join(__dirname, "..", "data", "sessions"),
    logFn: function () {}, // silence noisy default logging
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  },
  name: "sp.sid",
});
