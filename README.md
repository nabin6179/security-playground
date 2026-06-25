# Security Playground — Backend-Verified Edition

This adds a real Node/Express backend to your CTF/learning platform so flags
are never shipped to the browser, plus two genuinely exploitable mini-apps
(not simulations) as a proof of concept.

## What changed, and why

**The problem:** every flag (`SP{...}`) lived as a plaintext string inside
`script.js`, including inside several "Solution" hint strings. Anyone could
view-source or open the JS file and grep for every answer in seconds — no
exploitation required.

**The fix:**
- All 40 flags now live **only** on the server, salted + hashed
  (`src/data/flags.db.json`). The browser never receives a flag value except
  the instant a player legitimately earns it.
- `POST /api/submit-flag` is the **only** place "solved" is decided. The
  client sends `{ id, value }`; the server hashes and compares, and is the
  one awarding XP.
- Every literal flag previously embedded in "Solution" text has been
  redacted.
- The ~40 simulated labs (fake browser/devtools) still work exactly as
  before from the player's point of view — they just no longer have the
  answer sitting in the page source. A small `MutationObserver` in
  `script.js` watches the sandbox panel and swaps a placeholder for the
  real flag (fetched from `GET /api/reveal/:id`) the instant the simulation
  renders it, gated behind having opened that sandbox first.
- Two challenges (**Admin Cookie Stealer** / `xss-ctf` and **Database Flag
  Extractor** / `sqli-ctf`) are now backed by **real, working vulnerable
  Express apps** (`/labs/xss/`, `/labs/sqli/`) instead of a simulation —
  genuine stored XSS + cookie theft, and a real UNION-based SQL injection
  against an in-memory SQLite database. A "🚀 Launch Real Lab" button
  appears in the sandbox for these two.

## Honest limitation to know about

The ~38 *simulated* labs check their fake "did you do the right thing"
condition entirely in client JS (that hasn't changed — rewriting all of
them as real vulnerable endpoints is a much bigger project). The `/api/reveal/:id`
gate stops the trivial "read script.js, get every flag" attack, but a
determined player who reverse-engineers the simulation logic could still
call that endpoint directly without truly solving the puzzle. That's a
fundamentally different (much higher) bar than what existed before. The two
**real** labs don't have this limitation at all — there's no shortcut, you
have to actually exploit them.

## Setup

```bash
npm install
npm run build:flags   # only needed if you ever edit src/data/extracted-flags.private.json
npm start
```

Then open **http://localhost:3000**.

- Real SQLi lab: http://localhost:3000/labs/sqli/
- Real XSS lab: http://localhost:3000/labs/xss/

## Project layout

```
server.js                      Express app entry point
src/
  flagStore.js                 Loads hashed flags, does the actual compare
  session.js                   Cookie/session config (file-backed, no login)
  progressState.js             Per-session solved/xp shape
  routes/api.js                /api/progress, /api/submit-flag,
                                /api/sandbox/:id/launch, /api/reveal/:id
  labs/
    sqli.js                    Real vulnerable SQLi mini-app (node:sqlite)
    xss.js                     Real vulnerable stored-XSS mini-app
    flagSeed.js                 Server-only helper to seed the real labs
  data/
    extracted-flags.private.json   Plaintext flags — SERVER ONLY, never served
    flags.db.json               Hashed flags actually used at runtime
    buildFlagsDb.js              Regenerates flags.db.json from the private file
public/                        The frontend (index.html, script.js, styles.css, logo.svg)
data/sessions/                 Session store files (created at runtime)
```

## Configuration

Two environment variables you should change for any real deployment:

```bash
export SESSION_SECRET="something-long-and-random"
export FLAG_PEPPER="something-else-long-and-random"
```

If you change `FLAG_PEPPER`, re-run `npm run build:flags` to rehash.

## Extending it

- **Add a new CTF challenge:** add an entry to
  `src/data/extracted-flags.private.json` (`{ "id": "...", "flag": "SP{...}",
  "xp": 150 }`), run `npm run build:flags`, then add the matching
  content (title/desc/hints) to `public/script.js`'s `CTF_CHALLENGES` array
  — just don't add a `flag:` field there anymore.
- **Turn another simulated lab into a real one:** look at `src/labs/xss.js`
  or `src/labs/sqli.js` as a template, mount it in `server.js`, and add its
  URL to `REAL_LAB_URLS` near the top of `public/script.js`.
- **Add accounts/persistence across devices:** swap `session-file-store`
  for a real datastore and add a login step in front of the session — the
  `/api` routes don't need to change since they already key everything off
  `req.session`.
