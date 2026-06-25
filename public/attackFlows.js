// ==========================================
// Attack Flow Animation Data
// ==========================================
// One entry per vulnerability id. Each defines 4 actors and two step
// sequences ("breach" = vulnerable system, "defended" = secure system).
// Steps move a packet between actors (from === to means "this actor is
// processing/thinking", no movement, just a pulse).

const ATTACK_FLOWS = {
    xss: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Victim Browser" },
            c: { icon: "🖥️", label: "Forum Server" },
            d: { icon: "🍪", label: "Admin Session" },
        },
        breach: [
            { from: "a", to: "c", packet: "📝", caption: "Attacker posts a comment: <script>steal cookies</script> — instead of normal text." },
            { from: "c", to: "c", packet: "💾", caption: "Server saves the comment exactly as typed. No escaping, no filtering." },
            { from: "c", to: "b", packet: "📄", caption: "Later, an admin opens the page. The server sends that raw script back inside the HTML." },
            { from: "b", to: "b", packet: "⚙️", caption: "The browser can't tell code from content — it just runs the <script> tag like any other." },
            { from: "b", to: "d", packet: "🍪", caption: "The script reads document.cookie — the admin's live session." },
            { from: "d", to: "a", packet: "📡", caption: "...and silently sends it to the attacker's server in the background." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: attacker now has a valid admin session cookie — full account takeover, no password needed." },
        defended: [
            { from: "a", to: "c", packet: "📝", caption: "Attacker tries the exact same payload: <script>steal cookies</script>." },
            { from: "c", to: "c", packet: "🔐", caption: "Before storing or rendering it, the server encodes special characters: < becomes &lt;, > becomes &gt;." },
            { from: "c", to: "b", packet: "📄", caption: "The browser receives &lt;script&gt;...&lt;/script&gt; — literal text, not a real tag." },
            { from: "b", to: "b", packet: "🚫", caption: "Nothing executes. It just prints on screen as harmless text." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: output encoding turned working code into inert text. No cookie theft possible." },
    },

    sqli: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🔑", label: "Login Form" },
            c: { icon: "🖥️", label: "App Server" },
            d: { icon: "🗄️", label: "Database" },
        },
        breach: [
            { from: "a", to: "b", packet: "✍️", caption: "Attacker types ' OR '1'='1 into the username field instead of a real username." },
            { from: "b", to: "c", packet: "📨", caption: "The raw input travels to the server exactly as typed." },
            { from: "c", to: "c", packet: "🧩", caption: "The server glues it directly into a SQL string: SELECT * FROM users WHERE user='' OR '1'='1'" },
            { from: "c", to: "d", packet: "📤", caption: "The database doesn't see an attack — it just sees a query that's always true, and runs it." },
            { from: "d", to: "c", packet: "📋", caption: "It returns every row in the users table, including the admin account." },
            { from: "c", to: "a", packet: "✅", caption: "The server logs the attacker in as the first user it finds — usually the admin." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: full login bypass with zero valid credentials — and the same trick can dump the entire database." },
        defended: [
            { from: "a", to: "b", packet: "✍️", caption: "Attacker tries the same ' OR '1'='1 trick in the username field." },
            { from: "b", to: "c", packet: "📨", caption: "The input arrives at the server unchanged — that part hasn't changed." },
            { from: "c", to: "d", packet: "🧩", caption: "But the query uses a parameterized placeholder: WHERE user = ?  — the value is sent separately, never glued into the SQL text." },
            { from: "d", to: "c", packet: "📋", caption: "The database treats the whole string ' OR '1'='1' as one literal username to search for — which doesn't exist." },
            { from: "c", to: "a", packet: "❌", caption: "Login fails. No rows matched." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: parameterized queries make user input just data — it can never change the structure of the SQL command." },
    },

    bac: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Browser" },
            c: { icon: "🖥️", label: "App Server" },
            d: { icon: "🛠️", label: "Admin Panel" },
        },
        breach: [
            { from: "a", to: "b", packet: "🔗", caption: "Attacker is logged in as a normal user — but guesses the URL /admin/delete-user." },
            { from: "b", to: "c", packet: "📨", caption: "The browser requests that page directly, the same way it would request any normal page." },
            { from: "c", to: "c", packet: "❓", caption: "The server checks: is this person logged in? Yes. ...and never checks WHAT role they have." },
            { from: "c", to: "d", packet: "✅", caption: "The admin action runs — because the server only confirmed authentication, never authorization." },
            { from: "c", to: "a", packet: "📄", caption: "Page loads normally, as if the attacker were an admin." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: a regular logged-in user just performed an admin-only action — the page was 'hidden', not actually protected." },
        defended: [
            { from: "a", to: "c", packet: "🔗", caption: "Attacker requests the same /admin/delete-user URL." },
            { from: "c", to: "c", packet: "🪪", caption: "The server checks both: logged in? Yes. Role == admin? No." },
            { from: "c", to: "a", packet: "⛔", caption: "Request rejected with 403 Forbidden — before the admin logic ever runs." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: every privileged action re-checks the user's role server-side, on every single request — not just 'is logged in'." },
    },

    idor: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Browser" },
            c: { icon: "🖥️", label: "App Server" },
            d: { icon: "📄", label: "Other User's Data" },
        },
        breach: [
            { from: "a", to: "b", packet: "🧾", caption: "Attacker is viewing their own invoice: /invoices/1024 — their actual invoice ID." },
            { from: "a", to: "c", packet: "✏️", caption: "They simply change the number in the URL to /invoices/1025 — someone else's invoice." },
            { from: "c", to: "c", packet: "❓", caption: "The server fetches whatever ID is asked for... and never checks who actually owns it." },
            { from: "c", to: "d", packet: "📤", caption: "Record 1025 is pulled straight from the database." },
            { from: "d", to: "a", packet: "📄", caption: "It's returned and rendered — a complete stranger's invoice, name, and charges." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: every record in the system is readable just by guessing or incrementing IDs — no real access control exists." },
        defended: [
            { from: "a", to: "c", packet: "✏️", caption: "Attacker tries the same trick: /invoices/1025." },
            { from: "c", to: "c", packet: "🪪", caption: "Before returning anything, the server checks: does invoice 1025 belong to THIS logged-in user?" },
            { from: "c", to: "a", packet: "⛔", caption: "Ownership check fails. Server responds 403/404 — doesn't even confirm the record exists." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: ownership is verified server-side on every lookup, so changing an ID in the URL gets you nothing." },
    },

    csrf: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker Site" },
            b: { icon: "🌐", label: "Victim Browser" },
            c: { icon: "🏦", label: "Bank Server" },
            d: { icon: "💰", label: "Victim Account" },
        },
        breach: [
            { from: "b", to: "c", packet: "🍪", caption: "Victim is already logged into their bank in one tab — the session cookie is active." },
            { from: "a", to: "b", packet: "🪤", caption: "Victim visits a malicious page in another tab. It contains a hidden auto-submitting form pointed at the bank." },
            { from: "b", to: "c", packet: "💸", caption: "The browser auto-submits it — and automatically attaches the victim's bank cookie, because that's just how cookies work." },
            { from: "c", to: "c", packet: "❓", caption: "The bank sees a valid, authenticated request... and has no way to tell it wasn't intentional." },
            { from: "c", to: "d", packet: "💰", caption: "Funds transfer to the attacker's account. Processed exactly like a real transfer — because to the server, it was indistinguishable." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: money moved without the victim ever clicking anything on the bank's own site." },
        defended: [
            { from: "b", to: "c", packet: "🍪", caption: "Victim is logged into their bank, same as before." },
            { from: "c", to: "b", packet: "🎫", caption: "Every real form on the bank's site includes a hidden, unique CSRF token tied to that session." },
            { from: "a", to: "b", packet: "🪤", caption: "Victim visits the same malicious page and its hidden form auto-submits." },
            { from: "b", to: "c", packet: "💸", caption: "The forged request has the cookie (browsers always attach those) — but no valid CSRF token, because the attacker's page can't read or guess it." },
            { from: "c", to: "a", packet: "⛔", caption: "Server rejects the request: token missing or invalid." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: a CSRF token proves the request actually came from the bank's own page — not just from a logged-in browser." },
    },

    upload: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Browser" },
            c: { icon: "🖥️", label: "Upload Server" },
            d: { icon: "📁", label: "Web Root" },
        },
        breach: [
            { from: "a", to: "b", packet: "📄", caption: "Attacker renames a malicious script to photo.php and picks 'Upload Avatar'." },
            { from: "b", to: "c", packet: "📨", caption: "The file is sent. The server only checks the file's extension claim, not what's actually inside it." },
            { from: "c", to: "d", packet: "💾", caption: "photo.php gets saved directly inside the public web folder, executable scripts and all." },
            { from: "a", to: "d", packet: "🌐", caption: "Attacker simply visits /uploads/photo.php in their browser." },
            { from: "d", to: "a", packet: "💻", caption: "The server runs it as code — handing the attacker a remote shell on the box." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: full remote code execution on the server, just from an 'avatar' upload." },
        defended: [
            { from: "a", to: "b", packet: "📄", caption: "Attacker tries uploading the same photo.php." },
            { from: "b", to: "c", packet: "📨", caption: "The server inspects the actual file content (magic bytes), not just the name — and rejects anything that isn't really an image." },
            { from: "c", to: "c", packet: "🔁", caption: "Even accepted files get renamed to a random ID and stored OUTSIDE the directly-executable web root." },
            { from: "c", to: "a", packet: "⛔", caption: "Upload rejected — or stored as a harmless, non-executable file the server will never run as code." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: real content checks plus a non-executable storage location mean an uploaded 'image' can never become a running script." },
    },

    traversal: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Browser" },
            c: { icon: "🖥️", label: "File Server" },
            d: { icon: "🗂️", label: "Filesystem" },
        },
        breach: [
            { from: "a", to: "c", packet: "📨", caption: "Site lets you view files: /view?file=report.pdf. Attacker changes it to ../../../../etc/passwd." },
            { from: "c", to: "c", packet: "🧩", caption: "The server just glues that path onto its base folder: /files/../../../../etc/passwd — and the ../ walks right back out of it." },
            { from: "c", to: "d", packet: "📂", caption: "The OS resolves the path literally — it has no idea this 'should' have stayed inside /files." },
            { from: "d", to: "a", packet: "📄", caption: "The real system password file gets streamed back as the 'download'." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: any file on the server the web process can read is now downloadable — configs, source code, credentials." },
        defended: [
            { from: "a", to: "c", packet: "📨", caption: "Attacker tries the same ../../../../etc/passwd trick." },
            { from: "c", to: "c", packet: "🧹", caption: "The server resolves the path FIRST, then checks: does the result still live inside the allowed /files folder?" },
            { from: "c", to: "a", packet: "⛔", caption: "It doesn't — request rejected before any file is touched." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: validating the resolved path against an allow-list folder stops every ../ trick, no matter how it's encoded." },
    },

    auth: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🔑", label: "Login Page" },
            c: { icon: "🖥️", label: "Auth Server" },
            d: { icon: "🗄️", label: "User Database" },
        },
        breach: [
            { from: "a", to: "b", packet: "🔁", caption: "Attacker scripts a bot to try thousands of common passwords against one account, back to back." },
            { from: "b", to: "c", packet: "📨", caption: "The server has no rate limit and no lockout — it happily checks attempt #1 and attempt #50,000 the same way." },
            { from: "c", to: "d", packet: "🔍", caption: "Eventually one guess matches the stored (often weakly hashed) password." },
            { from: "d", to: "c", packet: "✅", caption: "Match found." },
            { from: "c", to: "a", packet: "🔓", caption: "Login succeeds. The attacker now owns the account." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: unlimited guesses + a guessable password = the account was never really protected at all." },
        defended: [
            { from: "a", to: "b", packet: "🔁", caption: "Attacker starts the same brute-force script." },
            { from: "b", to: "c", packet: "📨", caption: "After a handful of failed attempts, the server starts throttling — then temporarily locks the account." },
            { from: "c", to: "a", packet: "⏳", caption: "Further attempts are rejected outright: 'Too many attempts, try again later.'" },
            { from: "d", to: "d", packet: "🧂", caption: "Even if a guess ever landed, passwords are stored with strong salted hashing (e.g. bcrypt) — not reversible, not crackable at speed." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: rate limiting turns 'try everything' into 'try a handful and wait' — brute force stops being practical." },
    },

    ssrf: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🖥️", label: "App Server" },
            c: { icon: "☁️", label: "Cloud Metadata" },
            d: { icon: "🔑", label: "Cloud Credentials" },
        },
        breach: [
            { from: "a", to: "b", packet: "🔗", caption: "App has a 'fetch image from URL' feature. Attacker submits http://169.254.169.254/latest/meta-data/ instead of an image link." },
            { from: "b", to: "b", packet: "❓", caption: "The server doesn't check where the URL points — it just fetches whatever it's given, from its own network position." },
            { from: "b", to: "c", packet: "📡", caption: "The request goes out from the SERVER, not the attacker — reaching an internal cloud-only endpoint the attacker could never reach directly." },
            { from: "c", to: "d", packet: "🔑", caption: "That internal endpoint hands back temporary cloud credentials — it trusts anything calling from inside the network." },
            { from: "d", to: "a", packet: "📤", caption: "The server dutifully returns that response as the 'fetched image' — straight to the attacker." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: the attacker now holds live cloud credentials, obtained by abusing the server as a proxy into its own internal network." },
        defended: [
            { from: "a", to: "b", packet: "🔗", caption: "Attacker submits the same internal metadata URL." },
            { from: "b", to: "b", packet: "🪪", caption: "The server checks the destination against an allow-list of approved external domains before fetching anything." },
            { from: "b", to: "a", packet: "⛔", caption: "169.254.169.254 isn't on the list — request blocked, nothing is ever fetched." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: outbound requests the server makes on your behalf are restricted to a known allow-list — internal/cloud-only addresses are never reachable this way." },
    },

    misconfig: {
        actors: {
            a: { icon: "🧑‍💻", label: "Attacker" },
            b: { icon: "🌐", label: "Browser" },
            c: { icon: "🖥️", label: "Server" },
            d: { icon: "🔐", label: "Secrets/Configs" },
        },
        breach: [
            { from: "a", to: "c", packet: "🔍", caption: "Attacker simply requests /debug or /.env — paths the developer left on by accident in production." },
            { from: "c", to: "c", packet: "❓", caption: "Debug mode is still on. Default credentials were never changed. Directory listing is enabled." },
            { from: "c", to: "d", packet: "📤", caption: "The server happily serves up stack traces, environment variables, and API keys — no exploit needed, it's just exposed." },
            { from: "c", to: "a", packet: "📄", caption: "Full configuration, database connection strings, and secret keys land in the attacker's browser." },
        ],
        breachOutcome: { icon: "🔓", text: "Breach: zero 'hacking' required — the system handed over its own secrets because nobody hardened the defaults." },
        defended: [
            { from: "a", to: "c", packet: "🔍", caption: "Attacker tries the same /debug and /.env requests." },
            { from: "c", to: "c", packet: "🧹", caption: "Debug mode is off in production. Default accounts were removed. Sensitive paths return a flat 404." },
            { from: "c", to: "a", packet: "⛔", caption: "Nothing comes back but a generic 'not found'." },
        ],
        defendedOutcome: { icon: "🔒", text: "Blocked: a proper production hardening checklist (debug off, no defaults, least-privilege configs) leaves nothing for the attacker to simply ask for." },
    },
};
