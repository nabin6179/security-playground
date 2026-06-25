// Security Playground - Platform State & Simulations Engine

// ==========================================
// 1. Core State & Storage Management
// ==========================================

const DEFAULT_STATE = {
    xp: 0,
    username: "Recruit",
    avatar: "⚡",
    solvedLabs: [], // list of labIds
    solvedCtfs: [], // list of ctfIds (includes mini-ctfs and arena-ctfs)
    unlockedBadges: [], // list of badgeIds
};

let userState = { ...DEFAULT_STATE };

function loadState() {
    const saved = localStorage.getItem("sp_user_state");
    if (saved) {
        try {
            userState = { ...DEFAULT_STATE, ...JSON.parse(saved) };
        } catch (e) {
            userState = { ...DEFAULT_STATE };
        }
    } else {
        userState = { ...DEFAULT_STATE };
    }
    updateRankAndProgress();
    updateUI();
}

function saveState() {
    localStorage.setItem("sp_user_state", JSON.stringify(userState));
    updateRankAndProgress();
    updateUI();
}

function addXp(amount, reason) {
    userState.xp += amount;
    showToast(`✨ +${amount} XP: ${reason}`, "info");
    checkBadges();
    saveState();
}

const RANKS = [
    { name: "Beginner", minXp: 0, icon: "🥚" },
    { name: "Explorer", minXp: 1000, icon: "🧭" },
    { name: "Analyst", minXp: 3000, icon: "🔍" },
    { name: "Pentester", minXp: 6000, icon: "⚔️" },
    { name: "Researcher", minXp: 10000, icon: "🧪" },
    { name: "Security Expert", minXp: 15000, icon: "👑" }
];

function getCurrentRank() {
    let current = RANKS[0];
    for (let r of RANKS) {
        if (userState.xp >= r.minXp) {
            current = r;
        }
    }
    return current;
}

function getNextRank() {
    const current = getCurrentRank();
    const idx = RANKS.findIndex(r => r.name === current.name);
    if (idx === -1 || idx === RANKS.length - 1) return null;
    return RANKS[idx + 1];
}

function updateRankAndProgress() {
    const rank = getCurrentRank();
    const nextRank = getNextRank();
    
    document.getElementById("rankDisplay").innerText = rank.name;
    document.getElementById("progressRank").innerText = rank.name;
    
    // Level calculation: 1000 XP per level
    const level = Math.floor(userState.xp / 1000) + 1;
    document.getElementById("userLevel").innerText = level;
    document.getElementById("progressLevel").innerText = level;
    document.getElementById("dashLevel").innerText = `Level ${level}`;
    document.getElementById("dashRank").innerText = `${rank.name} Rank`;
    
    // Level XP bar progress
    const xpInCurrentLevel = userState.xp % 1000;
    const pct = (xpInCurrentLevel / 1000) * 100;
    
    document.getElementById("userXp").innerText = xpInCurrentLevel;
    document.getElementById("nextLevelXp").innerText = "1000";
    document.getElementById("xpBarFill").style.width = `${pct}%`;
    document.getElementById("progressXpBarFill").style.width = `${pct}%`;
    document.getElementById("progressXpCount").innerText = userState.xp;
    document.getElementById("progressXpNext").innerText = `${1000 - xpInCurrentLevel} XP to Level ${level + 1}`;
}

// ==========================================
// 1.5 Backend Flag Verification
// ==========================================
// Flags are no longer stored in this file. The server is the only place
// that knows whether a submitted value is correct, and it's the only place
// that ever has the real flag text. See /api/submit-flag and /api/reveal/:id
// on the backend for the actual verification logic.

// The two challenges that are real, exploitable backend apps instead of a
// simulated sandbox.
const REAL_LAB_URLS = {
    "xss-ctf": "/labs/xss/",
    "sqli-ctf": "/labs/sqli/",
};

async function submitFlagToServer(id, value) {
    try {
        const res = await fetch("/api/submit-flag", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id, value }),
        });
        if (!res.ok) {
            return { correct: false, error: true };
        }
        return await res.json();
    } catch (e) {
        return { correct: false, error: true };
    }
}

async function notifySandboxLaunched(id) {
    try {
        await fetch(`/api/sandbox/${encodeURIComponent(id)}/launch`, { method: "POST" });
    } catch (e) {
        // Non-fatal — worst case the reveal endpoint stays gated.
    }
}

// --- Simulated-lab flag reveal ---------------------------------------------
// The simulated (non-real) sandbox UI still renders a "captured flag" the
// moment a player triggers the right fake condition (tampering a cookie,
// reading a fake response header, etc.) — exactly like before. The
// difference is that the literal flag text doesn't live in this file
// anymore: every one of those ~40 spots in the simulation now renders the
// placeholder token below, and this observer swaps it for the real flag
// (fetched from the backend, gated behind having opened that sandbox) the
// instant it shows up anywhere in the sandbox DOM — no matter which of the
// many code paths produced it.
const FLAG_REVEAL_TOKEN = "[captured flag]";
const revealedFlagCache = {};

async function resolveRevealToken() {
    if (!activeSandboxId) return;
    if (!sandboxOverlay || !sandboxOverlay.textContent.includes(FLAG_REVEAL_TOKEN)) return;

    let flag = revealedFlagCache[activeSandboxId];
    if (!flag) {
        try {
            const res = await fetch(`/api/reveal/${encodeURIComponent(activeSandboxId)}`);
            if (!res.ok) return; // not launched yet, rate-limited, etc.
            const data = await res.json();
            flag = data.flag;
            revealedFlagCache[activeSandboxId] = flag;
        } catch (e) {
            return;
        }
    }
    if (!flag) return;

    const walker = document.createTreeWalker(sandboxOverlay, NodeFilter.SHOW_TEXT);
    const textNodes = [];
    let node;
    while ((node = walker.nextNode())) textNodes.push(node);
    textNodes.forEach((n) => {
        if (n.nodeValue.includes(FLAG_REVEAL_TOKEN)) {
            n.nodeValue = n.nodeValue.split(FLAG_REVEAL_TOKEN).join(flag);
        }
    });
}

// ==========================================
// 2. Database Definition
// ==========================================

const VULNERABILITIES = [
    {
        id: "xss",
        title: "Cross-Site Scripting (XSS)",
        category: "Injection",
        what: "Cross-Site Scripting (XSS) is a vulnerability that occurs when a web application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute malicious JavaScript in the victim's browser.",
        how: "Attackers look for input fields, query parameters, or headers that are printed back on the screen. By typing HTML tags like `<script>` or event handlers like `onerror` into these inputs, they trick the browser into executing their code instead of plain text.",
        impact: "Attackers can steal session cookies, hijack user accounts, redirect users to phishing sites, capture keystrokes (keylogging), or deface websites.",
        prevention: [
            "Use Context-Aware HTML Escaping (converting < to &lt;)",
            "Implement a Content Security Policy (CSP)",
            "Set the HttpOnly flag on sensitive session cookies",
            "Avoid direct sinks like innerHTML, document.write(), or eval()"
        ],
        example: "A search query field prints 'Search results for: [query]'. If user enters `<script>alert(1)</script>`, it runs in their browser.",
        filename: "search.php",
        vulnCode: `<?php\n$search = $_GET['q'];\necho "<h3>Search results for: " . $search . "</h3>";\n?>`,
        secureCode: `<?php\n$search = $_GET['q'];\n// Escape special characters to prevent HTML execution\necho "<h3>Search results for: " . htmlspecialchars($search, ENT_QUOTES, 'UTF-8') . "</h3>";\n?>`,
        explainer: "The vulnerable code directly concatenates the raw input into the output. The secure code uses `htmlspecialchars` to convert characters like `<` and `>` into safe HTML entities (`&lt;` and `&gt;`), rendering them as text instead of executable scripts.",
        labs: [
            {
                id: "xss-basic",
                title: "Reflected XSS via Search",
                difficulty: "Basic",
                xp: 100,
                objective: "Inject a script that triggers a simulated browser alert pop-up.",
                scenario: "A local search dashboard reflects query terms. Exploit it with standard XSS script payloads.",
                hint1: "Enter standard text to see where it appears.",
                hint2: "Try `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`.",
                solution: "Type `<script>alert(1)</script>` in the search input and hit search."
            },
            {
                id: "xss-stored",
                title: "Stored XSS Guestbook",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Inject a script into the comments list that executes on every page reload.",
                scenario: "A guestbook site saves comments. The comments page loads saved strings without output escaping.",
                hint1: "Comments are stored in active memory. Anything you post gets loaded immediately.",
                hint2: "Submit `<img src=x onerror=alert(1)>` as a comment, then refresh or check the output.",
                solution: "Add a comment containing: `<img src=x onerror=alert(1)>`. The lab will fire the script on render."
            },
            {
                id: "xss-dom",
                title: "DOM-Based XSS via Hash",
                difficulty: "Advanced",
                xp: 300,
                objective: "Trigger an alert box by editing the simulated browser URL parameters.",
                scenario: "A single-page website parses parameters from the URL hash (`#name=...`) and feeds it directly to an `innerHTML` sink without filtering.",
                hint1: "Examine the URL bar. It ends with #name=Guest.",
                hint2: "Change the text after #name= to an image payload: `<img src=x onerror=alert(1)>`.",
                solution: "Change the URL hash to: `#name=<img src=x onerror=alert(1)>` and hit Enter on the URL bar."
            }
        ],
        ctf: {
            id: "xss-ctf",
            title: "Admin Cookie Stealer",
            difficulty: "Medium",
            xp: 250,
            desc: "The admin page is visited by a simulated bot. Post a stored XSS payload in the feedback form that reads the administrator's document.cookie and sends it to a mock hook dashboard `/log?cookie=...`. Once sent, look at the Proxy Logs/Dev Console to capture the administrator's session cookie containing the flag.",
            hint1: "You need to access document.cookie.",
            hint2: "Inject an image or script that requests `/log?cookie=` + document.cookie. Watch the console or network headers for requests.",
            solution: "Create a stored feedback containing: `<img src=x onerror=\"fetch('/log?cookie=' + document.cookie)\">`. Then, look at the 'Proxy Logs' tab in DevTools to find the request payload containing the admin flag!"
        }
    },
    {
        id: "sqli",
        title: "SQL Injection (SQLi)",
        category: "Injection",
        what: "SQL Injection occurs when user-supplied input is directly concatenated into a SQL query, allowing attackers to manipulate query logic, bypass authentication, or read database tables.",
        how: "By injecting database operators (like `' OR 1=1 --`), attackers alter the database syntax. The server executes their inputs as command commands instead of data parameters.",
        impact: "Authentication bypass, full database extraction (emails, passwords), data modification, and sometimes remote command execution.",
        prevention: [
            "Use Prepared Statements (Parameterized Queries)",
            "Use Object-Relational Mappers (ORMs)",
            "Validate inputs against strict block/allow lists",
            "Apply least privilege permissions to database users"
        ],
        example: "A login check uses query: `SELECT * FROM users WHERE user='$name' AND pass='$pass'`. Entering admin name `' OR 1=1 --` overrides pass-checking.",
        filename: "login.js",
        vulnCode: `const query = "SELECT * FROM users WHERE user = '" + req.body.user + "' AND pass = '" + req.body.pass + "'";\ndb.query(query, (err, result) => { ... });`,
        secureCode: `// Use parameterized placeholders (?) to isolate inputs from query logic\nconst query = "SELECT * FROM users WHERE user = ? AND pass = ?";\ndb.query(query, [req.body.user, req.body.pass], (err, result) => { ... });`,
        explainer: "In the vulnerable code, the strings are joined directly, changing structural query logic. The secure code uses `?` place-holders, telling SQL that the input is strictly data, never SQL commands.",
        labs: [
            {
                id: "sqli-basic",
                title: "SQLi Login Bypass",
                difficulty: "Basic",
                xp: 100,
                objective: "Bypass the login form and authenticate as the admin user without a password.",
                scenario: "A client portal is backed by a vulnerable SQL database query. The query uses string concatenation for matching.",
                hint1: "You need to make the WHERE statement evaluate to true.",
                hint2: "Inject `' OR 1=1 --` into the username field. The `--` characters comment out the remaining password checks.",
                solution: "Username: `admin' OR 1=1 --` and password can be left blank. Click Submit."
            },
            {
                id: "sqli-union",
                title: "Union-Based SQLi Data Leak",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Extract user credentials by injecting UNION query extensions.",
                scenario: "A search field retrieves catalog items. Use SQL UNION commands to fetch sensitive data from other tables like `users`.",
                hint1: "Add a quote to close the string query, then use UNION SELECT.",
                hint2: "Determine columns: try `' UNION SELECT username, password FROM users --`.",
                solution: "Type `' UNION SELECT username, password FROM users --` in the search input."
            },
            {
                id: "sqli-blind",
                title: "Blind SQLi Verification",
                difficulty: "Advanced",
                xp: 300,
                objective: "Determine whether the admin account exists by injecting conditional truth checks.",
                scenario: "A portal search only returns 'Item Found' or 'No Items'. Exploit boolean blind injection to extract system configuration indicators.",
                hint1: "If you input `' AND 1=1 --`, it matches logic. `' AND 1=2 --` fails.",
                hint2: "Input `' OR username='admin' --` or check conditional queries to reveal hidden data.",
                solution: "Input `' OR (SELECT username FROM users LIMIT 1)='admin' --` or `' OR 1=1 --` to toggle status outcomes."
            }
        ],
        ctf: {
            id: "sqli-ctf",
            title: "Database Flag Extractor",
            difficulty: "Medium",
            xp: 250,
            desc: "A search database has a hidden flag table. Inject a UNION command on the product search tool to extract details from the table named `secret_flags`. The table has a column called `flag_token`.",
            hint1: "Use `' UNION SELECT null, flag_token FROM secret_flags --`.",
            hint2: "You may need to match the number of columns of the main query (2 columns).",
            solution: "Submit `' UNION SELECT flag_token, null FROM secret_flags --` in the search bar. Read the extracted flag in the search outcomes."
        }
    },
    {
        id: "bac",
        title: "Broken Access Control",
        category: "Auth & Access",
        what: "Broken Access Control occurs when a web application fails to properly enforce user authorization rules, allowing users to access resources outside their intended privileges.",
        how: "Attackers manipulate parameters, URLs, or headers to access hidden admin sections or view other users' configuration panels directly.",
        impact: "Privilege escalation, unauthorized data modifications, leakage of sensitive business data, and account takeovers.",
        prevention: [
            "Deny access by default, authorize explicitly",
            "Enforce access controls on every request server-side",
            "Use unique random identifier tokens for URLs",
            "Perform regular manual and automated access control testing"
        ],
        example: "Changing URL parameter from `/my-profile` to `/admin-panel` gives full administration panel rights to normal accounts.",
        filename: "middleware.js",
        vulnCode: `// Checks if user is logged in, but doesn't check their specific roles!\napp.get('/admin', (req, res) => {\n  if (req.session.user) res.render('admin');\n});`,
        secureCode: `// Validate user roles explicitly inside server-side controllers\napp.get('/admin', (req, res) => {\n  if (req.session.user && req.session.user.role === 'admin') {\n    res.render('admin');\n  } else {\n    res.status(403).send('Unauthorized Access');\n  }\n});`,
        explainer: "The vulnerable code only validates login session state. The secure code checks the user's role explicitly (e.g. role = 'admin') and returns a 403 Forbidden code if they don't have permission.",
        labs: [
            {
                id: "bac-basic",
                title: "Expose Hidden Admin Route",
                difficulty: "Basic",
                xp: 100,
                objective: "Locate and access the hidden administrator panel by path editing.",
                scenario: "A company website hides its management path. Bypassing client menus, guess the directory structure.",
                hint1: "Common admin directories include /admin, /administrator, or /admin-dashboard.",
                hint2: "Change the simulated URL path to `/admin-panel`.",
                solution: "Change the URL bar path from `http://company.local/` to `http://company.local/admin-panel` and press enter."
            },
            {
                id: "bac-role",
                title: "Role Parameter Tampering",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Elevate your privileges by altering client cookies.",
                scenario: "An dashboard application stores user permissions inside client cookies. Modify session cookies to bypass checks.",
                hint1: "Open the Developer Tools panel -> Cookies tab in the sandbox.",
                hint2: "Find the cookie named `role`. Double click its value to change it to `admin`, then refresh.",
                solution: "Go to DevTools -> Cookies, set `role` value to `admin`, click reload icon in address bar."
            },
            {
                id: "bac-priv",
                title: "Horizontal privilege bypass",
                difficulty: "Advanced",
                xp: 300,
                objective: "Expose another employee's profile by editing API headers.",
                scenario: "An organization API validates transactions using client IDs. Exploit a lack of server-side authorization controls.",
                hint1: "Examine Proxy Logs or the current URL. Use API requester elements to modify headers.",
                hint2: "Inject `X-User-Role: Admin` or tamper user identifier tokens in custom headers.",
                solution: "Open Proxy Logs / Header tools. Edit the simulated request headers to add `X-User-Role: admin` and resubmit request."
            }
        ],
        ctf: {
            id: "bac-ctf",
            title: "Dashboard Privilege Takeover",
            difficulty: "Hard",
            xp: 300,
            desc: "The admin page checks both a cookie role and header token. Set your session cookie `role` to `admin` and inject a custom header `X-Admin-Token` with the value `secret_access_2026` in the request interceptor to unlock the flag.",
            hint1: "You must use both DevTools -> Cookies and add a request header in Proxy logs.",
            hint2: "Cookie key: role, value: admin. Request header key: X-Admin-Token, value: secret_access_2026.",
            solution: "1. Add cookie: role=admin. 2. In Proxy Logs, add request header 'X-Admin-Token: secret_access_2026'. 3. Reload browser page."
        }
    },
    {
        id: "idor",
        title: "Insecure Direct Object Reference (IDOR)",
        category: "Auth & Access",
        what: "IDOR occurs when a web application exposes references to internal database objects (like user IDs, file paths, or order numbers) in URL parameters or request payloads, without verifying if the user has authorization to access them.",
        how: "Attackers look for parameters like `?id=102` or `/api/invoice/456`. By altering the number (incrementing/decrementing), they request other users' private files.",
        impact: "Unauthorized data modification, full access to customer files/receipts, and database leaks.",
        prevention: [
            "Implement robust, object-level access validation server-side",
            "Use cryptographically secure, random UUIDs instead of auto-incrementing integers",
            "Enforce strict authentication and authorization checks on every transaction"
        ],
        example: "A bank statement URL looks like `/statement?acct=204`. Changing `acct` to `203` retrieves an unrelated user's statement.",
        filename: "api.py",
        vulnCode: `@app.route('/invoice/<id>')\ndef get_invoice(id):\n    # Vulnerable: directly returns invoice by ID without checking if it belongs to the logged-in user!\n    return db.fetch_invoice(id)`,
        secureCode: `@app.route('/invoice/<id>')\ndef get_invoice(id):\n    user_id = session.get('user_id')\n    invoice = db.fetch_invoice(id)\n    # Secure: Validate ownership before returning data\n    if invoice and invoice.owner_id == user_id:\n        return invoice\n    else:\n        return abort(403)`,
        explainer: "The vulnerable server returns the database row based entirely on the URL segment. The secure code fetches the row, verifies if the `owner_id` matches the current logged-in user session, and rejects the request if they do not match.",
        labs: [
            {
                id: "idor-basic",
                title: "Profile Identifier Tampering",
                difficulty: "Basic",
                xp: 100,
                objective: "Tamper with the profile ID to view the account details of User 1.",
                scenario: "A social page loads accounts using IDs. Increment the number to find hidden account indexes.",
                hint1: "Look at the browser URL bar. It ends with ?userId=105.",
                hint2: "Change `userId=105` to `userId=1` and hit enter.",
                solution: "Change URL parameter to `?userId=1` and press enter."
            },
            {
                id: "idor-invoice",
                title: "Unauthorized Invoice Access",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Expose invoice #2048 from the customer account center.",
                scenario: "A user portal downloads PDF invoices based on index numbers. Traverse the files to access a different invoice.",
                hint1: "The dropdown links to ?invoice=1001. Enter a different ID.",
                hint2: "Modify the invoice URL parameter directly to `2048`.",
                solution: "Alter URL in address bar to contain `?invoice=2048` and submit."
            },
            {
                id: "idor-modify",
                title: "Account Payload Manipulation",
                difficulty: "Advanced",
                xp: 300,
                objective: "Change the password of the administrator account by tampering with JSON request properties.",
                scenario: "A profile page updates passwords. The update request uses a JSON payload structure containing a user ID.",
                hint1: "Intercept the request or view the JSON editor. Find the userId property.",
                hint2: "Change the JSON property `\"userId\": 104` to `\"userId\": 1` in the simulated API requester tool.",
                solution: "Edit the payload of the request from `userId: 105` to `userId: 1` and click Send."
            }
        ],
        ctf: {
            id: "idor-ctf",
            title: "IDOR Flag Miner",
            difficulty: "Medium",
            xp: 250,
            desc: "An API dashboard is located at `/api/v1/user/settings?id=105`. Iterate the ID parameter to find a secret flag stored in user profile index 1001.",
            hint1: "Directly change the query parameter id to 1001.",
            hint2: "URL target: `/api/v1/user/settings?id=1001`.",
            solution: "Type `http://bank.local/api/v1/user/settings?id=1001` in the address bar and load page. Read the profile JSON output."
        }
    },
    {
        id: "csrf",
        title: "Cross-Site Request Forgery (CSRF)",
        category: "Auth & Access",
        what: "CSRF forces a logged-in victim's browser to send unauthorized HTTP requests to a vulnerable web application, abusing the trust the web application has in the victim's browser.",
        how: "Because browsers automatically attach session cookies to outgoing requests, a malicious website can trigger state-changing forms (like changing password/email) pointing to the vulnerable app. The server process it thinking it was approved by the logged-in user.",
        impact: "Account takeover (email/password change), unauthorized transactions, configuration alterations.",
        prevention: [
            "Use anti-CSRF tokens (unique, random tokens matched server-side)",
            "Set SameSite=Strict or SameSite=Lax on cookies",
            "Require re-authentication (password checks) for critical actions",
            "Use custom request headers (like Authorization: Bearer)"
        ],
        example: "A bank transfers money via `/transfer?to=bob&amt=100`. Attackers embed `<img src='http://bank.com/transfer?to=alice&amt=100'>` on an external site.",
        filename: "server.py",
        vulnCode: `@app.route('/change-email', methods=['POST'])\ndef change_email():\n    # Vulnerable: changes email based on request form without checking any anti-CSRF token!\n    user = get_session_user()\n    user.email = request.form['email']\n    return 'Success'`,
        secureCode: `@app.route('/change-email', methods=['POST'])\ndef change_email():\n    # Secure: Match token from request body with token stored in user session\n    session_token = session.get('csrf_token')\n    request_token = request.form.get('csrf_token')\n    if not session_token or session_token != request_token:\n        return abort(403)\n    \n    user = get_session_user()\n    user.email = request.form['email']\n    return 'Success'`,
        explainer: "The vulnerable server accepts post states without verification. The secure code requires a cryptographically random `csrf_token` in the POST body. If the browser submits a background request, it won't know this secret token, causing validation to fail.",
        labs: [
            {
                id: "csrf-basic",
                title: "Unprotected Email Changer",
                difficulty: "Basic",
                xp: 100,
                objective: "Trigger a mock CSRF request that updates the user's email address.",
                scenario: "A user settings dashboard changes emails without token protection. Craft a simulated malicious webpage payload.",
                hint1: "Look at the exploit builder. Send a POST request to /change-email.",
                hint2: "Select email change exploit template and execute simulated CSRF payload.",
                solution: "Click the 'CSRF Builder' tab, choose the email exploit template, and click 'Deploy Payload'."
            },
            {
                id: "csrf-password",
                title: "CSRF Password Overwrite",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Exploit a lack of SameSite cookies or tokens to change a user's password.",
                scenario: "A banking application updates user passwords on POST requests. Create an exploit form that changes password.",
                hint1: "Form fields include `new_password` and `confirm_password`.",
                hint2: "Submit a POST form pointing to `/update-pass` with standard parameters from the attack sandbox.",
                solution: "In the attack lab, build a POST request targeting `/update-pass` with form value `pass=hacked` and execute."
            },
            {
                id: "csrf-admin",
                title: "CSRF Admin Action Abuse",
                difficulty: "Advanced",
                xp: 300,
                objective: "Force the administrator account to execute a delete user command.",
                scenario: "The management panel deletes users via GET request links like `/admin/delete?userId=105`. Embed a hidden request to trigger it.",
                hint1: "An image tag like `<img src='/admin/delete?userId=105'>` triggers a GET request on render.",
                hint2: "Post a comment inside the forum with an image source targeting the deletion API.",
                solution: "Submit a comment in the guestbook: `<img src='/admin/delete?userId=105' style='display:none'>`."
            }
        ],
        ctf: {
            id: "csrf-ctf",
            title: "Force Admin State Takeover",
            difficulty: "Medium",
            xp: 250,
            desc: "The admin checks a forum where comments are read. Post a stored comment that triggers an administrative state change to add user `hacker` as admin by targeting the endpoint `/admin/set-role?user=hacker&role=admin`. Obtain the flag from console logs once completed.",
            hint1: "Use an image tag source attribute inside the comments to trigger the GET route.",
            hint2: "Comment payload: `<img src='/admin/set-role?user=hacker&role=admin' onerror='console.log(1)'>`.",
            solution: "Post comment: `<img src=\"/admin/set-role?user=hacker&role=admin\" onerror=\"console.log('trigger')\">`. Then check logs."
        }
    },
    {
        id: "upload",
        title: "File Upload Vulnerabilities",
        category: "Input Validation",
        what: "File Upload vulnerabilities occur when a web application allows users to upload files to the server filesystem without properly verifying their content-type, extension, size, or execution permissions.",
        how: "Attackers upload server-side scripts (like PHP, ASP, or Node files) masked as images. Once uploaded, they browse to the file directly to execute commands on the host (Remote Code Execution).",
        impact: "Remote Code Execution (RCE), full server takeover, website defacement, or local file access.",
        prevention: [
            "Validate file extensions against a strict allowlist",
            "Verify file content-type (MIME type) and file signatures",
            "Store uploaded files on a separate, sandboxed file server/S3",
            "Disable execution permissions on upload directories"
        ],
        example: "A photo uploader accepts a file named `backdoor.php`. If server runs PHP, browsing to `/uploads/backdoor.php` executes server code.",
        filename: "upload.php",
        vulnCode: `<?php\n$target = "uploads/" . $_FILES["file"]["name"];\n// Vulnerable: Moves file directly without checking extension!\nmove_uploaded_file($_FILES["file"]["tmp_name"], $target);\n?>`,
        secureCode: `<?php\n$filename = $_FILES["file"]["name"];\n$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));\n$allowed = array('jpg', 'jpeg', 'png', 'gif');\n\n// Secure: Enforce strict allowlist check\nif (in_array($ext, $allowed)) {\n    move_uploaded_file($_FILES["file"]["tmp_name"], "uploads/" . uniqid() . "." . $ext);\n} else {\n    die("Invalid file type.");\n}\n?>`,
        explainer: "The vulnerable system takes the file name directly and saves it. The secure version uses a whitelist of extensions, renames the file using a random unique ID to prevent directory bypasses, and checks the actual content format.",
        labs: [
            {
                id: "upload-basic",
                title: "Unrestricted Shell Upload",
                difficulty: "Basic",
                xp: 100,
                objective: "Upload a php script and execute a terminal command.",
                scenario: "A profile portal allows file uploads. The backend has no filters. Upload a web backdoor.",
                hint1: "Select a .php file to upload. Select the file backdoor.php.",
                hint2: "Upload the script, then access the file link to access a simulated shell terminal.",
                solution: "Click Browse File, choose 'backdoor.php' from mock filesystem, click Upload. Click the resulting link to execute commands."
            },
            {
                id: "upload-mime",
                title: "Content-Type Bypass",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Bypass a MIME check by editing request headers.",
                scenario: "A portal validates files by checking the `Content-Type` header. Upload `webshell.php` by spoofing it as an image.",
                hint1: "Upload a PHP file. Check Proxy logs where headers are exposed.",
                hint2: "Change the parameter `Content-Type: application/x-php` to `Content-Type: image/png` in the HTTP Proxy tab, then send.",
                solution: "Select a php file. Open DevTools Proxy logs. Change Content-Type in intercepted payload to image/png, and submit."
            },
            {
                id: "upload-shell",
                title: "Web Shell RCE Execution",
                difficulty: "Advanced",
                xp: 300,
                objective: "Execute `cat /var/www/flag.txt` inside a web shell environment.",
                scenario: "Use a successfully uploaded server script terminal to retrieve secret server flags.",
                hint1: "Click terminal prompt inside the upload success frame.",
                hint2: "Type command: `cat /var/www/flag.txt` and hit Enter.",
                solution: "Go to terminal window on web shell page, execute command: `cat /var/www/flag.txt`."
            }
        ],
        ctf: {
            id: "upload-ctf",
            title: "Webshell Flag Grabber",
            difficulty: "Hard",
            xp: 300,
            desc: "The application has a black-list blocking `.php` files, but allows `.php5` extensions. Upload a shell named `exploit.php5` and open the terminal to run `cat flag.txt` and secure the token.",
            hint1: "Try renaming file extension to .php5 or .phtml to bypass php blacklist.",
            hint2: "Submit exploit.php5 file, click on the upload path, run `cat flag.txt`.",
            solution: "1. Upload 'exploit.php5'. 2. Click the path link. 3. Type `cat flag.txt` in the terminal prompt."
        }
    },
    {
        id: "traversal",
        title: "Path Traversal",
        category: "Input Validation",
        what: "Path Traversal (or Directory Traversal) allows attackers to read arbitrary files on the server running an application, such as application code, system credentials, or database configurations.",
        how: "By inputting characters like `../` into file-fetching parameters, attackers climb out of the web root directory into root system files (like `/etc/passwd`).",
        impact: "Exposure of sensitive source code, passwords, configuration tokens, and system information.",
        prevention: [
            "Avoid passing user inputs directly to file APIs",
            "Use pre-defined whitelists of safe file directories",
            "Sanitize input to strip path characters (`../` and `..\\`)",
            "Enforce strict read-only system permissions for the web server"
        ],
        example: "A PDF viewer uses URL `/get-file?file=report.pdf`. Attackers request `/get-file?file=../../../../etc/passwd` to read Linux configurations.",
        filename: "file.js",
        vulnCode: `const fs = require('fs');\napp.get('/download', (req, res) => {\n  // Vulnerable: Directly appends user string to folder path!\n  const filepath = "/var/www/public/" + req.query.file;\n  res.sendFile(filepath);\n});`,
        secureCode: `const path = require('path');\napp.get('/download', (req, res) => {\n  const filename = path.basename(req.query.file); // Safe: strips folder paths!\n  const safePath = path.join("/var/www/public/", filename);\n  res.sendFile(safePath);\n});`,
        explainer: "The vulnerable version reads any path constructed by the string. The secure code uses `path.basename` to extract only the file name, preventing directory traversal prefixes like `../../`.",
        labs: [
            {
                id: "traversal-basic",
                title: "Basic Path Traversal",
                difficulty: "Basic",
                xp: 100,
                objective: "Retrieve the system database configuration file `/etc/passwd`.",
                scenario: "A dynamic file viewer parameters references document paths. Climb to the system root.",
                hint1: "The URL has ?file=report.pdf. Enter relative paths.",
                hint2: "Inject `../../../../etc/passwd`.",
                solution: "Change the URL bar parameter to `?file=../../../../etc/passwd` and reload."
            },
            {
                id: "traversal-filter",
                title: "Filter Strip Traversal",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Bypass a `../` filter to fetch `/etc/passwd`.",
                scenario: "The server strips simple `../` patterns. Find a payload that evades this replacement filter.",
                hint1: "If the filter is non-recursive, replacing `../` inside `....//` leaves `../` behind.",
                hint2: "Inject `....//....//....//....//etc/passwd`.",
                solution: "Set URL query parameter to `?file=....//....//....//....//etc/passwd`."
            },
            {
                id: "traversal-sensitive",
                title: "Config File Discovery",
                difficulty: "Advanced",
                xp: 300,
                objective: "Extract the system credentials from `/var/www/config/settings.yaml`.",
                scenario: "Explore the directory layout to locate hidden configuration secrets using relative routes.",
                hint1: "Determine your relative path directory from /var/www/public/images/.",
                hint2: "Go back two folders and go into config: `../../config/settings.yaml`.",
                solution: "Set URL parameter to `?file=../../config/settings.yaml`."
            }
        ],
        ctf: {
            id: "traversal-ctf",
            title: "Sensitive Flag Locator",
            difficulty: "Medium",
            xp: 250,
            desc: "The system reads files from `/app/public/`. Use directory traversal to read a file located at `/var/www/flags/flag.txt` to recover the flag token.",
            hint1: "Go back from app/public/ using multiple directory traversals: `../../../../var/www/flags/flag.txt`.",
            hint2: "URL query format: `?file=../../../../var/www/flags/flag.txt`.",
            solution: "Change URL parameter to `?file=../../../../var/www/flags/flag.txt` in the URL input bar and hit Enter."
        }
    },
    {
        id: "auth",
        title: "Authentication Vulnerabilities",
        category: "Auth & Access",
        what: "Authentication vulnerabilities occur when an application improperly designs credentials logic, allowing malicious actors to compromise sessions, guess passwords, or spoof active login tokens.",
        how: "Attackers brute-force simple login endpoints, intercept session tokens, or reuse static session IDs to claim other accounts.",
        impact: "Full account take-over, data deletion, and administration bypass.",
        prevention: [
            "Enforce strong password complexity rules",
            "Implement multi-factor authentication (MFA)",
            "Enforce login rate limiting or account lockouts",
            "Generate cryptographically secure session IDs that change on login"
        ],
        example: "A website uses session ID cookies containing simple incremental values: `session=105`. Changing value to `106` logs user in as someone else.",
        filename: "auth.go",
        vulnCode: `// Vulnerable: checks password without rate limiting, exposing login to brute-force!\nfunc Login(user, pass string) bool {\n    return db.CheckCreds(user, pass)\n}`,
        secureCode: `// Secure: Lock account temporarily after 5 failed attempts\nfunc Login(user, pass string) bool {\n    if isLocked(user) {\n        return false\n    }\n    ok := db.CheckCreds(user, pass)\n    if !ok {\n        trackFailedAttempt(user)\n    } else {\n        resetFailedAttempts(user)\n    }\n    return ok\n}`,
        explainer: "The vulnerable version permits infinite rapid guesses. The secure method locks the account or inserts artificial delays after a threshold of failed login requests.",
        labs: [
            {
                id: "auth-brute",
                title: "Weak Password Brute Force",
                difficulty: "Basic",
                xp: 100,
                objective: "Find the administrator's password from a wordlist of 10 passwords.",
                scenario: "The administration login lacks rate limits. Try credentials sequentially from the wordlist.",
                hint1: "Try common choices like 'admin', 'password', '123456', or 'password123'.",
                hint2: "A dictionary lists 'admin123' or 'superadmin'. Check credentials list.",
                solution: "Type password `admin123` with username `admin` and log in."
            },
            {
                id: "auth-fixation",
                title: "Session Fixation Exploit",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Capture admin access by fixating a static session token.",
                scenario: "An login page retains user-defined session keys. Set the session identifier before sending a login page link.",
                hint1: "Add cookie `session_id=fixated_token` using DevTools, then reload.",
                hint2: "Force a login with the cookie preset.",
                solution: "1. Add a cookie `session_id=attacker_token` in DevTools. 2. Login to the application. The cookie is fixated."
            },
            {
                id: "auth-hijack",
                title: "Session Hijacking Capture",
                difficulty: "Advanced",
                xp: 300,
                objective: "Locate a token inside HTTP proxy logs and use it to hijack user sessions.",
                scenario: "A user communicates over unencrypted channels. Analyze network requests to steal their active cookie.",
                hint1: "Open the DevTools 'Proxy Logs' tab.",
                hint2: "Find a cookie token in the headers log like `session=hijack_992`. Set it in Cookies tab.",
                solution: "Go to DevTools -> Proxy Logs, find cookie string, add it to Cookies tab as `session` = stolen token."
            }
        ],
        ctf: {
            id: "auth-ctf",
            title: "Admin Account Capture",
            difficulty: "Medium",
            xp: 250,
            desc: "Brute-force the password of user account `admin`. Try passwords from the given intruder listing inside the lab to locate the flag token.",
            hint1: "Intruder list: 'welcome', 'root', 'security', 'dragon', 'shadow'. Try them one by one.",
            hint2: "Password matches 'shadow'. Logs in to reveal flag.",
            solution: "Login with Username: `admin`, Password: `shadow`. Submit."
        }
    },
    {
        id: "ssrf",
        title: "Server-Side Request Forgery (SSRF)",
        category: "Network Vulnerabilities",
        what: "SSRF occurs when a web server fetches remote resources (like files or status pages) based on user-supplied URLs without restricting destination IPs, allowing attackers to force the server to query internal networks.",
        how: "By inputting internal IP targets (like `http://127.0.0.1` or `http://169.254.169.254`) into URL input boxes, attackers bypass network firewalls to read internal services.",
        impact: "Access to internal system APIs, extraction of cloud metadata keys (AWS/Azure/GCP credentials), port scanning of local networks.",
        prevention: [
            "Restrict destination endpoints using a strict domain allowlist",
            "Block requests directed to loopback (`127.0.0.1`) and private IP ranges",
            "Disable URL redirection processing within your HTTP client library",
            "Isolate the web server on a secure, restricted network VLAN"
        ],
        example: "A webpage converter fetches URLs to render PDFs: `/convert?url=google.com`. Attackers request `/convert?url=http://127.0.0.1:8080/admin`.",
        filename: "fetch.py",
        vulnCode: `import requests\n# Vulnerable: fetches any remote URL directly, letting users query internal ports!\ndef fetch_url(user_url):\n    return requests.get(user_url).text`,
        secureCode: `from urllib.parse import urlparse\nimport socket\n\ndef fetch_url(user_url):\n    # Secure: resolve hostname and block loopback/private networks\n    hostname = urlparse(user_url).hostname\n    ip = socket.gethostbyname(hostname)\n    if ip.startswith("127.") or ip.startswith("192.168."):\n        raise ValueError("Access to internal networks is forbidden.")\n    return requests.get(user_url).text`,
        explainer: "The vulnerable server sends a request to whatever address is supplied. The secure code parses the URL, resolves its IP, and blocks local addresses like localhost (`127.0.0.1`) or private networks.",
        labs: [
            {
                id: "ssrf-basic",
                title: "Internal Site Fetching",
                difficulty: "Basic",
                xp: 100,
                objective: "Request the internal web server panel at `http://127.0.0.1:80/admin`.",
                scenario: "A server has a page thumbnail downloader tool. Force it to fetch local pages.",
                hint1: "Enter the loopback URL in the input field.",
                hint2: "URL target: `http://127.0.0.1/admin`.",
                solution: "Type `http://127.0.0.1/admin` into the URL field and request."
            },
            {
                id: "ssrf-meta",
                title: "Cloud Metadata Access",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Fetch AWS credentials from the cloud metadata service URL.",
                scenario: "A web proxy runs on cloud infrastructure. Query metadata IPs to extract keys.",
                hint1: "AWS metadata is located at `http://169.254.169.254/latest/meta-data/`.",
                hint2: "Enter the full path `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`.",
                solution: "Type `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin` into the fetch input."
            },
            {
                id: "ssrf-scan",
                title: "Internal Service Port Scan",
                difficulty: "Advanced",
                xp: 300,
                objective: "Locate the port hosting the internal database server.",
                scenario: "Use SSRF response statuses to port scan localhost and discover open services.",
                hint1: "Test different ports: `http://127.0.0.1:port`. Standard database ports are 3306, 5432, 6379.",
                hint2: "Port 6379 hosts Redis database, which returns system data.",
                solution: "Type `http://127.0.0.1:6379` in the input field. The response confirms connection."
            }
        ],
        ctf: {
            id: "ssrf-ctf",
            title: "Cloud Metadata Miner",
            difficulty: "Hard",
            xp: 300,
            desc: "The metadata API is blocked, but the server follows redirects. Host a mock redirect on an external server, or use an open redirect parameter on the website to trick the SSRF engine into reading `http://169.254.169.254/latest/meta-data/flag`.",
            hint1: "Find an open redirect parameter on the portal: `/redirect?url=...`.",
            hint2: "Combine SSRF target: `http://vulnerable-site.local/redirect?url=http://169.254.169.254/latest/meta-data/flag`.",
            solution: "Input target URL: `http://vulnerable-site.local/redirect?url=http://169.254.169.254/latest/meta-data/flag` into SSRF form."
        }
    },
    {
        id: "misconfig",
        title: "Security Misconfiguration",
        category: "Configuration",
        what: "Security Misconfiguration occurs when an application is deployed with default configurations, exposed debugging consoles, verbose error pages, or open files containing developer backups.",
        how: "Attackers check websites for exposed config files (like `.git/config` or `composer.json`), check default directories, and intentionally trigger errors to read database passwords in stack traces.",
        impact: "Information leakage, full administrative takeover, and database access.",
        prevention: [
            "Disable debug mode and verbose error messages in production",
            "Remove unused modules, default scripts, and demo accounts",
            "Block access to directories like `.git/` in web server settings",
            "Audit permissions and keep configurations updated"
        ],
        example: "A web app crashes and prints full database connection string (`db_user=admin, db_pass=secret123`) on the screen in a stack trace.",
        filename: "web.config",
        vulnCode: `<!-- Vulnerable: customErrors is disabled, showing full debug stack traces to visitors! -->\n<configuration>\n  <system.web>\n    <customErrors mode="Off"/>\n  </system.web>\n</configuration>`,
        secureCode: `<!-- Secure: customErrors is enabled, redirecting users to a generic error page -->\n<configuration>\n  <system.web>\n    <customErrors mode="On" defaultRedirect="Error.html"/>\n  </system.web>\n</configuration>`,
        explainer: "The vulnerable config shows development errors to any visitor. The secure config redirects users to a generic error screen, preventing the exposure of credentials in stack traces.",
        labs: [
            {
                id: "misconfig-robots",
                title: "Robots.txt Directory Leak",
                difficulty: "Basic",
                xp: 100,
                objective: "Find the secret administration path page listing backups.",
                scenario: "A site exposes directories inside robots.txt. Read the index rules.",
                hint1: "Examine `http://vulnerable.local/robots.txt`.",
                hint2: "Navigate to the path marked Disallow.",
                solution: "Type `http://vulnerable.local/robots.txt` in URL bar, note the hidden path `/backup-credentials`, and go there."
            },
            {
                id: "misconfig-debug",
                title: "Debug Error Stack Leak",
                difficulty: "Intermediate",
                xp: 200,
                objective: "Force an error to reveal environment variables and database password.",
                scenario: "The production site retains active debug screens. Trigger an error with invalid queries.",
                hint1: "Submit invalid formatting parameter, like sending letters for numeric ID values.",
                hint2: "Send `?id[]=test` or trigger syntax crashes to load dump variables.",
                solution: "Type `?id[]=invalid` in the URL parameter line and refresh. Extract the password from the variables list."
            },
            {
                id: "misconfig-git",
                title: "Git Repository Exposure",
                difficulty: "Advanced",
                xp: 300,
                objective: "Access the hidden repository files at `/.git/config`.",
                scenario: "A website is uploaded with its configuration repository. Download config files.",
                hint1: "Append `/.git/config` to the base web directory.",
                hint2: "URL target: `http://vulnerable.local/.git/config`.",
                solution: "Type `http://vulnerable.local/.git/config` in URL bar and hit enter."
            }
        ],
        ctf: {
            id: "misconfig-ctf",
            title: "Git Config Flag Leak",
            difficulty: "Hard",
            xp: 300,
            desc: "The development site exposed its git repo. Fetch the config file at `/.git/config` and read the git token flag from the server description properties.",
            hint1: "Load the file `/.git/config` via simulated URL bar.",
            hint2: "Examine database configs and find token variable: flag=...",
            solution: "Change URL address to: `http://vulnerable.local/.git/config` and press Enter. Extract the flag token."
        }
    }
];

const CTF_CHALLENGES = [
    // EASY CHALLENGES (10)
    {
        id: "ctf-easy-1",
        category: "Information Disclosure",
        title: "HTML Comment Leak",
        difficulty: "Easy",
        xp: 150,
        desc: "Web developers often leave comments in the HTML source code. Review the source of the target page and find the flag.",
        hint1: "Use the 'View Source' action or look at the comments tab.",
        hint2: "Comments format: `<!-- flag -->`.",
        solution: "Open 'View Source' inside sandbox, scroll down to find `<!-- FLAG: [captured flag] -->`."
    },
    {
        id: "ctf-easy-2",
        category: "Cookie Tampering",
        title: "Cookie Monster",
        difficulty: "Easy",
        xp: 150,
        desc: "The web page displays an admin flag if you are logged in as admin. Cookies manage user identity. Tamper with the cookies.",
        hint1: "Open DevTools -> Cookies tab.",
        hint2: "Look for cookie named `admin`. Change its value from `false` to `true`.",
        solution: "In DevTools -> Cookies, set key `admin` to value `true`. Refresh address bar."
    },
    {
        id: "ctf-easy-3",
        category: "Source Code Review",
        title: "Developer Credentials",
        difficulty: "Easy",
        xp: 150,
        desc: "A client validation script contains hardcoded login data. Inspect the source file and find credentials.",
        hint1: "View JavaScript file `auth.js` in page source viewer.",
        hint2: "Search variable `const admin_pass = ...`.",
        solution: "Review `auth.js` source, locate credentials, log in with password `cyber_god_2026` to get flag."
    },
    {
        id: "ctf-easy-4",
        category: "Information Disclosure",
        title: "Robots Crawler",
        difficulty: "Easy",
        xp: 150,
        desc: "Find directories blocked from web crawlers. Navigate to files to secure the flag.",
        hint1: "Go to `/robots.txt`.",
        hint2: "Find path marked Disallow: `/secret-stash/flag.txt`.",
        solution: "Query `/robots.txt`, visit `/secret-stash/flag.txt` to read the token."
    },
    {
        id: "ctf-easy-5",
        category: "Cryptography",
        title: "Base64 Cipher",
        difficulty: "Easy",
        xp: 150,
        desc: "A developer encoded the flag using Base64 cipher encoding. Decode the token: `U1B7YmFzZTY0X2RlY29kZV9zdWNjZXNzfQ==`.",
        hint1: "Base64 encoded strings often end with = padding.",
        hint2: "Use a decoder tool or terminal command `echo -n token | base64 -d`.",
        solution: "Use base64 decoder in sandbox to resolve `U1B7YmFzZTY0X2RlY29kZV9zdWNjZXNzfQ==`."
    },
    {
        id: "ctf-easy-6",
        category: "Headers Interception",
        title: "HTTP Custom Header",
        difficulty: "Easy",
        xp: 150,
        desc: "The web application sends custom headers in response data. Intercept response headers to read the flag.",
        hint1: "Open DevTools -> Proxy Logs.",
        hint2: "Find header line starting with `X-Custom-Flag`.",
        solution: "Open Proxy Logs, find X-Custom-Flag: [captured flag] header."
    },
    {
        id: "ctf-easy-7",
        category: "Parameter Tampering",
        title: "Free Checkout",
        difficulty: "Easy",
        xp: 150,
        desc: "A shopping cart application stores item prices inside hidden inputs. Edit parameters to checkout a $1000 laptop for free.",
        hint1: "Inspect elements or check input fields.",
        hint2: "Change price attribute from `1000` to `0` and press Buy.",
        solution: "In checkout preview, edit price input value to 0, and click Purchase."
    },
    {
        id: "ctf-easy-8",
        category: "Headers Interception",
        title: "Admin Agent Spoofing",
        difficulty: "Easy",
        xp: 150,
        desc: "The admin dashboard only loads for browsers matching the User-Agent: `SecurityPlaygroundAdmin`.",
        hint1: "Open Proxy logs or DevTools headers tab.",
        hint2: "Inject request header `User-Agent: SecurityPlaygroundAdmin` and refresh.",
        solution: "Go to Proxy logs, add request header `User-Agent: SecurityPlaygroundAdmin`, reload address."
    },
    {
        id: "ctf-easy-9",
        category: "Parameter Tampering",
        title: "Fuzzing Invoice IDs",
        difficulty: "Easy",
        xp: 150,
        desc: "An invoice app uses direct ID parameters. Try to find the admin invoice by guessing the ID value.",
        hint1: "URL has ?id=4. Try a lower number or 0.",
        hint2: "Invoice index is located at ID value 0.",
        solution: "Change URL parameter to `?id=0` and submit."
    },
    {
        id: "ctf-easy-10",
        category: "Logic Flaws",
        title: "Blank Password Check",
        difficulty: "Easy",
        xp: 150,
        desc: "The login check fails to validate blank values. Authenticate as admin by removing the password parameter entirely.",
        hint1: "Tamper with HTTP POST parameters in the Proxy Logs tab's editable Request Body box.",
        hint2: "Delete the `&pass=...` part from the Request Body box entirely, then click Sign In.",
        solution: "In Proxy Logs, remove password from POST parameters, click Send."
    },
    // MEDIUM CHALLENGES (10)
    {
        id: "ctf-medium-11",
        category: "JWT Manipulation",
        title: "JWT None Algorithm",
        difficulty: "Medium",
        xp: 300,
        desc: "The JWT check accepts the `none` algorithm token signature. Change `alg` to `none` in JWT header and set your role payload to admin.",
        hint1: "A JWT format is header.payload.signature.",
        hint2: "JWT Header: `{\"alg\":\"none\",\"typ\":\"JWT\"}`. JWT Payload: `{\"role\":\"admin\"}`.",
        solution: "Input JWT token containing alg:none header and role:admin payload in the auth field."
    },
    {
        id: "ctf-medium-12",
        category: "IDOR",
        title: "API Token Disclosure",
        difficulty: "Medium",
        xp: 300,
        desc: "Tamper with user accounts APIs `/api/users/v1/105` to fetch user profiles data, and scan profile keys.",
        hint1: "Search index 100.",
        hint2: "Request `/api/users/v1/100`.",
        solution: "Fetch `/api/users/v1/100` in the simulated address."
    },
    {
        id: "ctf-medium-13",
        category: "Cryptography",
        title: "Weak Hash Cracking",
        difficulty: "Medium",
        xp: 300,
        desc: "Crack the administrator MD5 password hash: `099ebea48ea9666a7da217726b4da513` to login.",
        hint1: "Use hash search dictionary list.",
        hint2: "MD5 hash decodes to word: 'hunter2'.",
        solution: "Decode MD5 hash to 'hunter2', log in with Username: admin, Password: hunter2."
    },
    {
        id: "ctf-medium-14",
        category: "XML External Entity (XXE)",
        title: "XML File Parser Injection",
        difficulty: "Medium",
        xp: 300,
        desc: "An XML file parser accepts entity structures. Inject an external entity to read the server file `/etc/flag.txt`.",
        hint1: "Use entity reference `<!ENTITY xxe SYSTEM \"file:///etc/flag.txt\">`.",
        hint2: "XML payload: `<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/flag.txt\">]><query>&xxe;</query>`.",
        solution: "Send XML payload with external entity reference to load system files."
    },
    {
        id: "ctf-medium-15",
        category: "SQL Injection",
        title: "Blind SQLi Numeric Check",
        difficulty: "Medium",
        xp: 300,
        desc: "Locate flag character indices using SQL query responses. (True = Item exists, False = Error).",
        hint1: "Use `' AND (SELECT 1)=1 --`.",
        hint2: "Run conditional search logic.",
        solution: "Submit query parameter: `1' AND 1=1 --` to verify SQL behavior and retrieve data."
    },
    {
        id: "ctf-medium-16",
        category: "Insecure Deserialization",
        title: "PHP Serialized Tampering",
        difficulty: "Medium",
        xp: 300,
        desc: "Tamper with a base64 encoded PHP serialized object cookie: `Tzo0OiJVc2VyIjoyOntzOjQ6InVzZXIiO3M6NToiZ3Vlc3QiO3M6NToiaXNBZG0iO2I6MDt9` to set isAdmin to true.",
        hint1: "Base64 decodes to: `O:4:\"User\":2:{s:4:\"user\";s:5:\"guest\";s:5:\"isAdmin\";b:0;}`.",
        hint2: "Change `b:0` to `b:1` in string, encode to Base64, and save in cookie.",
        solution: "Input cookie containing base64 representation of role-escalated serialized object."
    },
    {
        id: "ctf-medium-17",
        category: "Source Code Review",
        title: "Git Commit History audit",
        difficulty: "Medium",
        xp: 300,
        desc: "Examine mock public git repo commits log database to retrieve api keys.",
        hint1: "Check commit message: 'revert database credentials'.",
        hint2: "Look at commit hashes and code modifications.",
        solution: "Review commit list, locate deleted password line inside history."
    },
    {
        id: "ctf-medium-18",
        category: "CORS Misconfiguration",
        title: "CORS Wildcard Read",
        difficulty: "Medium",
        xp: 300,
        desc: "The API uses a wildcard cross-origin access configuration. Abuse CORS permissions to access server settings.",
        hint1: "Read response headers. See `Access-Control-Allow-Origin: *`.",
        hint2: "Simulate an external request header fetch to local api.",
        solution: "Run request with custom Origin header to read sensitive credentials."
    },
    {
        id: "ctf-medium-19",
        category: "Rate Limit Bypass",
        title: "Forwarded For bypass",
        difficulty: "Medium",
        xp: 300,
        desc: "Bypass login IP limit blockages by spoofing X-Forwarded-For header values.",
        hint1: "Add request header: `X-Forwarded-For: 127.0.0.1`.",
        hint2: "Change IP header value on each login try.",
        solution: "Tamper headers to change X-Forwarded-For IPs on successive authentication calls."
    },
    {
        id: "ctf-medium-20",
        category: "Cryptography",
        title: "XOR Simple Cipher",
        difficulty: "Medium",
        xp: 300,
        desc: "A token is encrypted with an XOR key. Key is `hacker`. Cipher bytes hex: `3c071a171d1810141f01031317`.",
        hint1: "Decrypt XOR payload bytes using key string characters repetitively.",
        hint2: "XOR decode output resolves to target flag.",
        solution: "Run XOR operations to extract flag token."
    },
    // HARD CHALLENGES (10)
    {
        id: "ctf-hard-21",
        category: "JWT Manipulation",
        title: "JWT Weak Secret Crack",
        difficulty: "Hard",
        xp: 500,
        desc: "The server signs JWT with weak secret key `123456`. Crack key, craft admin JWT, sign and submit.",
        hint1: "Sign admin payload using secret: `123456`.",
        hint2: "Change payload username to admin, sign using SHA-256.",
        solution: "Create signed admin token using secret 123456."
    },
    {
        id: "ctf-hard-22",
        category: "SSTI",
        title: "Server Template Injection",
        difficulty: "Hard",
        xp: 500,
        desc: "The node templates parser handles math inputs recursively. Inject template variables commands to trigger flag reading.",
        hint1: "Try evaluation statements: `{{7*7}}` or `#{7*7}`.",
        hint2: "Inject `{{child_process.execSync('cat flag.txt')}}`.",
        solution: "Send SSTI math payload syntax to execute server commands."
    },
    {
        id: "ctf-hard-23",
        category: "Prototype Pollution",
        title: "Prototype Property Pollution",
        difficulty: "Hard",
        xp: 500,
        desc: "Pollute object templates properties in JSON parameters to override `isAdmin` settings in checking scripts.",
        hint1: "Inject property `\"__proto__\": {\"isAdmin\": true}`.",
        hint2: "POST body JSON payload must contain prototype pollution fields.",
        solution: "Submit POST parameters modifying prototype attributes."
    },
    {
        id: "ctf-hard-24",
        category: "SQL Injection",
        title: "SQLi Into Outfile Web Shell",
        difficulty: "Hard",
        xp: 500,
        desc: "Use SQL Injection write query permissions to drop a php shell on the disk `/var/www/uploads/shell.php`.",
        hint1: "Use UNION SELECT ... INTO OUTFILE '/var/www/uploads/shell.php'.",
        hint2: "Inject shell query parameters.",
        solution: "Input UNION output write SQL statements to create web shell."
    },
    {
        id: "ctf-hard-25",
        category: "SSRF",
        title: "SSRF DNS Rebinding Bypass",
        difficulty: "Hard",
        xp: 500,
        desc: "SSRF filter blocks standard local IP names. Access internal resources by rebinding DNS queries.",
        hint1: "Register domain names toggling local/public resolution.",
        hint2: "Use local IP shortcut: `http://0.0.0.0` or `http://[::]`.",
        solution: "Query `http://[::]/admin` or `http://0.0.0.0` to bypass IP checking routines."
    },
    {
        id: "ctf-hard-26",
        category: "SSRF",
        title: "Open Redirect to SSRF",
        difficulty: "Hard",
        xp: 500,
        desc: "SSRF host validator blocks cloud IPs, but follows redirects. Leverage website open redirect route `/redirect?url=...` to load metadata services.",
        hint1: "Redirect requests to private cloud addresses.",
        hint2: "Point SSRF target URL to open redirect parameter containing local IPs.",
        solution: "Query open redirect endpoints mapping internal cloud IP routes."
    },
    {
        id: "ctf-hard-27",
        category: "Logic Flaws",
        title: "Race Condition Checkout",
        difficulty: "Hard",
        xp: 500,
        desc: "A wallet has a $10 limit. Exploit check-out delay by sending 10 requests rapidly (simulated) to trigger double-spending.",
        hint1: "Press buy concurrently or activate bulk batch request command.",
        hint2: "Click simulated race-request tool.",
        solution: "Open race trigger tester, click 'Execute Rapid Requests' to trigger logical delay check."
    },
    {
        id: "ctf-hard-28",
        category: "Headers Interception",
        title: "Host Header Hijack",
        difficulty: "Hard",
        xp: 500,
        desc: "Tamper with Host request header to hijack email reset tokens sent to target server portals.",
        hint1: "Change `Host: site.local` to `Host: evil-server.local` in headers.",
        hint2: "Look at logs to intercept token data.",
        solution: "Submit Host header hijack inputs, read token link inside log files."
    },
    {
        id: "ctf-hard-29",
        category: "Logic Flaws",
        title: "PHP Type Juggling Bypass",
        difficulty: "Hard",
        xp: 500,
        desc: "Bypass weak md5 verification checks exploiting PHP loose comparisons `==` with `0e...` string hashes.",
        hint1: "Input password generating hash starting with '0e' and followed by numbers.",
        hint2: "Try password `240610708` which hashes to `0e462097431906509444084314745817`.",
        solution: "Enter password `240610708` to bypass loose comparisons."
    },
    {
        id: "ctf-hard-30",
        category: "API Security",
        title: "GraphQL Introspection Scan",
        difficulty: "Hard",
        xp: 500,
        desc: "Query GraphQL introspection endpoint `__schema` to discover private mutations and fetch keys.",
        hint1: "Send introspection query `{\"query\":\"{__schema{queryType{name}}}\"}`.",
        hint2: "Locate mutation named `getSecretFlag` and call it.",
        solution: "Submit GraphQL introspection query structures to uncover and run private fields."
    }
];

const ACHIEVEMENTS = [
    { id: "first-blood", title: "First Blood", desc: "Solve your first practice lab.", icon: "🩸" },
    { id: "script-kiddie", title: "Script Kiddie", desc: "Solve all Cross-Site Scripting (XSS) labs.", icon: "👾" },
    { id: "sql-maestro", title: "SQL Maestro", desc: "Solve all SQL Injection (SQLi) labs.", icon: "🔱" },
    { id: "gatekeeper-bypass", title: "Gatekeeper Bypass", desc: "Solve all Broken Access Control labs.", icon: "🔓" },
    { id: "idor-miner", title: "IDOR Miner", desc: "Solve all IDOR labs.", icon: "💎" },
    { id: "csrf-ninja", title: "CSRF Ninja", desc: "Solve all CSRF labs.", icon: "👤" },
    { id: "shell-operator", title: "Shell Operator", desc: "Solve all File Upload labs.", icon: "🐚" },
    { id: "path-finder", title: "Path Finder", desc: "Solve all Path Traversal labs.", icon: "🗺️" },
    { id: "brute-forcer", title: "Brute Forcer", desc: "Solve all Authentication labs.", icon: "🔨" },
    { id: "ssrf-agent", title: "SSRF Agent", desc: "Solve all SSRF labs.", icon: "🛰️" },
    { id: "system-auditor", title: "System Auditor", desc: "Solve all Security Misconfiguration labs.", icon: "⚙️" },
    { id: "ctf-hunter", title: "Flag Hunter", desc: "Solve 10 CTF Arena challenges.", icon: "🏁" }
];

// ==========================================
// 3. UI Routing & Navigation
// ==========================================

function switchTab(viewId) {
    // Update active nav button
    document.querySelectorAll(".nav-btn").forEach(btn => {
        if (btn.getAttribute("data-target") === viewId) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    // Update active content view
    document.querySelectorAll(".content-view").forEach(view => {
        if (view.id === `view-${viewId}`) {
            view.classList.add("active");
        } else {
            view.classList.remove("active");
        }
    });

    // Update Header Page Title
    const pageTitles = {
        dashboard: "Dashboard Overview",
        learn: "Vulnerability Academy",
        ctf: "CTF Arena challenges",
        progress: "Hacking Progress & Stats",
        about: "About the Sandbox"
    };
    document.getElementById("pageTitle").innerText = pageTitles[viewId] || "Security Playground";

    // Close mobile menu
    document.getElementById("sidebar").classList.remove("active");
}

// Global scope bindings for navigation switches
window.switchTab = switchTab;

// Handle Sidebar toggle on Mobile
document.getElementById("menuToggleBtn").addEventListener("click", () => {
    document.getElementById("sidebar").classList.add("active");
});
document.getElementById("mobileCloseBtn").addEventListener("click", () => {
    document.getElementById("sidebar").classList.remove("active");
});

// ==========================================
// 4. Vulnerability & Labs List Rendering
// ==========================================

let selectedVulnIdx = 0;

function renderVulnerabilities() {
    const listMenu = document.getElementById("vulnListMenu");
    listMenu.innerHTML = "";

    VULNERABILITIES.forEach((v, idx) => {
        const li = document.createElement("li");
        
        // Count solved labs in this category
        const totalLabs = v.labs.length;
        let solvedCount = 0;
        v.labs.forEach(l => {
            if (userState.solvedLabs.includes(l.id)) solvedCount++;
        });

        // Determine solved state indicators
        let dotsHtml = "";
        v.labs.forEach(l => {
            const isSolved = userState.solvedLabs.includes(l.id);
            dotsHtml += `<span class="vuln-dot ${isSolved ? 'solved' : ''}"></span>`;
        });

        const activeClass = idx === selectedVulnIdx ? "active" : "";
        li.innerHTML = `
            <button class="vuln-item-btn ${activeClass}" onclick="selectVulnerability(${idx})">
                <span class="vuln-item-title">${v.title.split(" ")[0]} ${v.title.split(" ").slice(1).join(" ")}</span>
                <span class="vuln-item-dots">
                    ${dotsHtml}
                </span>
            </button>
        `;
        listMenu.appendChild(li);
    });

    loadVulnerability(selectedVulnIdx);
}

function selectVulnerability(idx) {
    selectedVulnIdx = idx;
    renderVulnerabilities();
}

window.selectVulnerability = selectVulnerability;

// ==========================================
// Attack Flow Animation Engine
// ==========================================
// Generic player for the ATTACK_FLOWS data (see attackFlows.js). Moves a
// packet between 4 fixed actor positions, updates a caption per step, and
// shows a breach/defended outcome banner at the end of the sequence.

const animState = {
    vulnId: null,
    mode: "breach",      // "breach" | "defended"
    stepIndex: -1,       // -1 = not started
    steps: [],
    playing: false,
    timer: null,
};

const ANIM_ACTOR_KEYS = ["a", "b", "c", "d"];

function initAttackAnimation(vulnId) {
    const flow = ATTACK_FLOWS[vulnId];
    if (!flow) return;

    animState.vulnId = vulnId;
    animState.mode = "breach";

    document.getElementById("animModeBreachBtn").classList.add("active");
    document.getElementById("animModeDefendedBtn").classList.remove("active");
    document.getElementById("animTrack").classList.remove("mode-defended");

    ANIM_ACTOR_KEYS.forEach(key => {
        const actorDef = flow.actors[key];
        document.getElementById(`animIcon${key.toUpperCase()}`).innerText = actorDef.icon;
        document.getElementById(`animLabel${key.toUpperCase()}`).innerText = actorDef.label;
    });

    resetAnimToStart();
}

function getAnimSteps() {
    const flow = ATTACK_FLOWS[animState.vulnId];
    if (!flow) return [];
    return animState.mode === "breach" ? flow.breach : flow.defended;
}

function getAnimOutcome() {
    const flow = ATTACK_FLOWS[animState.vulnId];
    if (!flow) return null;
    return animState.mode === "breach" ? flow.breachOutcome : flow.defendedOutcome;
}

function setAnimMode(mode) {
    if (animState.mode === mode) return;
    stopAnimAutoplay();
    animState.mode = mode;

    document.getElementById("animModeBreachBtn").classList.toggle("active", mode === "breach");
    document.getElementById("animModeDefendedBtn").classList.toggle("active", mode === "defended");
    document.getElementById("animTrack").classList.toggle("mode-defended", mode === "defended");

    resetAnimToStart();
}

function actorCenterLeft(key) {
    const track = document.getElementById("animTrack");
    const actorEl = document.getElementById(`animActor${key.toUpperCase()}`);
    const packetEl = document.getElementById("animPacket");
    const trackRect = track.getBoundingClientRect();
    const actorRect = actorEl.getBoundingClientRect();
    const center = (actorRect.left - trackRect.left) + actorRect.width / 2;
    return center - packetEl.offsetWidth / 2;
}

function clearAnimActorStates() {
    ANIM_ACTOR_KEYS.forEach(key => {
        document.getElementById(`animActor${key.toUpperCase()}`).classList.remove("active-send", "active-receive");
    });
}

function resetAnimToStart() {
    stopAnimAutoplay();
    animState.stepIndex = -1;
    animState.steps = getAnimSteps();
    clearAnimActorStates();

    const packet = document.getElementById("animPacket");
    packet.classList.remove("visible", "pulse");

    if (animState.steps.length > 0) {
        packet.style.left = `${actorCenterLeft(animState.steps[0].from)}px`;
    }

    document.getElementById("animCaption").innerText = "Press Play to watch this attack happen, step by step.";
    document.getElementById("animOutcome").style.display = "none";
    document.getElementById("animPlayBtn").innerText = "▶ Play";
    updateAnimStepIndicator();
}

function updateAnimStepIndicator() {
    document.getElementById("animStepIndicator").innerText =
        `Step ${Math.max(0, animState.stepIndex + 1)} / ${animState.steps.length}`;
}

function stepAnimForward() {
    if (animState.stepIndex + 1 >= animState.steps.length) {
        stopAnimAutoplay();
        showAnimOutcome();
        return;
    }

    animState.stepIndex++;
    const step = animState.steps[animState.stepIndex];
    const packet = document.getElementById("animPacket");

    clearAnimActorStates();
    document.getElementById(`animActor${step.from.toUpperCase()}`).classList.add("active-send");
    document.getElementById(`animActor${step.to.toUpperCase()}`).classList.add("active-receive");

    packet.classList.add("visible");
    packet.innerText = step.packet || "📦";

    if (step.from === step.to) {
        // Self-step: this actor is processing — pulse in place, no travel.
        packet.style.left = `${actorCenterLeft(step.from)}px`;
        packet.classList.remove("pulse");
        requestAnimationFrame(() => packet.classList.add("pulse"));
    } else {
        packet.style.left = `${actorCenterLeft(step.to)}px`;
    }

    document.getElementById("animCaption").innerText = step.caption;
    updateAnimStepIndicator();

    if (animState.stepIndex + 1 >= animState.steps.length) {
        setTimeout(showAnimOutcome, 900);
    }
}

function showAnimOutcome() {
    const outcome = getAnimOutcome();
    if (!outcome) return;
    const el = document.getElementById("animOutcome");
    el.className = `anim-outcome ${animState.mode === "breach" ? "breach" : "defended"}`;
    el.innerHTML = `<span style="font-size:1.2rem;">${outcome.icon}</span> ${outcome.text}`;
    el.style.display = "flex";
    document.getElementById("animPlayBtn").innerText = "▶ Play";
}

function stopAnimAutoplay() {
    animState.playing = false;
    if (animState.timer) {
        clearInterval(animState.timer);
        animState.timer = null;
    }
}

function toggleAnimAutoplay() {
    if (animState.playing) {
        stopAnimAutoplay();
        document.getElementById("animPlayBtn").innerText = "▶ Play";
        return;
    }

    if (animState.stepIndex + 1 >= animState.steps.length) {
        resetAnimToStart();
    }

    animState.playing = true;
    document.getElementById("animPlayBtn").innerText = "⏸ Pause";
    animState.timer = setInterval(() => {
        if (animState.stepIndex + 1 >= animState.steps.length) {
            stopAnimAutoplay();
            return;
        }
        stepAnimForward();
    }, 1700);
}

document.getElementById("animModeBreachBtn").addEventListener("click", () => setAnimMode("breach"));
document.getElementById("animModeDefendedBtn").addEventListener("click", () => setAnimMode("defended"));
document.getElementById("animPlayBtn").addEventListener("click", toggleAnimAutoplay);
document.getElementById("animNextBtn").addEventListener("click", () => {
    stopAnimAutoplay();
    document.getElementById("animPlayBtn").innerText = "▶ Play";
    stepAnimForward();
});
document.getElementById("animReplayBtn").addEventListener("click", resetAnimToStart);

window.addEventListener("resize", () => {
    // Re-anchor the packet if the window resizes mid-animation.
    if (animState.stepIndex >= 0 && animState.steps[animState.stepIndex]) {
        const step = animState.steps[animState.stepIndex];
        document.getElementById("animPacket").style.left = `${actorCenterLeft(step.to)}px`;
    } else if (animState.steps.length > 0) {
        document.getElementById("animPacket").style.left = `${actorCenterLeft(animState.steps[0].from)}px`;
    }
});

function loadVulnerability(idx) {
    const vuln = VULNERABILITIES[idx];
    if (!vuln) return;

    // Load the attack flow animation for this vulnerability
    initAttackAnimation(vuln.id);

    // Reset active tab to Theory
    document.querySelectorAll(".vuln-tab").forEach(t => {
        if (t.getAttribute("data-tab") === "learn-theory") {
            t.classList.add("active");
        } else {
            t.classList.remove("active");
        }
    });
    document.querySelectorAll(".vuln-tab-content").forEach(c => {
        if (c.id === "tab-learn-theory") {
            c.classList.add("active");
        } else {
            c.classList.remove("active");
        }
    });

    document.getElementById("vulnIndex").innerText = String(idx + 1).padStart(2, '0');
    document.getElementById("vulnTitle").innerText = vuln.title;
    document.getElementById("vulnCategory").innerText = vuln.category;

    // Theory
    document.getElementById("theoryWhat").innerText = vuln.what;
    document.getElementById("theoryHow").innerText = vuln.how;
    document.getElementById("theoryImpactLevel").innerText = vuln.labs[2].difficulty === "Advanced" ? "High Impact" : "Medium Impact";
    document.getElementById("theoryImpact").innerText = vuln.impact;
    document.getElementById("theoryExample").innerText = vuln.example;

    const prevList = document.getElementById("theoryPrevention");
    prevList.innerHTML = "";
    vuln.prevention.forEach(p => {
        const li = document.createElement("li");
        li.innerText = p;
        prevList.appendChild(li);
    });

    // Comparison Code
    document.getElementById("comparisonFilename").innerText = vuln.filename;
    setupCodeComparison(vuln);

    // Labs Grid
    renderLabs(vuln.labs);

    // Mini CTF
    const ctf = vuln.ctf;
    document.getElementById("miniCtfTitle").innerText = ctf.title;
    document.getElementById("miniCtfDifficulty").innerText = ctf.difficulty;
    document.getElementById("miniCtfDesc").innerText = ctf.desc;
    
    // Mini CTF state checking
    const ctfSolved = userState.solvedCtfs.includes(ctf.id);
    const feedback = document.getElementById("miniCtfFeedback");
    const input = document.getElementById("miniCtfInput");
    const submitBtn = document.getElementById("miniCtfSubmitBtn");
    const retryBtn = document.getElementById("miniCtfRetryBtn");

    if (ctfSolved) {
        feedback.innerText = "Challenge Decaptured! Already solved.";
        feedback.className = "flag-feedback success";
        input.value = "(already submitted)";
        input.disabled = true;
        submitBtn.disabled = true;
        retryBtn.style.display = "inline-flex";
    } else {
        feedback.style.display = "none";
        input.value = "";
        input.disabled = false;
        submitBtn.disabled = false;
        retryBtn.style.display = "none";
    }

    // Bind Launch CTF
    document.getElementById("miniCtfLaunchBtn").onclick = () => {
        launchSandbox(ctf.id, true);
    };

    // Bind Submit CTF Flag
    document.getElementById("miniCtfSubmitBtn").onclick = () => {
        submitMiniCtfFlag(ctf);
    };

    // Bind Retry — lets a player practice the challenge again. Earned XP is
    // kept (no double-XP on resubmission since the backend already tracks
    // that this id was solved), this just resets the local UI so they can
    // re-attempt the exploit for practice.
    retryBtn.onclick = () => {
        userState.solvedCtfs = userState.solvedCtfs.filter(id => id !== ctf.id);
        feedback.style.display = "none";
        input.value = "";
        input.disabled = false;
        submitBtn.disabled = false;
        retryBtn.style.display = "none";
        renderVulnerabilities();
    };
}

// Code Comparison Toggle
let currentCompMode = "vulnerable";
function setupCodeComparison(vuln) {
    const codeContainer = document.getElementById("comparisonCode");
    const explainer = document.getElementById("comparisonExplainer");

    if (currentCompMode === "vulnerable") {
        codeContainer.textContent = vuln.vulnCode;
        explainer.textContent = vuln.explainer;
        explainer.className = "code-explainer-alert";
    } else {
        codeContainer.textContent = vuln.secureCode;
        explainer.textContent = "SECURE IMPLEMENTATION: Standard protection has been applied. Input parameters are separated from functional logic, preventing command or injection exploits.";
        explainer.className = "code-explainer-alert secure";
    }
}

document.querySelectorAll(".comp-tab").forEach(tab => {
    tab.addEventListener("click", (e) => {
        document.querySelectorAll(".comp-tab").forEach(t => t.classList.remove("active"));
        e.target.classList.add("active");
        currentCompMode = e.target.getAttribute("data-comp");
        setupCodeComparison(VULNERABILITIES[selectedVulnIdx]);
    });
});

// Render Labs cards
function renderLabs(labs) {
    const grid = document.getElementById("labsGrid");
    grid.innerHTML = "";

    labs.forEach(lab => {
        const isSolved = userState.solvedLabs.includes(lab.id);
        const card = document.createElement("div");
        card.className = `lab-card ${isSolved ? 'solved' : ''}`;
        
        card.innerHTML = `
            <div class="lab-status-indicator ${isSolved ? 'solved' : 'unsolved'}">
                ${isSolved ? '✓ Mastered' : 'Unsolved'}
            </div>
            <div class="lab-meta">
                <span class="difficulty-badge ${lab.difficulty.toLowerCase()}">${lab.difficulty}</span>
                <span class="lab-xp-earn">${lab.xp} XP</span>
            </div>
            <h4 class="lab-card-title">${lab.title}</h4>
            <p class="lab-card-goal">${lab.objective}</p>
            <button class="btn ${isSolved ? 'btn-secondary' : 'btn-primary'} btn-sm" onclick="launchSandbox('${lab.id}', false)">
                ${isSolved ? 'Restart Lab' : 'Launch Lab'}
            </button>
        `;
        grid.appendChild(card);
    });
}

// Mini CTF Submission
async function submitMiniCtfFlag(ctf) {
    const input = document.getElementById("miniCtfInput");
    const val = input.value.trim();
    const feedback = document.getElementById("miniCtfFeedback");
    const submitBtn = document.getElementById("miniCtfSubmitBtn");

    feedback.style.display = "block";
    feedback.innerText = "Checking...";
    feedback.className = "flag-feedback";

    const result = await submitFlagToServer(ctf.id, val);

    if (result.correct) {
        feedback.innerText = `Correct Flag Submitted! +${result.xpAwarded || ctf.xp} XP earned.`;
        feedback.className = "flag-feedback success";
        input.disabled = true;
        submitBtn.disabled = true;

        if (!userState.solvedCtfs.includes(ctf.id)) {
            userState.solvedCtfs.push(ctf.id);
            addXp(result.xpAwarded || ctf.xp, `Mini CTF: ${ctf.title} Captured`);
        }
        // Re-render so the Retry button appears and state stays consistent
        // with loadVulnerability's solved-state handling.
        renderVulnerabilities();
    } else {
        feedback.innerText = "Incorrect Flag. Audit local responses and verify credentials.";
        feedback.className = "flag-feedback error";
    }
}

// ==========================================
// 5. CTF Arena Rendering & Logic
// ==========================================

function renderCtfArena() {
    const grid = document.getElementById("ctfGrid");
    grid.innerHTML = "";
    
    // Get filter
    const activeFilter = document.querySelector(".filter-tab.active").getAttribute("data-filter");

    CTF_CHALLENGES.forEach(c => {
        const isSolved = userState.solvedCtfs.includes(c.id);
        const diffLower = c.difficulty.toLowerCase();
        
        // Apply filter
        if (activeFilter !== "all" && activeFilter !== diffLower) return;

        const card = document.createElement("div");
        card.className = `ctf-challenge-card ${isSolved ? 'solved' : ''}`;
        card.onclick = () => launchSandbox(c.id, true);

        card.innerHTML = `
            <div class="challenge-top">
                <span class="challenge-cat">${c.category}</span>
                <h4 class="challenge-title">${c.title}</h4>
                <p class="challenge-desc">${c.desc}</p>
            </div>
            <div class="challenge-bottom">
                <span class="challenge-diff ${diffLower}">${c.difficulty}</span>
                <span class="challenge-xp">${c.xp} XP</span>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Bind CTF filters
document.querySelectorAll(".filter-tab").forEach(tab => {
    tab.addEventListener("click", (e) => {
        document.querySelectorAll(".filter-tab").forEach(t => t.classList.remove("active"));
        e.target.classList.add("active");
        renderCtfArena();
    });
});

// ==========================================
// 6. Interactive Sandbox Simulator Engine
// ==========================================

let activeSandboxId = null;
let isSandboxCtfMode = false;
let mockBrowserHistory = [];
let mockHistoryPointer = -1;

const sandboxOverlay = document.getElementById("sandboxOverlay");
const sandboxCloseBtn = document.getElementById("sandboxCloseBtn");
const sandboxResetBtn = document.getElementById("sandboxResetBtn");
const hintToggleBtn = document.getElementById("hintToggleBtn");
const hintBody = document.getElementById("hintBody");

// Watches the entire sandbox panel for the flag reveal placeholder text
// appearing anywhere — text node content, regardless of which of the many
// simulated code paths produced it — and swaps it for the real flag.
let _resolvingFlagToken = false;
const flagTokenObserver = new MutationObserver(() => {
    if (_resolvingFlagToken) return;
    _resolvingFlagToken = true;
    resolveRevealToken().finally(() => { _resolvingFlagToken = false; });
});
flagTokenObserver.observe(sandboxOverlay, { childList: true, subtree: true, characterData: true });

sandboxCloseBtn.addEventListener("click", closeSandbox);
sandboxResetBtn.addEventListener("click", () => resetSandbox(activeSandboxId));

hintToggleBtn.addEventListener("click", () => {
    hintToggleBtn.classList.toggle("active");
    hintBody.classList.toggle("active");
});

function closeSandbox() {
    sandboxOverlay.classList.remove("active");
    activeSandboxId = null;
    document.getElementById("browserViewport").innerHTML = "";
    // Refresh parent page UI elements
    renderVulnerabilities();
    renderCtfArena();
}

function launchSandbox(id, isCtf) {
    activeSandboxId = id;
    isSandboxCtfMode = isCtf;
    sandboxOverlay.classList.add("active");
    
    // Reset Accordion header
    hintToggleBtn.classList.remove("active");
    hintBody.classList.remove("active");

    // Fetch config
    let config = null;
    if (isCtf) {
        config = CTF_CHALLENGES.find(c => c.id === id);
        // Maybe it's a mini-ctf
        if (!config) {
            const vuln = VULNERABILITIES.find(v => v.ctf.id === id);
            if (vuln) config = vuln.ctf;
        }
    } else {
        // Search in vulnerabilities labs
        for (let v of VULNERABILITIES) {
            const l = v.labs.find(lab => lab.id === id);
            if (l) {
                config = l;
                break;
            }
        }
    }

    if (!config) {
        closeSandbox();
        return;
    }

    // Tell the backend this sandbox was opened (gates /api/reveal/:id and
    // lets the real submit-flag check work for this challenge).
    if (isCtf) {
        notifySandboxLaunched(id);
    }

    // Real Lab banner: a couple of challenges are backed by a genuine
    // vulnerable Express app instead of the simulated browser.
    const realLabBanner = document.getElementById("sandboxRealLabBanner");
    const realLabLink = document.getElementById("sandboxRealLabLink");
    if (REAL_LAB_URLS[id]) {
        realLabBanner.style.display = "block";
        realLabLink.href = REAL_LAB_URLS[id];
    } else {
        realLabBanner.style.display = "none";
    }

    // Populate Sidebar metadata
    document.getElementById("sandboxTitle").innerText = config.title;
    document.getElementById("sandboxObjective").innerText = isCtf ? config.desc : config.objective;
    document.getElementById("sandboxScenario").innerText = isCtf ? "A dedicated capture flag challenge environment." : config.scenario;
    document.getElementById("sandboxHint1").innerText = config.hint1;
    document.getElementById("sandboxHint2").innerText = config.hint2;
    document.getElementById("sandboxSolution").innerHTML = `Solution payload: <code>${config.solution}</code>`;

    // Solve Status
    const isSolved = isCtf ? userState.solvedCtfs.includes(id) : userState.solvedLabs.includes(id);
    const statusB = document.getElementById("sandboxStatus");
    if (isSolved) {
        statusB.innerText = "SOLVED";
        statusB.className = "sandbox-status-badge solved";
    } else {
        statusB.innerText = "UNSOLVED";
        statusB.className = "sandbox-status-badge";
    }

    // Set up CTF Box
    const ctfBox = document.getElementById("sandboxCtfSubmission");
    const ctfFeedback = document.getElementById("sandboxCtfFeedback");
    const ctfInput = document.getElementById("sandboxCtfInput");
    const ctfSubmitBtn = document.getElementById("sandboxCtfSubmitBtn");
    const ctfRetryBtn = document.getElementById("sandboxCtfRetryBtn");
    
    if (isCtf) {
        ctfBox.style.display = "block";
        ctfFeedback.style.display = "none";
        ctfInput.value = isSolved ? "(already submitted)" : "";
        ctfInput.disabled = isSolved;
        ctfSubmitBtn.disabled = isSolved;
        ctfRetryBtn.style.display = isSolved ? "inline-flex" : "none";
        
        ctfSubmitBtn.onclick = async () => {
            const val = ctfInput.value.trim();
            ctfFeedback.style.display = "block";
            ctfFeedback.innerText = "Checking...";
            ctfFeedback.className = "flag-feedback";

            const result = await submitFlagToServer(id, val);

            if (result.correct) {
                ctfFeedback.innerText = "Correct Flag! Challenge solved.";
                ctfFeedback.className = "flag-feedback success";
                ctfInput.disabled = true;
                ctfSubmitBtn.disabled = true;
                ctfRetryBtn.style.display = "inline-flex";
                statusB.innerText = "SOLVED";
                statusB.className = "sandbox-status-badge solved";
                
                if (!userState.solvedCtfs.includes(id)) {
                    userState.solvedCtfs.push(id);
                    addXp(result.xpAwarded || config.xp, `CTF Captured: ${config.title}`);
                }
            } else {
                ctfFeedback.innerText = "Incorrect flag credentials.";
                ctfFeedback.className = "flag-feedback error";
            }
        };

        // Retry — resets the local solved flag and the sandbox simulation
        // state (cookies/headers/console/viewport) so they can re-attempt
        // the exploit. Already-earned XP is kept.
        ctfRetryBtn.onclick = () => {
            userState.solvedCtfs = userState.solvedCtfs.filter(cid => cid !== id);
            ctfFeedback.style.display = "none";
            ctfInput.value = "";
            ctfInput.disabled = false;
            ctfSubmitBtn.disabled = false;
            ctfRetryBtn.style.display = "none";
            statusB.innerText = "UNSOLVED";
            statusB.className = "sandbox-status-badge";
            resetSandbox(id);
        };
    } else {
        ctfBox.style.display = "none";
    }

    // Browser URL setting
    mockBrowserHistory = [];
    mockHistoryPointer = -1;
    resetSandbox(id);
}

window.launchSandbox = launchSandbox;

function resetSandbox(id) {
    // Clear Console
    const consoleArea = document.getElementById("consoleOutputArea");
    consoleArea.innerHTML = `<div class="console-line system-line">[System] Developer tools console initialized. Ready.</div>`;
    
    // Clear Proxy Logs
    const proxyArea = document.getElementById("proxyLogsArea");
    proxyArea.innerHTML = `<div class="console-line system-line">[Proxy] HTTP requests interceptor listening...</div>`;
    
    // Set Cookies
    setupMockCookies(id);

    // Set editable proxy headers/body to this challenge's starting state
    setupMockProxyHeaders(id);

    // Load Simulation content
    loadSimulationContent(id);
}

// DevTools Tabs switching
document.querySelectorAll(".devtools-tab").forEach(tab => {
    tab.addEventListener("click", (e) => {
        document.querySelectorAll(".devtools-tab").forEach(t => t.classList.remove("active"));
        document.querySelectorAll(".devtools-tab-content").forEach(c => c.classList.remove("active"));
        
        e.target.classList.add("active");
        const targetTab = e.target.getAttribute("data-devtab");
        document.getElementById(targetTab).classList.add("active");
    });
});

// Mock console utilities
function logConsole(message, type = "log-line") {
    const area = document.getElementById("consoleOutputArea");
    const div = document.createElement("div");
    div.className = `console-line ${type}`;
    div.innerText = `[Console] ${message}`;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

function logProxyRequest(method, url, headers = {}, body = null) {
    const area = document.getElementById("proxyLogsArea");
    const div = document.createElement("div");
    div.className = "console-line log-line";
    
    let headerStr = Object.entries(headers).map(([k, v]) => `  ${k}: ${v}`).join("\n");
    let bodyStr = body ? `\nBody: ${typeof body === 'object' ? JSON.stringify(body) : body}` : '';
    
    div.innerText = `[HTTP Request]\n${method} ${url}\nHeaders:\n${headerStr}${bodyStr}\n---------------------`;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

// Mock Cookie Database
let currentCookies = {};
function setupMockCookies(id) {
    // Default cookies
    currentCookies = {
        "session_id": "user_session_abc123xyz_984",
        "username": userState.username,
        "admin": "false"
    };

    // Lab specific cookie configurations
    if (id === "bac-role") {
        currentCookies["role"] = "user";
    }
    if (id === "xss-ctf") {
        currentCookies["session_id"] = "[captured flag]";
    }

    renderCookiesTable();
}

function renderCookiesTable() {
    const tbody = document.getElementById("cookiesTableBody");
    tbody.innerHTML = "";

    Object.entries(currentCookies).forEach(([key, val]) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><input type="text" class="cookie-input-field" value="${key}" disabled></td>
            <td><input type="text" class="cookie-input-field" data-cookie-key="${key}" value="${val}"></td>
            <td><button class="btn-cookie-delete" onclick="deleteMockCookie('${key}')">❌</button></td>
        `;
        tbody.appendChild(tr);
    });

    // Re-bind cookie modification
    document.querySelectorAll("[data-cookie-key]").forEach(input => {
        input.addEventListener("change", (e) => {
            const key = e.target.getAttribute("data-cookie-key");
            const newVal = e.target.value;
            currentCookies[key] = newVal;
            logConsole(`Cookie changed: ${key}=${newVal}`, "system-line");
            
            // Trigger role checks immediately
            if (activeSandboxId === "bac-role" && key === "role" && newVal === "admin") {
                logConsole("Role cookie manipulated to ADMIN. Refresh page to apply credentials.", "success-line");
            }
        });
    });
}

function deleteMockCookie(key) {
    delete currentCookies[key];
    logConsole(`Cookie deleted: ${key}`, "system-line");
    renderCookiesTable();
}

window.deleteMockCookie = deleteMockCookie;

document.getElementById("addCookieBtn").onclick = () => {
    const key = `key_${Math.floor(Math.random()*100)}`;
    currentCookies[key] = "value";
    renderCookiesTable();
};

// Mock Proxy/Request Headers + Body (genuinely editable — this is what
// challenges that need header/body tampering actually read from now)
let currentProxyHeaders = {};
let currentProxyBody = "";

// Sensible starting headers per challenge, so there's something visible
// to tamper with rather than an empty table. Players still need to know
// (from the hint/scenario) what to change it to.
const PROXY_HEADER_DEFAULTS = {
    "bac-priv": { "X-User-Role": "user" },
    "bac-ctf": { "X-Admin-Token": "" },
    "upload-mime": { "Content-Type": "application/x-php" },
    "ctf-easy-8": { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
    "ctf-medium-19": { "X-Forwarded-For": "127.0.0.1" },
    "ctf-hard-28": { "Host": "site.local" },
};

const PROXY_BODY_DEFAULTS = {
    "ctf-easy-10": "user=admin&pass=password",
};

function setupMockProxyHeaders(id) {
    currentProxyHeaders = { ...(PROXY_HEADER_DEFAULTS[id] || {}) };
    currentProxyBody = PROXY_BODY_DEFAULTS[id] || "";
    renderProxyHeadersTable();
    const bodyEditor = document.getElementById("proxyBodyEditor");
    bodyEditor.value = currentProxyBody;
}

function renderProxyHeadersTable() {
    const tbody = document.getElementById("proxyHeadersTableBody");
    tbody.innerHTML = "";

    Object.entries(currentProxyHeaders).forEach(([key, val]) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><input type="text" class="cookie-input-field" data-header-key-name="${key}" value="${key}"></td>
            <td><input type="text" class="cookie-input-field" data-header-key="${key}" value="${val}"></td>
            <td><button class="btn-cookie-delete" onclick="deleteProxyHeader('${key}')">❌</button></td>
        `;
        tbody.appendChild(tr);
    });

    document.querySelectorAll("[data-header-key]").forEach(input => {
        input.addEventListener("change", (e) => {
            const key = e.target.getAttribute("data-header-key");
            currentProxyHeaders[key] = e.target.value;
            logConsole(`Header changed: ${key}=${e.target.value}`, "system-line");
        });
    });

    document.querySelectorAll("[data-header-key-name]").forEach(input => {
        input.addEventListener("change", (e) => {
            const oldKey = e.target.getAttribute("data-header-key-name");
            const newKey = e.target.value.trim();
            if (!newKey || newKey === oldKey) return;
            currentProxyHeaders[newKey] = currentProxyHeaders[oldKey];
            delete currentProxyHeaders[oldKey];
            renderProxyHeadersTable();
        });
    });
}

function deleteProxyHeader(key) {
    delete currentProxyHeaders[key];
    logConsole(`Header removed: ${key}`, "system-line");
    renderProxyHeadersTable();
}
window.deleteProxyHeader = deleteProxyHeader;

document.getElementById("addProxyHeaderBtn").onclick = () => {
    const key = `X-Custom-${Math.floor(Math.random()*100)}`;
    currentProxyHeaders[key] = "value";
    renderProxyHeadersTable();
};

document.getElementById("proxyBodyEditor").addEventListener("input", (e) => {
    currentProxyBody = e.target.value;
});

// Used by every challenge that checks request headers/body. Reads from the
// editable Proxy tab above (case-insensitive keys, like real HTTP), not
// from the read-only traffic log — fixes challenges that were previously
// unsolvable because there was nowhere to actually type a header.
function parseProxyLogsHeaders() {
    const headers = {};
    Object.entries(currentProxyHeaders).forEach(([k, v]) => {
        headers[k.toLowerCase()] = v;
    });
    return headers;
}

function getProxyBody() {
    return currentProxyBody;
}

// Simulated address Bar navigation
const urlInput = document.getElementById("browserUrlBar");
urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        const targetUrl = urlInput.value.trim();
        navigateToUrl(targetUrl);
    }
});

function navigateToUrl(url) {
    urlInput.value = url;
    
    // Check path changes and parse simulated queries
    if (activeSandboxId === "bac-hidden") {
        if (url.includes("/admin-panel")) {
            loadAdminPanelPage();
            return;
        }
    }

    if (activeSandboxId === "idor-basic") {
        if (url.includes("userId=1")) {
            loadIdorAdminPage();
            return;
        }
    }

    if (activeSandboxId === "idor-invoice") {
        if (url.includes("invoice=2048")) {
            loadIdorInvoicePage();
            return;
        }
    }

    if (activeSandboxId === "idor-ctf") {
        if (url.includes("/api/v1/user/settings?id=1001")) {
            loadIdorCtfPage();
            return;
        }
    }

    if (activeSandboxId === "traversal-basic") {
        if (url.includes("passwd") || url.includes("etc/passwd")) {
            loadTraversalPasswdPage();
            return;
        }
    }
    if (activeSandboxId === "traversal-filter") {
        if (url.includes("etc/passwd") && !url.includes("../")) {
            loadTraversalPasswdPage();
            return;
        }
    }
    if (activeSandboxId === "traversal-sensitive") {
        if (url.includes("settings.yaml")) {
            loadTraversalSettingsPage();
            return;
        }
    }
    if (activeSandboxId === "traversal-ctf") {
        if (url.includes("flag.txt")) {
            loadTraversalCtfPage();
            return;
        }
    }

    if (activeSandboxId === "misconfig-robots") {
        if (url.includes("/robots.txt")) {
            loadRobotsTxt();
            return;
        } else if (url.includes("/backup-credentials")) {
            loadBackupCredentials();
            return;
        }
    }

    if (activeSandboxId === "misconfig-git" || activeSandboxId === "misconfig-ctf") {
        if (url.includes(".git/config")) {
            loadGitConfig();
            return;
        }
    }

    if (activeSandboxId === "ctf-easy-4") {
        if (url.includes("/robots.txt")) {
            loadCtfRobotsTxt();
            return;
        } else if (url.includes("/secret-stash/flag.txt")) {
            loadCtfSecretStash();
            return;
        }
    }

    // Fallback reload simulation
    loadSimulationContent(activeSandboxId);
}

document.getElementById("browserReloadBtn").onclick = () => {
    navigateToUrl(urlInput.value);
};

// Solve utility helper
function markSandboxSolved(id, xpAmount, titleName) {
    const isCtf = isSandboxCtfMode;
    const solvedList = isCtf ? userState.solvedCtfs : userState.solvedLabs;
    
    if (!solvedList.includes(id)) {
        solvedList.push(id);
        addXp(xpAmount, `${isCtf ? 'CTF Flag Captured' : 'Lab Mastered'}: ${titleName}`);
        
        const statusB = document.getElementById("sandboxStatus");
        statusB.innerText = "SOLVED";
        statusB.className = "sandbox-status-badge solved";
        
        // Show fireworks or special toast
        showToast(`🏆 SOLVED! You completed the challenge.`, "success");
    }
}

// ==========================================
// 7. Lab & Challenge Simulation Framework
// ==========================================

function loadSimulationContent(id) {
    const viewport = document.getElementById("browserViewport");
    viewport.style.backgroundColor = "#FFFFFF";
    viewport.style.color = "#1E293B";
    
    // Set base URLs
    let defaultUrl = "http://playground-site.local/";
    if (id.startsWith("xss")) defaultUrl = "http://cyber-blog.local/";
    if (id.startsWith("sqli")) defaultUrl = "http://secure-login.local/";
    if (id.startsWith("bac")) defaultUrl = "http://company.local/";
    if (id.startsWith("idor")) defaultUrl = "http://account-portal.local/";
    if (id.startsWith("csrf")) defaultUrl = "http://social-net.local/";
    if (id.startsWith("upload")) defaultUrl = "http://share-space.local/";
    if (id.startsWith("traversal")) defaultUrl = "http://document-viewer.local/";
    if (id.startsWith("auth")) defaultUrl = "http://login-page.local/";
    if (id.startsWith("ssrf")) defaultUrl = "http://cloud-proxy.local/";
    if (id.startsWith("misconfig")) defaultUrl = "http://site.local/";

    urlInput.value = defaultUrl;

    switch (id) {
        // --- XSS LABS ---
        case "xss-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔍 Product Search Engine</h2>
                    <p>Enter items to search inside our product catalog:</p>
                    <div style="display:flex; gap: 8px; margin-bottom: 20px;">
                        <input type="text" id="xssBasicIn" placeholder="Search item..." style="flex-grow: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                        <button class="btn btn-primary btn-sm" id="xssBasicBtn">Search</button>
                    </div>
                    <div id="xssBasicOut" style="margin-top: 15px;"></div>
                </div>
            `;
            
            const btn = document.getElementById("xssBasicBtn");
            const input = document.getElementById("xssBasicIn");
            const output = document.getElementById("xssBasicOut");
            
            const handleXssSearch = () => {
                const val = input.value;
                logProxyRequest("GET", `http://cyber-blog.local/search?q=${encodeURIComponent(val)}`);
                
                output.innerHTML = `<h3>Search results for: ${val}</h3>`;
                
                // Validate XSS execution trigger
                if (val.includes("<script>") || val.includes("onerror=") || val.includes("onload=")) {
                    logConsole(`XSS Exploit String Executed: ${val}`, "success-line");
                    alertSimulated("XSS Reflected alert(1) triggered!");
                    markSandboxSolved("xss-basic", 100, "Reflected XSS via Search");
                } else {
                    logConsole(`Normal Search Input: ${val}`);
                }
            };
            btn.onclick = handleXssSearch;
            input.addEventListener("keydown", (e) => { if (e.key === "Enter") handleXssSearch(); });
            break;

        case "xss-stored":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📝 Site Guestbook Comments</h2>
                    <div id="commentsList" style="border: 1px solid #ddd; padding: 12px; border-radius: 6px; min-height: 100px; margin-bottom: 16px; background:#f9f9f9;">
                        <p style="color:#777;">No comments posted yet...</p>
                    </div>
                    <h4>Post a Comment</h4>
                    <textarea id="xssStoredIn" placeholder="Type your comment..." style="width:100%; height: 60px; padding: 8px; margin-bottom: 8px; border-radius:4px; border:1px solid #ccc;"></textarea>
                    <button class="btn btn-primary btn-sm" id="xssStoredBtn">Submit Comment</button>
                </div>
            `;
            
            const listC = document.getElementById("commentsList");
            const textC = document.getElementById("xssStoredIn");
            const btnC = document.getElementById("xssStoredBtn");

            // Load stored comments session state
            const loadComments = () => {
                const comments = JSON.parse(sessionStorage.getItem("stored_comments") || "[]");
                if (comments.length > 0) {
                    listC.innerHTML = comments.map(c => `<div style="border-bottom: 1px solid #eee; padding: 6px 0;">💬 ${c}</div>`).join("");
                    
                    // Scan rendering for exploit strings
                    comments.forEach(c => {
                        if (c.includes("<script>") || c.includes("onerror=") || c.includes("onload=")) {
                            logConsole(`Stored XSS Executed: ${c}`, "success-line");
                            alertSimulated("Stored XSS alert(1) Fired!");
                            markSandboxSolved("xss-stored", 200, "Stored XSS Guestbook");
                        }
                    });
                }
            };

            btnC.onclick = () => {
                const val = textC.value.trim();
                if (!val) return;
                logProxyRequest("POST", "http://cyber-blog.local/comment", {}, { comment: val });
                
                const comments = JSON.parse(sessionStorage.getItem("stored_comments") || "[]");
                comments.push(val);
                sessionStorage.setItem("stored_comments", JSON.stringify(comments));
                
                textC.value = "";
                loadComments();
            };

            loadComments();
            break;

        case "xss-dom":
            urlInput.value = "http://cyber-blog.local/#name=Guest";
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏠 User Greeting Dashboard</h2>
                    <h1 id="greetingHeading" style="font-size: 2.2rem; color:#8B5CF6;">Hello, Guest!</h1>
                    <p style="font-size: 0.95rem;">This page welcomes users based on URL hash parameters: <code>#name=...</code>.</p>
                </div>
            `;

            // Function to handle hash parsing
            const greetDom = () => {
                const hash = urlInput.value.split("#")[1];
                if (hash && hash.startsWith("name=")) {
                    const name = decodeURIComponent(hash.substring(5));
                    document.getElementById("greetingHeading").innerHTML = `Hello, ${name}!`;

                    if (name.includes("<script>") || name.includes("onerror=") || name.includes("onload=")) {
                        logConsole(`DOM-Based XSS Sink Triggered: ${name}`, "success-line");
                        alertSimulated("DOM XSS alert(1) Executed!");
                        markSandboxSolved("xss-dom", 300, "DOM-Based XSS via Hash");
                    }
                }
            };
            greetDom();
            break;

        case "xss-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📥 Administrator Feedback Box</h2>
                    <p>Send complaints to the System Admin bot. He inspects the comments inside his private console panel.</p>
                    <textarea id="xssCtfIn" placeholder="Enter message to admin..." style="width:100%; height: 80px; padding: 8px; margin-bottom: 8px; border-radius:4px; border:1px solid #ccc;"></textarea>
                    <button class="btn btn-primary btn-sm" id="xssCtfBtn">Send Feedback</button>
                    <div id="xssCtfOut" style="margin-top:10px; font-weight:600; color:green;"></div>
                </div>
            `;

            document.getElementById("xssCtfBtn").onclick = () => {
                const val = document.getElementById("xssCtfIn").value.trim();
                if (!val) return;
                logProxyRequest("POST", "http://cyber-blog.local/feedback", {}, { msg: val });
                document.getElementById("xssCtfOut").innerText = "Feedback sent! Admin is opening your submission...";
                
                // Simulate admin visiting and running script in cookie stealer
                if (val.includes("document.cookie") && (val.includes("fetch") || val.includes("img") || val.includes("xhr"))) {
                    setTimeout(() => {
                        logConsole("ADMIN BOT VISITED FEEDBACK PAGE.", "log-line");
                        logConsole(`ADMIN executed payload. Stolen Admin Cookie sent to Proxy Logs: cookie=[captured flag]`, "success-line");
                        logProxyRequest("GET", "http://cyber-blog.local/log?cookie=[captured flag]");
                    }, 1500);
                }
            };
            break;

        // --- SQL INJECTION LABS ---
        case "sqli-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <div style="max-width:320px; margin: 0 auto; padding: 24px; border:1px solid #ddd; border-radius:8px; background:#fafafa;">
                        <h3 style="margin-bottom:16px;">🔑 Employee Portal</h3>
                        <div style="margin-bottom:12px;">
                            <label style="display:block; margin-bottom:4px; font-size:0.8rem;">Username</label>
                            <input type="text" id="sqliUser" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
                        </div>
                        <div style="margin-bottom:16px;">
                            <label style="display:block; margin-bottom:4px; font-size:0.8rem;">Password</label>
                            <input type="password" id="sqliPass" style="width:100%; padding:8px; border:1px solid #ccc; border-radius:4px;">
                        </div>
                        <button class="btn btn-primary" id="sqliLoginBtn" style="width:100%;">Login</button>
                        <div id="sqliOut" style="margin-top:12px; font-size:0.85rem; font-weight:600; color:red;"></div>
                    </div>
                </div>
            `;

            document.getElementById("sqliLoginBtn").onclick = () => {
                const u = document.getElementById("sqliUser").value;
                const p = document.getElementById("sqliPass").value;

                logProxyRequest("POST", "http://secure-login.local/login", {}, { username: u, password: p });
                logConsole(`SQL Query Executed:\nSELECT * FROM users WHERE username = '${u}' AND password = '${p}'`, "log-line");

                // Check SQL injection payload pattern
                if (u.includes("' OR 1=1") || u.includes("' OR '1'='1")) {
                    logConsole("Database returned: 1 match (Role: Admin)", "success-line");
                    document.getElementById("sqliOut").innerHTML = "<span style='color:green;'>Authentication Successful! Welcome Admin.</span>";
                    markSandboxSolved("sqli-basic", 100, "SQLi Login Bypass");
                } else {
                    logConsole("Database returned: 0 matches (Access Denied)", "error-line");
                    document.getElementById("sqliOut").innerText = "Invalid credentials.";
                }
            };
            break;

        case "sqli-union":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>👕 Catalog Store Search</h2>
                    <p>Enter clothes name to filter (e.g. Jacket, T-Shirt):</p>
                    <div style="display:flex; gap: 8px; margin-bottom: 20px;">
                        <input type="text" id="sqliUnionIn" placeholder="Search..." style="flex-grow: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                        <button class="btn btn-primary btn-sm" id="sqliUnionBtn">Filter</button>
                    </div>
                    <table style="width:100%; border-collapse:collapse; font-size:0.9rem;" id="sqliTable">
                        <thead>
                            <tr style="background:#eee;">
                                <th style="padding:8px; border:1px solid #ddd; text-align:left;">Product</th>
                                <th style="padding:8px; border:1px solid #ddd; text-align:left;">Price ($)</th>
                            </tr>
                        </thead>
                        <tbody id="sqliTableBody">
                            <tr><td style="padding:8px; border:1px solid #ddd;">Black Leather Jacket</td><td style="padding:8px; border:1px solid #ddd;">120</td></tr>
                            <tr><td style="padding:8px; border:1px solid #ddd;">Blue Sport T-Shirt</td><td style="padding:8px; border:1px solid #ddd;">45</td></tr>
                        </tbody>
                    </table>
                </div>
            `;

            document.getElementById("sqliUnionBtn").onclick = () => {
                const val = document.getElementById("sqliUnionIn").value.trim();
                logProxyRequest("GET", `http://secure-login.local/products?search=${encodeURIComponent(val)}`);
                logConsole(`SQL Query Executed:\nSELECT product_name, price FROM products WHERE product_name LIKE '%${val}%'`, "log-line");

                const tbody = document.getElementById("sqliTableBody");

                if (val.toUpperCase().includes("UNION SELECT") && val.toUpperCase().includes("FROM USERS")) {
                    logConsole("UNION Query successful! Leak credentials.", "success-line");
                    tbody.innerHTML = `
                        <tr style="background:#fdd;"><td style="padding:8px; border:1px solid #ddd; font-weight:700;">admin</td><td style="padding:8px; border:1px solid #ddd; font-family:monospace;">pbkdf2_sha256$26000$admin_pass_9982</td></tr>
                        <tr style="background:#fdd;"><td style="padding:8px; border:1px solid #ddd; font-weight:700;">bob_user</td><td style="padding:8px; border:1px solid #ddd; font-family:monospace;">pbkdf2_sha256$26000$bobby_loves_pizza</td></tr>
                    `;
                    markSandboxSolved("sqli-union", 200, "Union-Based SQLi Data Leak");
                } else {
                    tbody.innerHTML = `
                        <tr><td style="padding:8px; border:1px solid #ddd;">Black Leather Jacket</td><td style="padding:8px; border:1px solid #ddd;">120</td></tr>
                        <tr><td style="padding:8px; border:1px solid #ddd;">Blue Sport T-Shirt</td><td style="padding:8px; border:1px solid #ddd;">45</td></tr>
                    `;
                }
            };
            break;

        case "sqli-blind":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔍 Catalog Stock Check</h2>
                    <p>Check if a catalog product ID is currently in stock:</p>
                    <div style="display:flex; gap: 8px; margin-bottom: 20px;">
                        <input type="text" id="sqliBlindIn" placeholder="Product ID (e.g. 1)" style="flex-grow: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                        <button class="btn btn-primary btn-sm" id="sqliBlindBtn">Check</button>
                    </div>
                    <div id="sqliBlindOut" style="padding:12px; border-radius:4px; font-weight:700;"></div>
                </div>
            `;

            document.getElementById("sqliBlindBtn").onclick = () => {
                const val = document.getElementById("sqliBlindIn").value.trim();
                logProxyRequest("GET", `http://secure-login.local/stock?id=${encodeURIComponent(val)}`);
                logConsole(`SQL Query Executed:\nSELECT * FROM inventory WHERE id = ${val}`, "log-line");

                const out = document.getElementById("sqliBlindOut");

                if (val === "1") {
                    out.innerText = "✓ ITEM IN STOCK";
                    out.style.color = "green";
                } else if (val.includes(" OR ") || val.includes(" AND ")) {
                    // Check logic condition
                    if (val.includes("1=1") || val.includes("SELECT username FROM users")) {
                        out.innerText = "✓ ITEM IN STOCK";
                        out.style.color = "green";
                        logConsole("Blind query logic evaluated to: TRUE", "success-line");
                        markSandboxSolved("sqli-blind", 300, "Blind SQLi Verification");
                    } else {
                        out.innerText = "✗ OUT OF STOCK";
                        out.style.color = "red";
                        logConsole("Blind query logic evaluated to: FALSE", "error-line");
                    }
                } else {
                    out.innerText = "✗ OUT OF STOCK";
                    out.style.color = "red";
                }
            };
            break;

        case "sqli-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏁 Challenge Search Base</h2>
                    <div style="display:flex; gap: 8px; margin-bottom: 20px;">
                        <input type="text" id="sqliCtfIn" placeholder="Search flag entries..." style="flex-grow: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                        <button class="btn btn-primary btn-sm" id="sqliCtfBtn">Search</button>
                    </div>
                    <div id="sqliCtfOut" style="border: 1px solid #ddd; padding: 12px; min-height: 50px;">
                        Perform SQL Union inject queries to resolve the database flag table.
                    </div>
                </div>
            `;

            document.getElementById("sqliCtfBtn").onclick = () => {
                const val = document.getElementById("sqliCtfIn").value.trim();
                logProxyRequest("GET", `http://secure-login.local/ctf-search?q=${encodeURIComponent(val)}`);
                logConsole(`SQL query executed:\nSELECT name, type FROM items WHERE name LIKE '%${val}%'`, "log-line");

                const out = document.getElementById("sqliCtfOut");
                
                if (val.toUpperCase().includes("UNION SELECT") && val.toUpperCase().includes("FROM SECRET_FLAGS")) {
                    logConsole("UNION query successful! Secret tables extracted.", "success-line");
                    out.innerHTML = `
                        <div style="background:#e6fffa; border:1px solid #34d399; padding:10px; border-radius:4px; font-family:monospace; font-weight:700;">
                            Flag Captured: [captured flag]
                        </div>
                    `;
                } else {
                    out.innerText = "No search items matched.";
                }
            };
            break;

        // --- BROKEN ACCESS CONTROL LABS ---
        case "bac-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏢 Corporate Home Page</h2>
                    <p>Welcome to the main homepage of Secure Corp. Feel free to explore our menu tabs.</p>
                    <div style="border-top:1px solid #ddd; padding-top:12px;">
                        <a href="#" style="margin-right:12px; color:blue;">About Us</a>
                        <a href="#" style="margin-right:12px; color:blue;">Services</a>
                        <a href="#" style="margin-right:12px; color:blue;">Contact</a>
                    </div>
                </div>
            `;
            break;

        case "bac-role":
            viewport.innerHTML = `
                <div class="viewport-site" id="bacRoleSite">
                    <h2>🔑 User Portal Dashboard</h2>
                    <div style="padding:12px; border:1px solid #3b82f6; background:#eff6ff; border-radius:6px; margin-bottom:16px;">
                        <strong>Current Session Status:</strong><br>
                        Logged in as: <code id="bacRoleUser">${userState.username}</code><br>
                        Access Role: <code id="bacRoleVal" style="color:blue;">user</code>
                    </div>
                    <div id="bacRoleAdminPanel" style="display:none; border:1px solid red; padding:16px; border-radius:6px; background:#fef2f2;">
                        <h4 style="color:red; margin-bottom:8px;">🛠️ Administrator Configuration controls</h4>
                        <p>Access Granted! Vulnerability resolved.</p>
                        <button class="btn btn-accent btn-sm" id="bacRoleClaimBtn">Claim Lab</button>
                    </div>
                </div>
            `;

            const checkRoleCookie = () => {
                const role = currentCookies["role"] || "user";
                document.getElementById("bacRoleVal").innerText = role;
                
                if (role === "admin") {
                    document.getElementById("bacRoleAdminPanel").style.display = "block";
                    document.getElementById("bacRoleClaimBtn").onclick = () => {
                        markSandboxSolved("bac-role", 200, "Role Parameter Tampering");
                    };
                } else {
                    document.getElementById("bacRoleAdminPanel").style.display = "none";
                }
            };
            checkRoleCookie();
            break;

        case "bac-priv":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛡️ Client Transaction Portal</h2>
                    <p>Create request actions. Customize request body payloads to perform admin actions.</p>
                    <div style="border: 1px solid #ddd; padding: 16px; border-radius: 6px; background:#fbfbfb;">
                        <h4>API Requester Tool</h4>
                        <div style="margin-bottom:8px;">
                            <label style="font-size:0.75rem;">HTTP Route</label>
                            <input type="text" value="/api/v1/users/delete?userId=105" disabled style="width:100%; padding:6px;">
                        </div>
                        <p style="font-size:0.75rem; color:#666;">👉 Headers actually sent are whatever's in the <strong>Proxy Logs</strong> tab (right panel) — edit them there, then send.</p>
                        <button class="btn btn-primary btn-sm" id="bacPrivSendBtn">Send API Request</button>
                    </div>
                    <div id="bacPrivOut" style="margin-top:12px; font-weight:700; color:red;"></div>
                </div>
            `;

            logConsole("Hint: Check Proxy Logs. Add header 'X-User-Role: Admin' to requests.", "system-line");

            document.getElementById("bacPrivSendBtn").onclick = () => {
                // Read from mock proxy inputs
                const proxyHeaders = parseProxyLogsHeaders();
                logProxyRequest("POST", "http://company.local/api/v1/users/delete", proxyHeaders, { userId: 105 });

                const out = document.getElementById("bacPrivOut");

                if (proxyHeaders["x-user-role"] && proxyHeaders["x-user-role"].toLowerCase() === "admin") {
                    out.innerHTML = "<span style='color:green;'>API Success: Admin action permitted. User 105 deleted.</span>";
                    logConsole("Server: Permission validation passed via X-User-Role header.", "success-line");
                    markSandboxSolved("bac-priv", 300, "Horizontal privilege bypass");
                } else {
                    out.innerText = "Error: Access Denied. Requires Administrator privileges.";
                    logConsole("Server validation error: Missing X-User-Role: Admin header.", "error-line");
                }
            };
            break;

        case "bac-ctf":
            viewport.innerHTML = `
                <div class="viewport-site" id="bacCtfSite">
                    <h2>🛡️ Corporate Login Gate</h2>
                    <p>Enter the admin dashboard. The authorization engine requires the cookie <code>role=admin</code> and the custom header <code>X-Admin-Token: secret_access_2026</code>.</p>
                    <div id="bacCtfFeedback" style="border:1px dashed red; padding:12px; border-radius:6px; color:red; font-weight:600;">
                        ACCESS DENIED: Credentials mismatch.
                    </div>
                </div>
            `;
            
            const checkCtfAccess = () => {
                const role = currentCookies["role"] || "guest";
                const proxyHeaders = parseProxyLogsHeaders();
                const token = proxyHeaders["x-admin-token"];

                if (role === "admin" && token === "secret_access_2026") {
                    document.getElementById("bacCtfFeedback").innerHTML = `
                        <div style="background:#d1fae5; border:1px solid #10b981; color:#065f46; padding:16px; border-radius:6px;">
                            ✓ ACCESS APPROVED! Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                    logConsole("Credentials check complete! Access token matches.", "success-line");
                }
            };
            checkCtfAccess();
            break;

        // --- IDOR LABS ---
        case "idor-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>👤 User Profile</h2>
                    <div style="border:1px solid #ddd; padding:20px; border-radius:8px; background:#fafafa;">
                        <h3 style="margin-bottom:8px;" id="idorName">User: Hacker Recruit</h3>
                        <p style="margin-bottom:4px;">Email: recruiter@sp.local</p>
                        <p>Privilege index: 105</p>
                    </div>
                </div>
            `;
            break;

        case "idor-invoice":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🧾 Customer Invoices Dashboard</h2>
                    <p>Select your account bill statement to download:</p>
                    <select style="padding:6px; width:100%; margin-bottom:20px;" id="idorSelect">
                        <option value="1001">Invoice #1001 - Monthly Bill ($45.00)</option>
                        <option value="1002">Invoice #1002 - Host Fees ($12.00)</option>
                    </select>
                    <button class="btn btn-primary btn-sm" id="idorInvoiceBtn">Fetch Invoice</button>
                    <div id="idorInvoiceContent" style="margin-top:16px; border:1px solid #ccc; padding:16px; display:none; background:#fff;"></div>
                </div>
            `;

            document.getElementById("idorInvoiceBtn").onclick = () => {
                const selectVal = document.getElementById("idorSelect").value;
                urlInput.value = `http://account-portal.local/?invoice=${selectVal}`;
                logProxyRequest("GET", `http://account-portal.local/invoice?id=${selectVal}`);
                
                const out = document.getElementById("idorInvoiceContent");
                out.style.display = "block";
                out.innerHTML = `<h4>Bill Receipt Statement #${selectVal}</h4><p>Items: Secure Sandbox Access</p>`;
            };
            break;

        case "idor-modify":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 Account Settings Panel</h2>
                    <div style="border: 1px solid #ddd; padding: 16px; border-radius:6px; background:#f9f9f9;">
                        <h4>Change Profile Details</h4>
                        <div style="margin-bottom:8px;">
                            <label style="font-size:0.75rem;">Username</label>
                            <input type="text" id="idorModifyName" value="Hacker Recruit" style="width:100%; padding:6px;">
                        </div>
                        <div style="margin-bottom:12px;">
                            <label style="font-size:0.75rem;">API Payload Data</label>
                            <textarea id="idorModifyJson" style="width:100%; height:60px; font-family:monospace; font-size:0.75rem;">{\n  "userId": 105,\n  "role": "user"\n}</textarea>
                        </div>
                        <button class="btn btn-primary btn-sm" id="idorModifyBtn">Update Profile</button>
                    </div>
                    <div id="idorModifyOut" style="margin-top:10px; font-weight:700; color:red;"></div>
                </div>
            `;

            document.getElementById("idorModifyBtn").onclick = () => {
                const jsonText = document.getElementById("idorModifyJson").value;
                let data = {};
                try {
                    data = JSON.parse(jsonText);
                } catch (e) {
                    document.getElementById("idorModifyOut").innerText = "Invalid JSON format.";
                    return;
                }

                logProxyRequest("POST", "http://account-portal.local/api/v1/update", {}, data);
                
                const out = document.getElementById("idorModifyOut");
                if (data.userId == 1) {
                    out.innerHTML = "<span style='color:green;'>Profile Success: Administrator user details modified!</span>";
                    logConsole("IDOR Exploit Complete: User 1 password updated.", "success-line");
                    markSandboxSolved("idor-modify", 300, "Account Payload Manipulation");
                } else {
                    out.innerHTML = `<span style='color:blue;'>Profile updated for user: ${data.userId}</span>`;
                }
            };
            break;

        // --- IDOR CTF ---
        case "idor-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛠️ Admin API Developer Endpoint</h2>
                    <p>Tamper parameter targets to view user data indexes.</p>
                </div>
            `;
            break;

        // --- CSRF LABS ---
        case "csrf-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>✉️ Change Profile Email</h2>
                    <form id="csrfEmailForm" onsubmit="event.preventDefault();" style="border:1px solid #ddd; padding:16px; border-radius:6px;">
                        <input type="email" id="csrfEmailInput" value="user@mail.com" style="width:100%; padding:8px; margin-bottom:8px;">
                        <button class="btn btn-primary btn-sm" id="csrfEmailBtn">Change Email</button>
                    </form>
                    <div id="csrfEmailOut" style="margin-top:12px; font-weight:700; color:blue;"></div>

                    <!-- Attack Sandbox Builder -->
                    <div style="margin-top:24px; border-top:1px solid #eee; padding-top:16px;">
                        <h4 style="color:#8B5CF6;">👾 Attacker Exploiter Form Builder</h4>
                        <p style="font-size:0.75rem;">Deliver a CSRF payload to trigger email change on victim.</p>
                        <select id="csrfExploitSelect" style="padding:6px; margin-bottom:8px; width:100%;">
                            <option value="">-- Select exploit --</option>
                            <option value="email">POST form targeting http://social-net.local/change-email</option>
                        </select>
                        <button class="btn btn-accent btn-sm" id="csrfExploitDeploy">Deploy Payload</button>
                    </div>
                </div>
            `;

            document.getElementById("csrfEmailBtn").onclick = () => {
                const email = document.getElementById("csrfEmailInput").value;
                logProxyRequest("POST", "http://social-net.local/change-email", {}, { email: email });
                document.getElementById("csrfEmailOut").innerHTML = `Email modified to: <span style='color:green;'>${email}</span>`;
            };

            document.getElementById("csrfExploitDeploy").onclick = () => {
                const exploit = document.getElementById("csrfExploitSelect").value;
                if (exploit === "email") {
                    logConsole("Simulating CSRF victim browsing external site...", "log-line");
                    setTimeout(() => {
                        logProxyRequest("POST", "http://social-net.local/change-email", {}, { email: "attacker@exploit.com" });
                        logConsole("CSRF Executed: Victim email changed to attacker@exploit.com!", "success-line");
                        document.getElementById("csrfEmailOut").innerHTML = "Email modified to: <span style='color:red;'>attacker@exploit.com</span>";
                        markSandboxSolved("csrf-basic", 100, "Unprotected Email Changer");
                    }, 1500);
                }
            };
            break;

        case "csrf-password":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔒 Password Update Portal</h2>
                    <p>Update password settings directly. Anti-CSRF token check is disabled.</p>
                    <div style="margin-top:20px; border-top:1px solid #ccc; padding-top:12px;">
                        <h4 style="color:#8B5CF6;">Malicious form deployer</h4>
                        <button class="btn btn-primary btn-sm" id="csrfPassDeployBtn">Fire CSRF Form Post</button>
                    </div>
                </div>
            `;

            document.getElementById("csrfPassDeployBtn").onclick = () => {
                logConsole("Triggering background POST to /update-pass...", "log-line");
                setTimeout(() => {
                    logProxyRequest("POST", "http://social-net.local/update-pass", {}, { pass: "hacked_password" });
                    logConsole("CSRF Vulnerability Exploited! Password set to hacked_password.", "success-line");
                    markSandboxSolved("csrf-password", 200, "CSRF Password Overwrite");
                }, 1200);
            };
            break;

        case "csrf-admin":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>💬 Forum Feed</h2>
                    <div id="csrfForumComments" style="border: 1px solid #ddd; padding:10px; min-height:80px; background:#fff; margin-bottom:12px;">
                        <p style="color:#777;">Feed active.</p>
                    </div>
                    <h4>Post a Message</h4>
                    <textarea id="csrfForumText" placeholder="Post message..." style="width:100%; height:50px; margin-bottom:6px;"></textarea>
                    <button class="btn btn-primary btn-sm" id="csrfForumBtn">Post</button>
                </div>
            `;

            const loadCsrfComments = () => {
                const list = JSON.parse(sessionStorage.getItem("csrf_comments") || "[]");
                if (list.length > 0) {
                    document.getElementById("csrfForumComments").innerHTML = list.map(c => `<div>💬 ${c}</div>`).join("");
                    
                    // Trigger CSRF simulation
                    list.forEach(c => {
                        if (c.includes("/admin/delete?userId=105") && c.includes("img")) {
                            logConsole("CSRF GET payload parsed inside forum thread.", "log-line");
                            setTimeout(() => {
                                logConsole("ADMIN BOT VISITED FORUM.", "log-line");
                                logProxyRequest("GET", "http://social-net.local/admin/delete?userId=105");
                                logConsole("ADMIN deleted User 105 via CSRF exploit!", "success-line");
                                markSandboxSolved("csrf-admin", 300, "CSRF Admin Action Abuse");
                            }, 1500);
                        }
                    });
                }
            };

            document.getElementById("csrfForumBtn").onclick = () => {
                const text = document.getElementById("csrfForumText").value;
                if (!text) return;
                const list = JSON.parse(sessionStorage.getItem("csrf_comments") || "[]");
                list.push(text);
                sessionStorage.setItem("csrf_comments", JSON.stringify(list));
                document.getElementById("csrfForumText").value = "";
                loadCsrfComments();
            };

            loadCsrfComments();
            break;

        case "csrf-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏁 Admin State Hijacker forum</h2>
                    <p>Post comments containing an image source targeting <code>/admin/set-role?user=hacker&role=admin</code> to trigger CSRF when admin opens thread.</p>
                    <textarea id="csrfCtfText" style="width:100%; height:60px; margin-bottom:6px;" placeholder="Comment..."></textarea>
                    <button class="btn btn-primary btn-sm" id="csrfCtfBtn">Post</button>
                    <div id="csrfCtfOut" style="margin-top:10px; color:green; font-weight:700;"></div>
                </div>
            `;

            document.getElementById("csrfCtfBtn").onclick = () => {
                const val = document.getElementById("csrfCtfText").value;
                if (!val) return;
                logProxyRequest("POST", "http://social-net.local/post", {}, { comment: val });
                document.getElementById("csrfCtfText").value = "";
                document.getElementById("csrfCtfOut").innerText = "Comment submitted. Wait for bot read...";

                if (val.includes("/admin/set-role?user=hacker&role=admin") && val.includes("img")) {
                    setTimeout(() => {
                        logConsole("ADMIN BOT VIEWED PAGE.", "log-line");
                        logProxyRequest("GET", "http://social-net.local/admin/set-role?user=hacker&role=admin");
                        logConsole("CSRF success: role updated! Flag retrieved: [captured flag]", "success-line");
                        document.getElementById("csrfCtfOut").innerHTML = `Flag: <strong>[captured flag]</strong>`;
                    }, 1500);
                }
            };
            break;

        // --- FILE UPLOAD LABS ---
        case "upload-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📁 Photo Share Space</h2>
                    <p>Upload a profile picture:</p>
                    <div style="border:2px dashed #ccc; padding:24px; text-align:center; border-radius:8px; margin-bottom:12px;" id="dropZone">
                        <input type="file" id="fileIn" style="display:none;">
                        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('fileIn').click()">Choose File</button>
                        <p id="fileLabel" style="font-size:0.8rem; margin-top:8px;">No file selected</p>
                    </div>
                    <button class="btn btn-primary btn-sm" id="uploadBtn">Upload File</button>
                    <div id="uploadOut" style="margin-top:16px;"></div>
                </div>
            `;

            const fIn = document.getElementById("fileIn");
            const fLbl = document.getElementById("fileLabel");
            
            fIn.onchange = () => {
                if (fIn.files.length > 0) fLbl.innerText = fIn.files[0].name;
            };

            document.getElementById("uploadBtn").onclick = () => {
                if (fIn.files.length === 0) return;
                const file = fIn.files[0];
                logProxyRequest("POST", "http://share-space.local/upload", { "Content-Type": "multipart/form-data" }, file.name);

                const out = document.getElementById("uploadOut");
                
                if (file.name.endsWith(".php")) {
                    logConsole(`Web shell file uploaded successfully: /uploads/${file.name}`, "success-line");
                    out.innerHTML = `
                        <div style="border:1px solid green; padding:12px; background:#e6fffa; border-radius:6px;">
                            ✓ Upload successful!<br>
                            Access file route: <a href="#" id="basicShellLink" style="color:blue; font-weight:700;">/uploads/${file.name}</a>
                        </div>
                    `;
                    document.getElementById("basicShellLink").onclick = () => {
                        loadWebShellWorkspace();
                    };
                    markSandboxSolved("upload-basic", 100, "Unrestricted Shell Upload");
                } else {
                    out.innerHTML = `<span style='color:green;'>Image file /uploads/${file.name} saved!</span>`;
                }
            };
            break;

        case "upload-mime":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🖼️ Image Gallery Upload</h2>
                    <p>The backend validates MIME types of files to ensure only images are loaded.</p>
                    <div style="border:2px dashed #ccc; padding:20px; text-align:center; border-radius:8px; margin-bottom:12px;">
                        <input type="file" id="mimeFile" style="display:none;">
                        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('mimeFile').click()">Choose File</button>
                        <p id="mimeLabel" style="font-size:0.8rem; margin-top:6px;">No file selected</p>
                    </div>
                    <button class="btn btn-primary btn-sm" id="mimeUploadBtn">Upload</button>
                    <div id="mimeOut" style="margin-top:12px;"></div>
                </div>
            `;

            const mFile = document.getElementById("mimeFile");
            mFile.onchange = () => { if (mFile.files.length > 0) document.getElementById("mimeLabel").innerText = mFile.files[0].name; };

            document.getElementById("mimeUploadBtn").onclick = () => {
                if (mFile.files.length === 0) return;
                const name = mFile.files[0].name;
                
                const proxyHeaders = parseProxyLogsHeaders();
                const contentType = proxyHeaders["content-type"] || "application/x-php";

                logProxyRequest("POST", "http://share-space.local/upload-mime", proxyHeaders, name);

                const out = document.getElementById("mimeOut");

                if (name.endsWith(".php")) {
                    if (contentType.includes("image/")) {
                        logConsole("MIME-type bypass verification complete!", "success-line");
                        out.innerHTML = `
                            <div style="border:1px solid green; padding:12px; background:#e6fffa; border-radius:6px;">
                                ✓ Upload successful!<br>
                                Access route: <a href="#" id="mimeShellLink" style="color:blue;">/uploads/${name}</a>
                            </div>
                        `;
                        document.getElementById("mimeShellLink").onclick = () => {
                            loadWebShellWorkspace();
                        };
                        markSandboxSolved("upload-mime", 200, "Content-Type Bypass");
                    } else {
                        out.innerHTML = "<span style='color:red;'>Error: Rejected. Only MIME type image/png or image/jpeg allowed!</span>";
                        logConsole("Upload rejected: Content-Type is application/x-php", "error-line");
                    }
                } else {
                    out.innerHTML = "<span style='color:green;'>Image loaded successfully!</span>";
                }
            };
            break;

        case "upload-shell":
            loadWebShellWorkspace();
            break;

        case "upload-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏁 Webshell Flag Portal</h2>
                    <p>The backend blocks extension `.php` strings. Bypass the filter using `.php5` to upload a backend shell.</p>
                    <div style="border:2px dashed #ccc; padding:20px; text-align:center;">
                        <input type="file" id="ctfFileIn" style="display:none;">
                        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('ctfFileIn').click()">Choose File</button>
                        <p id="ctfFileLbl" style="font-size:0.8rem; margin-top:6px;">No file selected</p>
                    </div>
                    <button class="btn btn-primary btn-sm" id="ctfUploadBtn">Upload</button>
                    <div id="ctfUploadOut" style="margin-top:12px;"></div>
                </div>
            `;

            const ctfFile = document.getElementById("ctfFileIn");
            ctfFile.onchange = () => { if (ctfFile.files.length > 0) document.getElementById("ctfFileLbl").innerText = ctfFile.files[0].name; };

            document.getElementById("ctfUploadBtn").onclick = () => {
                if (ctfFile.files.length === 0) return;
                const name = ctfFile.files[0].name;
                logProxyRequest("POST", "http://share-space.local/ctf-upload", {}, name);
                const out = document.getElementById("ctfUploadOut");

                if (name.endsWith(".php")) {
                    out.innerHTML = "<span style='color:red;'>Error: Upload containing blocklisted extension '.php' is forbidden!</span>";
                    logConsole("Upload blocked: .php extension disallowed.", "error-line");
                } else if (name.endsWith(".php5") || name.endsWith(".phtml")) {
                    logConsole("Bypass validation complete: .php5 extension accepted.", "success-line");
                    out.innerHTML = `
                        <div style="border:1px solid green; padding:12px; background:#e6fffa; border-radius:6px;">
                            ✓ Upload success!<br>
                            Click to launch shell: <a href="#" id="ctfShellLink" style="color:blue;">/uploads/${name}</a>
                        </div>
                    `;
                    document.getElementById("ctfShellLink").onclick = () => {
                        loadWebShellWorkspace(true);
                    };
                } else {
                    out.innerHTML = "<span style='color:green;'>Uploaded non-executable file.</span>";
                }
            };
            break;

        // --- PATH TRAVERSAL LABS ---
        case "traversal-basic":
        case "traversal-filter":
        case "traversal-sensitive":
        case "traversal-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📂 Document Repository Manager</h2>
                    <p>Click invoices below to open files:</p>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        <button class="btn btn-secondary btn-sm" onclick="navigateToUrl('${defaultUrl}?file=financial_report.pdf')">Financial Report</button>
                        <button class="btn btn-secondary btn-sm" onclick="navigateToUrl('${defaultUrl}?file=annual_taxes.pdf')">Annual Taxes</button>
                    </div>
                    <div id="traversalOutBox" style="margin-top:20px; border:1px solid #ddd; padding:16px; min-height:80px; background:#fff; font-family:monospace; font-size:0.8rem; overflow-x:auto;">
                        Select a document to read details.
                    </div>
                </div>
            `;
            break;

        // --- AUTHENTICATION LABS ---
        case "auth-brute":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <div style="max-width:320px; margin:0 auto; border:1px solid #ddd; padding:20px; background:#f9f9f9; border-radius:8px;">
                        <h3>🔒 Admin Panel Gateway</h3>
                        <div style="margin-bottom:8px;">
                            <label style="font-size:0.75rem;">Username</label>
                            <input type="text" id="bruteUser" value="admin" style="width:100%; padding:6px;">
                        </div>
                        <div style="margin-bottom:12px;">
                            <label style="font-size:0.75rem;">Password</label>
                            <input type="password" id="brutePass" style="width:100%; padding:6px;">
                        </div>
                        <button class="btn btn-primary" id="bruteBtn" style="width:100%;">Submit Credentials</button>
                        <div id="bruteOut" style="margin-top:12px; font-weight:700; color:red;"></div>
                    </div>
                    <div style="margin-top:16px; border:1px solid #ccc; padding:12px; background:#fff; font-size:0.75rem;">
                        <strong>🔑 Weak Password Wordlist:</strong><br>
                        welcome, root, security, dragon, admin123, master, password, pass123
                    </div>
                </div>
            `;

            document.getElementById("bruteBtn").onclick = () => {
                const u = document.getElementById("bruteUser").value;
                const p = document.getElementById("brutePass").value;
                logProxyRequest("POST", "http://login-page.local/login", {}, { user: u, pass: p });

                const out = document.getElementById("bruteOut");
                if (u === "admin" && p === "admin123") {
                    out.innerHTML = "<span style='color:green;'>Authentication Success! Welcome Admin.</span>";
                    logConsole("Login successful on admin123", "success-line");
                    markSandboxSolved("auth-brute", 100, "Weak Password Brute Force");
                } else {
                    out.innerText = "Error: Invalid username or password.";
                    logConsole(`Brute force attempt failed: ${p}`, "error-line");
                }
            };
            break;

        case "auth-fixation":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔗 Secure Banking Portal</h2>
                    <p>Authenticate sessions. The system loads account credentials based on <code>session_id</code> cookie tokens.</p>
                    <div style="margin-bottom:16px; border:1px solid #3b82f6; padding:12px; background:#eff6ff;">
                        Logged in as: <strong id="fixationUser">Guest User</strong>
                    </div>
                    <button class="btn btn-primary btn-sm" id="fixationLogin">Confirm Authentication</button>
                </div>
            `;

            const runFixationCheck = () => {
                const sid = currentCookies["session_id"];
                logConsole(`Checking active session: session_id=${sid}`);
                
                if (sid === "attacker_token") {
                    document.getElementById("fixationUser").innerText = "Administrator Account";
                    logConsole("Admin authenticated on fixated session token!", "success-line");
                    markSandboxSolved("auth-fixation", 200, "Session Fixation Exploit");
                }
            };

            document.getElementById("fixationLogin").onclick = () => {
                logProxyRequest("POST", "http://login-page.local/api/session-login", {}, { session: currentCookies["session_id"] });
                runFixationCheck();
            };
            runFixationCheck();
            break;

        case "auth-hijack":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛰️ Unencrypted Internal API Portal</h2>
                    <p>This portal accesses systems using cookie strings. Intercept networks traffic using DevTools proxy logs to discover credentials.</p>
                    <div id="hijackOut" style="margin-top:20px; font-weight:700; color:red; padding:12px; border:1px dashed #ccc;">
                        Access Denied: Unauthenticated.
                    </div>
                </div>
            `;

            // Write custom traffic packets log in proxy log
            setTimeout(() => {
                logConsole("Intercepting network packets...", "system-line");
                logProxyRequest("GET", "http://login-page.local/user/profile", {
                    "Host": "login-page.local",
                    "Cookie": "session=hijack_cookie_token_9921",
                    "User-Agent": "Mozilla/5.0"
                });
            }, 1000);

            const runHijackCheck = () => {
                const s = currentCookies["session"];
                if (s === "hijack_cookie_token_9921") {
                    document.getElementById("hijackOut").innerHTML = `
                        <div style="background:#e6fffa; border:1px solid #34d399; color:green; padding:16px;">
                            ✓ ACCOUNT HIJACKED! Welcome admin user.<br>
                            Flag unlocked: <strong>[captured flag]</strong>
                        </div>
                    `;
                    logConsole("Session hijacked successfully via cookie injection!", "success-line");
                    markSandboxSolved("auth-hijack", 300, "Session Hijacking Capture");
                }
            };
            runHijackCheck();
            break;

        case "auth-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <div style="max-width:300px; margin:0 auto; border:1px solid #ddd; padding:16px; background:#f9f9f9;">
                        <h3>🏁 Administrator login gateway</h3>
                        <div style="margin-bottom:8px;">
                            <label style="font-size:0.75rem;">Username</label>
                            <input type="text" id="authCtfUser" value="admin" style="width:100%; padding:4px;">
                        </div>
                        <div style="margin-bottom:8px;">
                            <label style="font-size:0.75rem;">Password</label>
                            <input type="password" id="authCtfPass" style="width:100%; padding:4px;">
                        </div>
                        <button class="btn btn-primary btn-sm" id="authCtfBtn" style="width:100%;">Login</button>
                        <div id="authCtfOut" style="margin-top:10px; font-weight:700; color:red;"></div>
                    </div>
                    <div style="margin-top:12px; font-size:0.75rem; border:1px solid #ccc; padding:8px; background:#fff;">
                        <strong>🔑 Intruder Dictionary List:</strong><br>
                        welcome, root, security, dragon, shadow, hunter2
                    </div>
                </div>
            `;

            document.getElementById("authCtfBtn").onclick = () => {
                const u = document.getElementById("authCtfUser").value;
                const p = document.getElementById("authCtfPass").value;
                logProxyRequest("POST", "http://login-page.local/login", {}, { user: u, pass: p });

                const out = document.getElementById("authCtfOut");
                if (u === "admin" && p === "shadow") {
                    out.innerHTML = `<span style='color:green;'>Success! Flag: [captured flag]</span>`;
                    logConsole("Correct admin password guessed: shadow", "success-line");
                } else {
                    out.innerText = "Error: Authentication failed.";
                    logConsole(`Brute force attempt failed: ${p}`, "error-line");
                }
            };
            break;

        // --- SSRF LABS ---
        case "ssrf-basic":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛰️ Cloud Proxy Fetcher</h2>
                    <p>Enter remote URL to generate website snapshots:</p>
                    <div style="display:flex; gap:8px; margin-bottom:16px;">
                        <input type="text" id="ssrfBasicIn" placeholder="http://google.com" style="flex-grow:1; padding:8px; border:1px solid #ccc; border-radius:4px;">
                        <button class="btn btn-primary btn-sm" id="ssrfBasicBtn">Request</button>
                    </div>
                    <div id="ssrfBasicOut" style="border:1px solid #ddd; padding:12px; background:#fff; font-size:0.8rem; font-family:monospace; min-height:80px; overflow-y:auto; max-height:200px;">
                        Proxy ready.
                    </div>
                </div>
            `;

            document.getElementById("ssrfBasicBtn").onclick = () => {
                const url = document.getElementById("ssrfBasicIn").value.trim();
                logProxyRequest("POST", "http://cloud-proxy.local/fetch", {}, { targetUrl: url });
                logConsole(`Server fetching: ${url}`, "log-line");

                const out = document.getElementById("ssrfBasicOut");

                if (url.includes("127.0.0.1") || url.includes("localhost")) {
                    if (url.includes("/admin")) {
                        out.innerHTML = `
                            <div style="border:1px solid green; padding:12px; background:#e6fffa;">
                                <strong>✓ Internal Admin Dashboard</strong><br>
                                system_status: Online<br>
                                database_host: local_socket<br>
                                flag: [captured flag]
                            </div>
                        `;
                        logConsole("SSRF connection resolved to internal host localhost:80/admin", "success-line");
                        markSandboxSolved("ssrf-basic", 100, "Internal Site Fetching");
                    } else {
                        out.innerText = "Error 404: Route not found on localhost.";
                        logConsole("SSRF loopback access success: 404", "log-line");
                    }
                } else {
                    out.innerText = `Content of ${url}:\n<html><body>Hello World from public site</body></html>`;
                }
            };
            break;

        case "ssrf-meta":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛰️ API Cloud Endpoint proxy</h2>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="ssrfMetaIn" placeholder="Enter service address..." style="flex-grow:1; padding:6px;">
                        <button class="btn btn-primary btn-sm" id="ssrfMetaBtn">Fetch</button>
                    </div>
                    <div id="ssrfMetaOut" style="border:1px solid #ccc; padding:12px; font-family:monospace; font-size:0.8rem; min-height:60px;"></div>
                </div>
            `;

            document.getElementById("ssrfMetaBtn").onclick = () => {
                const url = document.getElementById("ssrfMetaIn").value.trim();
                logProxyRequest("POST", "http://cloud-proxy.local/api/proxy", {}, { url: url });

                const out = document.getElementById("ssrfMetaOut");

                if (url.includes("169.254.169.254")) {
                    if (url.includes("iam/security-credentials/admin")) {
                        out.innerHTML = `
                            {\n  "AccessKeyId": "ASIAV17726372AA",\n  "SecretAccessKey": "Kj982ksldhHh81+a/SP_METADATA_SECRET",\n  "Token": "aws_session_token_1900182",\n  "Flag": "[captured flag]"\n}
                        `;
                        logConsole("AWS Cloud metadata accessed via SSRF!", "success-line");
                        markSandboxSolved("ssrf-meta", 200, "Cloud Metadata Access");
                    } else {
                        out.innerText = "latest\nmeta-data\nuser-data";
                    }
                } else {
                    out.innerText = "Proxy response timed out.";
                }
            };
            break;

        case "ssrf-scan":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛰️ Internal Network Scanner</h2>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="ssrfScanIn" placeholder="http://127.0.0.1:port" style="flex-grow:1; padding:6px;">
                        <button class="btn btn-primary btn-sm" id="ssrfScanBtn">Scan Port</button>
                    </div>
                    <div id="ssrfScanOut" style="font-weight:700; font-size:0.95rem;"></div>
                </div>
            `;

            document.getElementById("ssrfScanBtn").onclick = () => {
                const url = document.getElementById("ssrfScanIn").value.trim();
                logProxyRequest("POST", "http://cloud-proxy.local/scan", {}, { target: url });

                const out = document.getElementById("ssrfScanOut");

                if (url.includes("127.0.0.1") || url.includes("localhost")) {
                    if (url.includes(":6379")) {
                        out.innerHTML = "<span style='color:green;'>✓ PORT 6379 OPEN: Redis Server 6.0.9 detected. Connection Accepted.</span>";
                        logConsole("Internal scan match found: Redis port 6379 open.", "success-line");
                        markSandboxSolved("ssrf-scan", 300, "Internal Service Port Scan");
                    } else {
                        out.innerHTML = "<span style='color:red;'>✗ Connection Refused: Port closed.</span>";
                        logConsole(`Port connection timeout for address: ${url}`, "error-line");
                    }
                } else {
                    out.innerText = "Only local IP targets permitted.";
                }
            };
            break;

        case "ssrf-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏁 SSRF Redirect Exploit</h2>
                    <p>The fetcher blocks '169.254.169.254' directly. Redirect requests using local endpoints.</p>
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="ssrfCtfIn" placeholder="URL..." style="flex-grow:1; padding:6px;">
                        <button class="btn btn-primary btn-sm" id="ssrfCtfBtn">Request Target</button>
                    </div>
                    <div id="ssrfCtfOut" style="margin-top:12px; font-family:monospace; border:1px solid #ccc; padding:10px;"></div>
                </div>
            `;

            document.getElementById("ssrfCtfBtn").onclick = () => {
                const url = document.getElementById("ssrfCtfIn").value.trim();
                logProxyRequest("POST", "http://cloud-proxy.local/ctf-fetch", {}, { url: url });
                const out = document.getElementById("ssrfCtfOut");

                if (url.includes("169.254.169.254")) {
                    out.innerText = "Forbidden: Access to cloud metadata IP blocked.";
                    logConsole("SSRF blocklist rule triggered: Metadata IP rejected.", "error-line");
                } else if (url.includes("redirect?url=") && url.includes("169.254.169.254")) {
                    logConsole("SSRF Bypass: Server followed local open redirect to metadata.", "success-line");
                    out.innerHTML = `
                        <div style="color:green;">
                            ✓ REDIRECT FOLLOWED: Metadata read.<br>
                            Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                } else {
                    out.innerText = "Fetch complete.";
                }
            };
            break;

        // --- SECURITY MISCONFIGURATION LABS ---
        case "misconfig-robots":
        case "misconfig-debug":
        case "misconfig-git":
        case "misconfig-ctf":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>⚙️ System Home Dashboard</h2>
                    <p>Welcome to configuration control systems dashboard.</p>
                </div>
            `;
            break;

        // --- CTF ARENA EASY CHALLENGES ---
        case "ctf-easy-1":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📝 Static Company Details</h2>
                    <p>Look around the components. Review page comments to recover details.</p>
                    <button class="btn btn-secondary btn-sm" id="ctfEasy1SrcBtn">View Source Code</button>
                    <div id="ctfEasy1Src" style="display:none; margin-top:12px; font-family:monospace; background:#222; color:#fff; padding:12px; border-radius:4px; font-size:0.75rem; white-space:pre-wrap;"></div>
                </div>
            `;
            document.getElementById("ctfEasy1SrcBtn").onclick = () => {
                const src = document.getElementById("ctfEasy1Src");
                src.style.display = src.style.display === "none" ? "block" : "none";
                src.innerText = `<!DOCTYPE html>\n<html>\n<head>\n  <title>Company Details</title>\n</head>\n<body>\n  <h1>Details page</h1>\n  <!-- FLAG: [captured flag] -->\n  <p>Static description of corporate services.</p>\n</body>\n</html>`;
            };
            break;

        case "ctf-easy-2":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 Cookie Portal Gate</h2>
                    <div id="ctfEasy2Out" style="padding:16px; border:1px solid #ccc; font-weight:700; color:red;">
                        ACCESS DENIED: Cookie role is not set to admin.
                    </div>
                </div>
            `;
            const checkCtfEasy2 = () => {
                const admin = currentCookies["admin"];
                if (admin === "true") {
                    document.getElementById("ctfEasy2Out").innerHTML = `
                        <div style="background:#e6fffa; color:green; border:1px solid green; padding:12px;">
                            ✓ WELCOME ADMINISTRATOR!<br>
                            Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                }
            };
            checkCtfEasy2();
            break;

        case "ctf-easy-3":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 Credentials Lock</h2>
                    <div style="max-width:280px; margin:0 auto; padding:16px; border:1px solid #ccc;">
                        <h4>Admin Login</h4>
                        <input type="password" id="ctfEasy3Pass" placeholder="Password..." style="width:100%; padding:6px; margin-bottom:8px;">
                        <button class="btn btn-primary btn-sm" id="ctfEasy3Btn" style="width:100%;">Submit</button>
                    </div>
                    <button class="btn btn-secondary btn-sm" id="ctfEasy3SrcBtn" style="margin-top:12px;">Inspect auth.js</button>
                    <div id="ctfEasy3Src" style="display:none; font-family:monospace; background:#222; color:#fff; padding:10px; font-size:0.75rem; margin-top:8px;">
                        const admin_pass = "cyber_god_2026";\nfunction checkAuth(p) {\n  return p === admin_pass;\n}
                    </div>
                    <div id="ctfEasy3Out" style="margin-top:10px; font-weight:700;"></div>
                </div>
            `;
            document.getElementById("ctfEasy3SrcBtn").onclick = () => {
                const src = document.getElementById("ctfEasy3Src");
                src.style.display = src.style.display === "none" ? "block" : "none";
            };
            document.getElementById("ctfEasy3Btn").onclick = () => {
                const pass = document.getElementById("ctfEasy3Pass").value;
                const out = document.getElementById("ctfEasy3Out");
                if (pass === "cyber_god_2026") {
                    out.innerHTML = "<span style='color:green;'>Flag: [captured flag]</span>";
                } else {
                    out.innerHTML = "<span style='color:red;'>Access Denied.</span>";
                }
            };
            break;

        case "ctf-easy-4":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🤖 Corporate Crawler Gateway</h2>
                    <p>Welcome to corporate index page. Crawlers can review indexing instructions.</p>
                </div>
            `;
            break;

        case "ctf-easy-5":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔓 Cryptographic Base64 Decoder</h2>
                    <p>Decipher key values to secure target flags:</p>
                    <div style="margin-bottom:12px;">
                        <input type="text" id="b64Cipher" value="U1B7YmFzZTY0X2RlY29kZV9zdWNjZXNzfQ==" style="width:100%; padding:8px; font-family:monospace;">
                    </div>
                    <button class="btn btn-primary btn-sm" id="b64Btn">Decode Cipher</button>
                    <div id="b64Out" style="margin-top:16px; font-weight:700; color:green; font-family:monospace;"></div>
                </div>
            `;
            document.getElementById("b64Btn").onclick = () => {
                const cipher = document.getElementById("b64Cipher").value;
                try {
                    const decoded = atob(cipher);
                    logConsole(`Base64 Decode Result: ${decoded}`, "success-line");
                    document.getElementById("b64Out").innerText = `Result: ${decoded}`;
                } catch(e) {
                    logConsole("Error: Invalid Base64 string", "error-line");
                    document.getElementById("b64Out").innerText = "Invalid Base64 format.";
                }
            };
            break;

        case "ctf-easy-6":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📥 Network Custom Headers Dashboard</h2>
                    <p>Audit incoming transactions. Custom metadata flag token has been embedded inside HTTP logs.</p>
                </div>
            `;
            setTimeout(() => {
                logConsole("Logs analysis initialized...", "system-line");
                logProxyRequest("GET", "http://site-headers.local/", {
                    "Host": "site-headers.local",
                    "X-Custom-Flag": "[captured flag]"
                });
            }, 800);
            break;

        case "ctf-easy-7":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛒 Smart Cart Checkout</h2>
                    <div style="border:1px solid #ccc; padding:16px; max-width:280px; background:#fafafa; border-radius:6px;">
                        <h4>Super Laptop</h4>
                        <p style="color:#555;">Retail Price: $1000.00</p>
                        <div style="margin-bottom:10px;">
                            <label style="font-size:0.75rem;">Price Parameter ($)</label>
                            <input type="number" id="ctfEasy7Price" value="1000" style="width:100%; padding:6px; border:1px solid #ccc; border-radius:4px;">
                        </div>
                        <button class="btn btn-primary btn-sm" id="ctfEasy7Btn" style="width:100%;">Purchase</button>
                    </div>
                    <div id="ctfEasy7Out" style="margin-top:10px; font-weight:700;"></div>
                </div>
            `;
            document.getElementById("ctfEasy7Btn").onclick = () => {
                const p = parseInt(document.getElementById("ctfEasy7Price").value);
                const out = document.getElementById("ctfEasy7Out");
                logProxyRequest("POST", "http://smart-cart.local/checkout", {}, { price: p });
                if (p <= 0) {
                    out.innerHTML = "<span style='color:green;'>Purchase Complete! Price: $0. Flag: [captured flag]</span>";
                    logConsole("Payment validation complete! Price parameter bypass verified.", "success-line");
                } else {
                    out.innerHTML = "<span style='color:red;'>Insufficient credit balance. Try parameter tampering.</span>";
                    logConsole("Payment transaction declined. Insufficient balance.", "error-line");
                }
            };
            break;

        case "ctf-easy-8":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛡️ Agent Authentication Shield</h2>
                    <div id="ctfEasy8Out" style="padding:16px; border:1px solid #ccc; font-weight:700; color:red; background:#fef2f2; border-radius:6px;">
                        ACCESS DENIED: Web crawler detected. Requires User-Agent: SecurityPlaygroundAdmin.
                    </div>
                </div>
            `;
            const checkCtfEasy8 = () => {
                const proxyHeaders = parseProxyLogsHeaders();
                const ua = proxyHeaders["user-agent"] || "";
                if (ua.includes("SecurityPlaygroundAdmin")) {
                    document.getElementById("ctfEasy8Out").innerHTML = `
                        <div style="background:#e6fffa; color:green; border:1px solid green; padding:12px;">
                            ✓ USER-AGENT SPOOFED!<br>
                            Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                    logConsole("User-agent checks passed.", "success-line");
                }
            };
            checkCtfEasy8();
            break;

        case "ctf-easy-9":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📂 User Invoice Viewer</h2>
                    <p>Tamper URL ID query parameters to fuzz indexes.</p>
                </div>
            `;
            const checkCtfEasy9 = () => {
                const url = urlInput.value;
                if (url.includes("id=0")) {
                    viewport.innerHTML = `
                        <div class="viewport-site" style="border:1px solid green; padding:20px; background:#f0fdf4;">
                            <h3>🧾 Administration Invoice Details</h3>
                            <p>Customer: Root Administrator</p>
                            <p>Flag Captured: <strong>[captured flag]</strong></p>
                        </div>
                    `;
                    logConsole("ID parameter fuzzed successfully to index 0.", "success-line");
                }
            };
            checkCtfEasy9();
            break;

        case "ctf-easy-10":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 Blank Credentials Checker</h2>
                    <div style="max-width:300px; margin:0 auto; padding:16px; border:1px solid #ccc; border-radius:6px; background:#f9f9f9;">
                        <h4>Admin Portal</h4>
                        <div style="margin-bottom:10px;">
                            <label style="font-size:0.75rem;">Username</label>
                            <input type="text" id="easy10User" value="admin" style="width:100%; padding:6px;">
                        </div>
                        <div style="margin-bottom:10px;">
                            <label style="font-size:0.75rem;">Password</label>
                            <input type="password" id="easy10Pass" value="password" style="width:100%; padding:6px;">
                        </div>
                        <button class="btn btn-primary btn-sm" id="easy10Btn" style="width:100%;">Sign In</button>
                        <div id="easy10Out" style="margin-top:10px; font-weight:700; color:red;"></div>
                    </div>
                </div>
            `;
            document.getElementById("easy10Btn").onclick = () => {
                const u = document.getElementById("easy10User").value;
                const proxyHeaders = parseProxyLogsHeaders();
                const body = getProxyBody();

                logProxyRequest("POST", "http://login-page.local/api/verify", proxyHeaders, body);
                const out = document.getElementById("easy10Out");

                // The actual request body sent is whatever's in the editable
                // Proxy Logs > Request Body box. Remove the &pass=... part
                // there (not just clear the password input above) to bypass.
                if (!body.includes("pass=")) {
                    out.innerHTML = "<span style='color:green;'>Flag: [captured flag]</span>";
                    logConsole("Authentication check passed: blank password parameter bypass.", "success-line");
                } else {
                    out.innerText = "Error: Authentication failed.";
                    logConsole("Authentication failed: invalid credentials.", "error-line");
                }
            };
            break;

        // --- CTF ARENA MEDIUM CHALLENGES ---
        case "ctf-medium-11":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 JWT None Algorithm Login</h2>
                    <div style="margin-bottom:16px; border:1px solid #ddd; padding:12px; background:#fafafa; border-radius:6px;">
                        <label style="font-size:0.8rem; font-weight:700;">Submit JWT Token</label>
                        <input type="text" id="jwtInput" placeholder="header.payload.signature" style="width:100%; padding:8px; font-family:monospace; margin-top:6px;">
                    </div>
                    <button class="btn btn-primary btn-sm" id="jwtLoginBtn">Login</button>
                    <div id="jwtOut" style="margin-top:16px; font-weight:700; color:red;"></div>
                    
                    <div style="margin-top:20px; border-top:1px solid #eee; padding-top:12px; font-size:0.75rem;">
                        <strong>🛠️ JWT Encoder:</strong><br>
                        Header: <input type="text" id="jwtHeader" value='{"alg":"none","typ":"JWT"}' style="width:100%; margin-bottom:4px; font-family:monospace;"><br>
                        Payload: <input type="text" id="jwtPayload" value='{"role":"admin"}' style="width:100%; margin-bottom:8px; font-family:monospace;"><br>
                        <button class="btn btn-secondary btn-sm" id="jwtEncodeBtn">Encode Payload</button>
                        <div id="jwtEncodeOut" style="font-family:monospace; margin-top:6px; word-break:break-all; color:blue;"></div>
                    </div>
                </div>
            `;
            document.getElementById("jwtEncodeBtn").onclick = () => {
                const h = document.getElementById("jwtHeader").value;
                const p = document.getElementById("jwtPayload").value;
                try {
                    const hB64 = btoa(h).replace(/=/g, "");
                    const pB64 = btoa(p).replace(/=/g, "");
                    document.getElementById("jwtEncodeOut").innerText = `${hB64}.${pB64}.`;
                } catch(e) {
                    document.getElementById("jwtEncodeOut").innerText = "Error encoding components.";
                }
            };
            document.getElementById("jwtLoginBtn").onclick = () => {
                const token = document.getElementById("jwtInput").value.trim();
                logProxyRequest("POST", "http://jwt-gate.local/login", {}, { token: token });
                
                const parts = token.split(".");
                const out = document.getElementById("jwtOut");
                
                if (parts.length >= 2) {
                    try {
                        const header = JSON.parse(atob(parts[0]));
                        const payload = JSON.parse(atob(parts[1]));
                        
                        if (header.alg === "none" && payload.role === "admin") {
                            out.innerHTML = "<span style='color:green;'>Success! Welcome admin. Flag: [captured flag]</span>";
                            logConsole("JWT validation passed with none algorithm.", "success-line");
                        } else {
                            out.innerText = "Error: Access denied. Role must be admin.";
                        }
                    } catch(e) {
                        out.innerText = "Error: Invalid token signature format.";
                    }
                } else {
                    out.innerText = "Error: Invalid JWT structure.";
                }
            };
            break;

        case "ctf-medium-12":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📡 Private Account REST API</h2>
                    <p>Enter route path to fetch details:</p>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="medium12Path" value="/api/users/v1/105" style="flex-grow:1; font-family:monospace; padding:6px;">
                        <button class="btn btn-primary btn-sm" id="medium12Btn">Fetch REST API</button>
                    </div>
                    <div id="medium12Out" style="border:1px solid #ccc; padding:12px; font-family:monospace; font-size:0.8rem; background:#222; color:#38bdf8;">
                        {"id": 105, "user": "guest", "role": "user"}
                    </div>
                </div>
            `;
            document.getElementById("medium12Btn").onclick = () => {
                const path = document.getElementById("medium12Path").value.trim();
                logProxyRequest("GET", `http://account-portal.local${path}`);
                
                const out = document.getElementById("medium12Out");
                if (path === "/api/users/v1/100") {
                    out.innerHTML = `{\n  "id": 100,\n  "user": "administrator",\n  "role": "admin",\n  "token_flag": "[captured flag]"\n}`;
                    logConsole("IDOR target matched for admin account.", "success-line");
                } else {
                    out.innerText = `{"id": 105, "user": "guest", "role": "user"}`;
                }
            };
            break;

        case "ctf-medium-13":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 MD5 Authentication Gate</h2>
                    <p>Crack hash and submit password: <code>099ebea48ea9666a7da217726b4da513</code></p>
                    <div style="max-width:280px; margin:0 auto; padding:16px; border:1px solid #ccc;">
                        <input type="password" id="med13Pass" placeholder="Decoded Password..." style="width:100%; padding:6px; margin-bottom:8px;">
                        <button class="btn btn-primary btn-sm" id="med13Btn" style="width:100%;">Sign In</button>
                    </div>
                    <div id="med13Out" style="margin-top:10px; font-weight:700; color:red; text-align:center;"></div>
                </div>
            `;
            document.getElementById("med13Btn").onclick = () => {
                const pass = document.getElementById("med13Pass").value.trim();
                const out = document.getElementById("med13Out");
                logProxyRequest("POST", "http://auth.local/login", {}, { pass: pass });
                
                if (pass === "hunter2") {
                    out.innerHTML = "<span style='color:green;'>Flag: [captured flag]</span>";
                    logConsole("Password hash validation matched on: hunter2", "success-line");
                } else {
                    out.innerText = "Error: Password incorrect.";
                }
            };
            break;

        case "ctf-medium-14":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📝 XML Document Parser</h2>
                    <p>Paste the XML template payload to check credentials:</p>
                    <textarea id="xmlPayload" style="width:100%; height:100px; font-family:monospace; margin-bottom:10px;"></textarea>
                    <button class="btn btn-primary btn-sm" id="xmlBtn">Parse XML</button>
                    <div id="xmlOut" style="margin-top:12px; font-family:monospace; font-size:0.8rem; border:1px solid #ccc; padding:8px;"></div>
                </div>
            `;
            document.getElementById("xmlBtn").onclick = () => {
                const xml = document.getElementById("xmlPayload").value;
                logProxyRequest("POST", "http://xml-gate.local/parse", {}, xml);
                
                const out = document.getElementById("xmlOut");
                if (xml.includes("ENTITY") && xml.includes("SYSTEM") && xml.includes("flag.txt")) {
                    out.innerHTML = "<span style='color:green;'>SYSTEM output: [captured flag]</span>";
                    logConsole("XXE validation passed. Loaded file: /etc/flag.txt", "success-line");
                } else {
                    out.innerText = "XML Parsed successfully. No match elements.";
                }
            };
            break;

        case "ctf-medium-15":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>👕 Product search Base</h2>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="med15In" placeholder="Product ID..." style="flex-grow:1; padding:6px;">
                        <button class="btn btn-primary btn-sm" id="med15Btn">Search</button>
                    </div>
                    <div id="med15Out" style="font-weight:700; color:blue;"></div>
                </div>
            `;
            document.getElementById("med15Btn").onclick = () => {
                const val = document.getElementById("med15In").value.trim();
                logProxyRequest("GET", `http://secure-login.local/item?id=${encodeURIComponent(val)}`);
                logConsole(`SQL Query: SELECT * FROM items WHERE id = '${val}'`, "log-line");
                
                const out = document.getElementById("med15Out");
                if (val.includes("' AND 1=1") || val.includes("' OR 1=1")) {
                    out.innerHTML = "<span style='color:green;'>Item Exists! Flag: [captured flag]</span>";
                    logConsole("SQL injection boolean returned: TRUE", "success-line");
                } else {
                    out.innerText = "Item stock active.";
                }
            };
            break;

        case "ctf-medium-16":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>⚙️ PHP Object Portal Dashboard</h2>
                    <div id="phpSerialOut" style="padding:16px; border:1px solid #ccc; font-weight:700; color:red; background:#fef2f2;">
                        ACCESS DENIED: Serialized profile isAdmin is set to false.
                    </div>
                </div>
            `;
            const checkPhpSerial = () => {
                const userCookie = currentCookies["User"] || "";
                if (userCookie) {
                    try {
                        const decoded = atob(userCookie);
                        logConsole(`Cookie User Decoded: ${decoded}`);
                        if (decoded.includes("isAdmin") && decoded.includes("b:1")) {
                            document.getElementById("phpSerialOut").innerHTML = `
                                <div style="background:#e6fffa; color:green; border:1px solid green; padding:12px;">
                                    ✓ ROLE ELEVATED TO ADMIN!<br>
                                    Flag: <strong>[captured flag]</strong>
                                </div>
                            `;
                            logConsole("Object deserialization check completed successfully.", "success-line");
                        }
                    } catch(e) {
                        logConsole("Error parsing User cookie.", "error-line");
                    }
                }
            };
            // Set default cookie
            if (!currentCookies["User"]) {
                currentCookies["User"] = "Tzo0OiJVc2VyIjoyOntzOjQ6InVzZXIiO3M6NToiZ3Vlc3QiO3M6NToiaXNBZG0iO2I6MDt9";
                renderCookiesTable();
            }
            checkPhpSerial();
            break;

        case "ctf-medium-17":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📋 Git Commit Repository Logs</h2>
                    <p>Double click commits to inspect source changes:</p>
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        <button class="btn btn-secondary btn-sm" id="commitBtn1" style="text-align:left;">Commit d67e812 - revert database credentials</button>
                        <button class="btn btn-secondary btn-sm" style="text-align:left;">Commit f3a1290 - setup admin auth</button>
                    </div>
                    <div id="commitDiffOut" style="display:none; font-family:monospace; background:#222; color:#fff; padding:12px; margin-top:12px; font-size:0.75rem; white-space:pre-wrap;"></div>
                </div>
            `;
            document.getElementById("commitBtn1").onclick = () => {
                const diff = document.getElementById("commitDiffOut");
                diff.style.display = "block";
                diff.innerHTML = `<span style="color:red;">- const API_KEY = "[captured flag]"</span>\n<span style="color:green;">+ const API_KEY = process.env.API_KEY</span>`;
                logConsole("Commit modifications loaded.", "success-line");
            };
            break;

        case "ctf-medium-18":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛡️ CORS API Endpoint Terminal</h2>
                    <p>Enter target request Origin domain:</p>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="corsOrigin" value="http://evil-site.local" style="flex-grow:1; font-family:monospace;">
                        <button class="btn btn-primary btn-sm" id="corsBtn">Fetch API</button>
                    </div>
                    <div id="corsOut" style="font-family:monospace; font-size:0.8rem; border:1px solid #ccc; padding:8px;"></div>
                </div>
            `;
            document.getElementById("corsBtn").onclick = () => {
                const origin = document.getElementById("corsOrigin").value;
                logProxyRequest("GET", "http://api.secure-bank.local/config", { "Origin": origin });
                
                const out = document.getElementById("corsOut");
                out.innerHTML = `
                    <strong>Response Headers:</strong><br>
                    Access-Control-Allow-Origin: *<br>
                    Access-Control-Allow-Credentials: true<br><br>
                    <strong>Response Body:</strong><br>
                    { "flag": "[captured flag]" }
                `;
                logConsole("CORS connection authorized via wildcard headers.", "success-line");
            };
            break;

        case "ctf-medium-19":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛑 Rate Limit Login Shield</h2>
                    <div id="rateLimitOut" style="padding:16px; border:1px solid red; font-weight:700; color:red; background:#fef2f2;">
                        TOO MANY LOGIN ATTEMPTS from your IP block. Please wait 15 minutes.
                    </div>
                </div>
            `;
            const checkRateLimit = () => {
                const proxyHeaders = parseProxyLogsHeaders();
                const forward = proxyHeaders["x-forwarded-for"];
                if (forward && forward !== "127.0.0.1") {
                    document.getElementById("rateLimitOut").innerHTML = `
                        <div style="background:#e6fffa; color:green; border:1px solid green; padding:12px;">
                            ✓ IP BLOCK BYPASSED via X-Forwarded-For: ${forward}!<br>
                            Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                    logConsole("Rate limit bypass complete.", "success-line");
                }
            };
            checkRateLimit();
            break;

        case "ctf-medium-20":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 XOR Cryptography decoder</h2>
                    <div style="margin-bottom:10px;">
                        <label style="font-size:0.75rem;">Cipher Hex</label>
                        <input type="text" id="xorCipher" value="3c071a171d1810141f01031317" style="width:100%; padding:6px; font-family:monospace;">
                    </div>
                    <div style="margin-bottom:12px;">
                        <label style="font-size:0.75rem;">XOR Key</label>
                        <input type="text" id="xorKey" value="hacker" style="width:100%; padding:6px; font-family:monospace;">
                    </div>
                    <button class="btn btn-primary btn-sm" id="xorBtn">Decrypt</button>
                    <div id="xorOut" style="margin-top:12px; font-weight:700; font-family:monospace; color:green;"></div>
                </div>
            `;
            document.getElementById("xorBtn").onclick = () => {
                const hex = document.getElementById("xorCipher").value;
                const key = document.getElementById("xorKey").value;
                const out = document.getElementById("xorOut");
                
                if (hex === "3c071a171d1810141f01031317" && key === "hacker") {
                    out.innerText = "Result: [captured flag]";
                    logConsole("XOR decipher operations complete.", "success-line");
                } else {
                    out.innerText = "Error: Key/Hex mismatch.";
                }
            };
            break;

        // --- CTF ARENA HARD CHALLENGES ---
        case "ctf-hard-21":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 JWT Signature Signer</h2>
                    <div style="border:1px solid #ddd; padding:12px; background:#fafafa; border-radius:6px;">
                        <h4>Admin Settings Gate</h4>
                        <div id="jwtHardOut" style="color:red; font-weight:700; font-size:0.85rem; margin-top:6px;">
                            Authenticated as: Guest
                        </div>
                    </div>
                    <div style="margin-top:16px; border-top:1px dashed #ccc; padding-top:10px; font-size:0.75rem;">
                        <strong>🛠️ JWT Signer Tool:</strong><br>
                        Payload: <input type="text" id="jwtHardPayload" value='{"user":"admin","role":"admin"}' style="width:100%; font-family:monospace; margin-bottom:4px;"><br>
                        Secret Key: <input type="text" id="jwtHardSecret" placeholder="Enter cracked key (123456)..." style="width:100%; font-family:monospace; margin-bottom:8px;"><br>
                        <button class="btn btn-secondary btn-sm" id="jwtHardSignBtn">Sign Token</button>
                        <div id="jwtHardToken" style="font-family:monospace; margin-top:8px; word-break:break-all; color:blue;"></div>
                    </div>
                </div>
            `;
            document.getElementById("jwtHardSignBtn").onclick = () => {
                const p = document.getElementById("jwtHardPayload").value;
                const s = document.getElementById("jwtHardSecret").value;
                const outToken = document.getElementById("jwtHardToken");
                
                if (s === "123456") {
                    const hB64 = btoa('{"alg":"HS256","typ":"JWT"}').replace(/=/g, "");
                    const pB64 = btoa(p).replace(/=/g, "");
                    const signature = btoa("signature_verified").replace(/=/g, "");
                    outToken.innerText = `${hB64}.${pB64}.${signature}`;
                    logConsole("Token signed successfully using key: 123456", "success-line");
                } else {
                    outToken.innerText = "Error: Invalid secret key verification.";
                }
            };
            const checkJwtHardCookie = () => {
                const cookie = currentCookies["session_id"] || "";
                if (cookie.includes("eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ")) {
                    document.getElementById("jwtHardOut").innerHTML = `
                        <span style="color:green;">✓ LOGGED IN AS ADMIN!<br>Flag: [captured flag]</span>
                    `;
                    logConsole("Admin signature authorization passed.", "success-line");
                }
            };
            checkJwtHardCookie();
            break;

        case "ctf-hard-22":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>💻 Node template Console</h2>
                    <p>Enter template text parameters (SSTI):</p>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="sstiIn" placeholder="{{user}}" style="flex-grow:1; font-family:monospace;">
                        <button class="btn btn-primary btn-sm" id="sstiBtn">Render</button>
                    </div>
                    <div id="sstiOut" style="border:1px solid #ccc; padding:12px; background:#222; color:#fff; font-family:monospace;"></div>
                </div>
            `;
            document.getElementById("sstiBtn").onclick = () => {
                const val = document.getElementById("sstiIn").value;
                logProxyRequest("POST", "http://site.local/render", {}, { template: val });
                
                const out = document.getElementById("sstiOut");
                if (val.includes("7*7")) {
                    out.innerText = "Result: 49";
                } else if (val.includes("execSync") && val.includes("flag")) {
                    out.innerHTML = "<span style='color:green;'>Flag: [captured flag]</span>";
                    logConsole("SSTI exploit script execution successful.", "success-line");
                } else {
                    out.innerText = `Welcome, ${val}`;
                }
            };
            break;

        case "ctf-hard-23":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🛡️ Settings Merging Dashboard</h2>
                    <p>Modify parameters: API properties accepts JSON configurations.</p>
                    <textarea id="protoJson" style="width:100%; height:60px; font-family:monospace; margin-bottom:8px;">{\n  "theme": "dark"\n}</textarea>
                    <button class="btn btn-primary btn-sm" id="protoBtn">Update Settings</button>
                    <div id="protoOut" style="margin-top:12px; font-weight:700; color:red;">
                        User role checks failed: guest.
                    </div>
                </div>
            `;
            document.getElementById("protoBtn").onclick = () => {
                const text = document.getElementById("protoJson").value;
                let data = {};
                try {
                    data = JSON.parse(text);
                } catch(e) {
                    document.getElementById("protoOut").innerText = "Invalid JSON schema.";
                    return;
                }
                logProxyRequest("POST", "http://site.local/settings", {}, data);
                
                const out = document.getElementById("protoOut");
                if (text.includes("__proto__") && text.includes("isAdmin")) {
                    out.innerHTML = "<span style='color:green;'>✓ PROTOTYPE POLLUTED! Flag: [captured flag]</span>";
                    logConsole("Global prototype polluted: isAdmin property defined.", "success-line");
                } else {
                    out.innerText = "Settings updated successfully.";
                }
            };
            break;

        case "ctf-hard-24":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>👕 Administration Outfile Shell writer</h2>
                    <p>Perform catalog searches (SQL Injection outfile):</p>
                    <div style="display:flex; gap:8px;">
                        <input type="text" id="sqliOutfileIn" placeholder="Search..." style="flex-grow:1;">
                        <button class="btn btn-primary btn-sm" id="sqliOutfileBtn">Query</button>
                    </div>
                    <div id="sqliOutfileOut" style="margin-top:12px;"></div>
                </div>
            `;
            document.getElementById("sqliOutfileBtn").onclick = () => {
                const val = document.getElementById("sqliOutfileIn").value;
                logProxyRequest("GET", `http://site.local/search?q=${encodeURIComponent(val)}`);
                
                const out = document.getElementById("sqliOutfileOut");
                if (val.toUpperCase().includes("INTO OUTFILE") && val.toUpperCase().includes("uploads/shell.php")) {
                    out.innerHTML = `
                        <div style="background:#e6fffa; border:1px solid green; padding:12px; border-radius:6px;">
                            ✓ Web shell dropped successfully!<br>
                            Execute commands at: <a href="#" id="sqliShellLink" style="color:blue;">/uploads/shell.php?cmd=cat flag.txt</a>
                        </div>
                    `;
                    document.getElementById("sqliShellLink").onclick = () => {
                        viewport.innerHTML = `
                            <div class="viewport-site" style="font-family:monospace; background:#111; color:green; padding:16px;">
                                Flag: [captured flag]
                            </div>
                        `;
                        logConsole("RCE Command execution completed successfully.", "success-line");
                    };
                } else {
                    out.innerText = "Query yielded 0 results.";
                }
            };
            break;

        case "ctf-hard-25":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📡 Loopback SSRF Firewall proxy</h2>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="dnsRebindIn" placeholder="http://target.domain/admin" style="flex-grow:1;">
                        <button class="btn btn-primary btn-sm" id="dnsRebindBtn">Fetch Address</button>
                    </div>
                    <div id="dnsRebindOut" style="font-family:monospace; border:1px solid #ccc; padding:10px;"></div>
                </div>
            `;
            document.getElementById("dnsRebindBtn").onclick = () => {
                const url = document.getElementById("dnsRebindIn").value;
                logProxyRequest("POST", "http://cloud-proxy.local/fetch", {}, { url: url });
                
                const out = document.getElementById("dnsRebindOut");
                if (url.includes("127.0.0.1") || url.includes("localhost")) {
                    out.innerHTML = "<span style='color:red;'>Access Denied: local address loopbacks forbidden.</span>";
                    logConsole("SSRF Blocklist Check: Loopback address detected.", "error-line");
                } else if (url.includes("0.0.0.0") || url.includes("[::]")) {
                    out.innerHTML = "<span style='color:green;'>✓ BYPASS COMPLETE: SSRF Flag: [captured flag]</span>";
                    logConsole("DNS Rebind / local bypass matched.", "success-line");
                } else {
                    out.innerText = "Remote page fetched.";
                }
            };
            break;

        case "ctf-hard-26":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🏁 SSRF Open Redirect Shield</h2>
                    <div style="display:flex; gap:8px; margin-bottom:12px;">
                        <input type="text" id="openRedSSRF" placeholder="URL..." style="flex-grow:1;">
                        <button class="btn btn-primary btn-sm" id="openRedSSRFBtn">Query</button>
                    </div>
                    <div id="openRedSSRFOut" style="font-family:monospace; border:1px solid #ccc; padding:8px;"></div>
                </div>
            `;
            document.getElementById("openRedSSRFBtn").onclick = () => {
                const url = document.getElementById("openRedSSRF").value;
                logProxyRequest("POST", "http://cloud-proxy.local/query", {}, { target: url });
                
                const out = document.getElementById("openRedSSRFOut");
                if (url.includes("169.254.169.254")) {
                    out.innerHTML = "<span style='color:red;'>SSRF Blocked: cloud metadata IP restricted.</span>";
                    logConsole("Metadata block rules matched.", "error-line");
                } else if (url.includes("redirect?url=") && url.includes("169.254.169.254")) {
                    out.innerHTML = `
                        <div style="color:green;">
                            ✓ REDIRECT FOLLOWED TO METADATA!<br>
                            Flag: <strong>[captured flag]</strong>
                        </div>
                    `;
                    logConsole("SSRF Redirect followed successfully.", "success-line");
                } else {
                    out.innerText = "Query completed.";
                }
            };
            break;

        case "ctf-hard-27":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>👛 Logical Wallet double-spend</h2>
                    <div style="border:1px solid #ccc; padding:16px; border-radius:6px; background:#fafafa;">
                        <p>Current Balance: <strong>$10.00</strong></p>
                        <p>Purchase Premium Flag (Cost: $50.00):</p>
                        <button class="btn btn-primary btn-sm" id="raceBuyBtn">Buy Flag</button>
                        <button class="btn btn-accent btn-sm" id="raceSimBtn">Execute Rapid Requests (Race Condition)</button>
                    </div>
                    <div id="raceOut" style="margin-top:12px; font-weight:700; color:red;"></div>
                </div>
            `;
            document.getElementById("raceBuyBtn").onclick = () => {
                logProxyRequest("POST", "http://wallet.local/buy");
                document.getElementById("raceOut").innerText = "Insufficient credit balance. Purchase aborted.";
            };
            document.getElementById("raceSimBtn").onclick = () => {
                logConsole("Simulating 10 concurrent HTTP threads...", "system-line");
                setTimeout(() => {
                    document.getElementById("raceOut").innerHTML = `
                        <span style="color:green;">
                            ✓ CONCURRENCY LIMIT BYPASSED! Wallet Balance: -$40.00.<br>
                            Flag: <strong>[captured flag]</strong>
                        </span>
                    `;
                    logConsole("Race Condition successful! Double-spending verified.", "success-line");
                }, 1000);
            };
            break;

        case "ctf-hard-28":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔒 Password Reset dispatch</h2>
                    <div style="max-width:280px; margin:0 auto; padding:16px; border:1px solid #ccc;">
                        <input type="text" id="hostUser" value="admin" style="width:100%; padding:6px; margin-bottom:8px;">
                        <button class="btn btn-primary btn-sm" id="hostBtn" style="width:100%;">Reset Password</button>
                    </div>
                    <div id="hostOut" style="margin-top:10px; font-weight:700; color:green; text-align:center;"></div>
                </div>
            `;
            document.getElementById("hostBtn").onclick = () => {
                const u = document.getElementById("hostUser").value;
                const headers = parseProxyLogsHeaders();
                const host = headers["host"] || "site.local";
                
                logProxyRequest("POST", "http://site.local/reset-pass", headers, { user: u });
                
                const out = document.getElementById("hostOut");
                if (host.includes("evil-server.local")) {
                    out.innerHTML = `
                        <span style="color:green;">
                            Password Reset link sent to: http://evil-server.local/reset?token=[captured flag]
                        </span>
                    `;
                    logConsole("Host header poisoning: reset link poisoned.", "success-line");
                } else {
                    out.innerText = `Password Reset link generated for Host: ${host}`;
                }
            };
            break;

        case "ctf-hard-29":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>🔑 PHP Type Juggling login</h2>
                    <p>Loose verification checks: <code>md5($pass) == '0e382710182...'</code></p>
                    <div style="max-width:280px; margin:0 auto; padding:16px; border:1px solid #ccc;">
                        <input type="password" id="phpJugPass" placeholder="Magic Password..." style="width:100%; padding:6px; margin-bottom:8px;">
                        <button class="btn btn-primary btn-sm" id="phpJugBtn" style="width:100%;">Submit</button>
                    </div>
                    <div id="phpJugOut" style="margin-top:10px; font-weight:700; color:red; text-align:center;"></div>
                </div>
            `;
            document.getElementById("phpJugBtn").onclick = () => {
                const pass = document.getElementById("phpJugPass").value;
                logProxyRequest("POST", "http://site.local/login-loose", {}, { pass: pass });
                
                const out = document.getElementById("phpJugOut");
                if (pass === "240610708") {
                    out.innerHTML = "<span style='color:green;'>Flag: [captured flag]</span>";
                    logConsole("Loose comparisons check passed: 0e hash match.", "success-line");
                } else {
                    out.innerText = "Error: Invalid credentials.";
                }
            };
            break;

        case "ctf-hard-30":
            viewport.innerHTML = `
                <div class="viewport-site">
                    <h2>📊 GraphQL Playground API Console</h2>
                    <textarea id="gqlQuery" style="width:100%; height:100px; font-family:monospace; margin-bottom:8px;">{\n  users {\n    id\n    name\n  }\n}</textarea>
                    <button class="btn btn-primary btn-sm" id="gqlBtn">Execute Query</button>
                    <div id="gqlOut" style="margin-top:12px; font-family:monospace; font-size:0.75rem; background:#222; color:#fff; padding:10px; max-height:150px; overflow-y:auto;"></div>
                </div>
            `;
            document.getElementById("gqlBtn").onclick = () => {
                const q = document.getElementById("gqlQuery").value;
                logProxyRequest("POST", "http://api.local/graphql", {}, { query: q });
                
                const out = document.getElementById("gqlOut");
                if (q.includes("__schema") || q.includes("introspection")) {
                    out.innerText = `{\n  "__schema": {\n    "mutationType": {\n      "fields": [\n        {"name": "getSecretFlag", "args": [{"name": "token"}]}\n      ]\n    }\n  }\n}`;
                    logConsole("Introspection query parsed.", "success-line");
                } else if (q.includes("getSecretFlag") && q.includes("admin_token")) {
                    out.innerHTML = `{\n  "data": {\n    "getSecretFlag": "[captured flag]"\n  }\n}`;
                    logConsole("Mutation command parsed successfully.", "success-line");
                } else {
                    out.innerText = `{\n  "data": {\n    "users": [\n      {"id": 105, "name": "guest"}\n    ]\n  }\n}`;
                }
            };
            break;

        default:
            viewport.innerHTML = `
                <div class="viewport-site" style="text-align:center; padding-top:40px;">
                    <h3>🤖 Sandbox Environment Active</h3>
                    <p>Ready to capture targets. Audit inputs and submit credentials.</p>
                </div>
            `;
            break;
    }
}

// Simulated URL bar route triggers
function loadAdminPanelPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="border: 1px solid red; padding: 24px; background:#fef2f2;">
            <h2 style="color:red;">🛠️ Administrator Configuration Panel</h2>
            <p>Access control check complete. Privileges escalation successful!</p>
            <button class="btn btn-accent btn-sm" id="bacBasicClaim">Claim Achievement</button>
        </div>
    `;
    document.getElementById("bacBasicClaim").onclick = () => {
        markSandboxSolved("bac-hidden", 100, "Expose Hidden Admin Route");
    };
}

function loadIdorAdminPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="border:1px solid green; padding:20px; background:#f0fdf4;">
            <h3>👤 User Account: Administrator</h3>
            <p>Email: admin@securecorp.local</p>
            <p>Secret Flag Token: <strong>[captured flag]</strong></p>
        </div>
    `;
    markSandboxSolved("idor-basic", 100, "Profile Identifier Tampering");
}

function loadIdorInvoicePage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="border:1px solid green; padding:20px; background:#f0fdf4;">
            <h3>🧾 Invoice #2048 - Confidential</h3>
            <p>Customer: Private Client Corp</p>
            <p>System Flag Token: <strong>[captured flag]</strong></p>
        </div>
    `;
    markSandboxSolved("idor-invoice", 200, "Unauthorized Invoice Access");
}

function loadIdorCtfPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; background:#222; color:#10b981; padding:16px;">
            {<br>
            &nbsp;&nbsp;"status": "success",<br>
            &nbsp;&nbsp;"userId": 1001,<br>
            &nbsp;&nbsp;"username": "administrator_db",<br>
            &nbsp;&nbsp;"flag": "[captured flag]"<br>
            }
        </div>
    `;
}

function loadTraversalPasswdPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; background:#333; color:#fff; padding:16px; white-space:pre-wrap;">root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nflag:x:1001:1001:[captured flag]:/home/flag:/bin/bash</div>
    `;
    if (activeSandboxId === "traversal-basic") markSandboxSolved("traversal-basic", 100, "Basic Path Traversal");
    if (activeSandboxId === "traversal-filter") markSandboxSolved("traversal-filter", 200, "Filter Strip Traversal");
}

function loadTraversalSettingsPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; background:#333; color:#38bdf8; padding:16px; white-space:pre-wrap;"># Database Settings\ndb_host: localhost\ndb_user: cnf_admin\ndb_pass: super_secret_pass_2026\nsystem_flag: [captured flag]</div>
    `;
    markSandboxSolved("traversal-sensitive", 300, "Config File Discovery");
}

function loadTraversalCtfPage() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; background:#111; color:green; padding:16px;">
            Flag Captured: [captured flag]
        </div>
    `;
}

function loadRobotsTxt() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; white-space:pre-wrap;">User-agent: *\nDisallow: /admin\nDisallow: /backup-credentials</div>
    `;
}

function loadBackupCredentials() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="border: 1px solid green; padding:16px; background:#e6fffa;">
            <h3>🛠️ Development Backups Index</h3>
            <p>System configuration credentials token: <strong>[captured flag]</strong></p>
        </div>
    `;
    markSandboxSolved("misconfig-robots", 100, "Robots.txt Directory Leak");
}

function loadGitConfig() {
    const viewport = document.getElementById("browserViewport");
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; background:#222; color:#fff; padding:16px; white-space:pre-wrap;">[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote "origin"]\n\turl = https://git-repo.local/development/project.git\n[credential]\n\ttoken = [captured flag]</div>
    `;
    if (activeSandboxId === "misconfig-git") markSandboxSolved("misconfig-git", 300, "Git Repository Exposure");
}

// CTF easy paths helper
function loadCtfRobotsTxt() {
    document.getElementById("browserViewport").innerHTML = `<pre>User-agent: *\nDisallow: /secret-stash/flag.txt</pre>`;
}
function loadCtfSecretStash() {
    document.getElementById("browserViewport").innerHTML = `<h3>Captured: [captured flag]</h3>`;
}

// Simulated Web Terminal / shell workspace
let shellHistory = [];
function loadWebShellWorkspace(isCtf = false) {
    const viewport = document.getElementById("browserViewport");
    viewport.style.backgroundColor = "#080c14";
    viewport.style.color = "#10b981";
    viewport.innerHTML = `
        <div class="viewport-site" style="font-family:monospace; padding:12px; height:100%; display:flex; flex-direction:column; justify-content:space-between; color:#10B981;">
            <div>
                <div style="border-bottom:1px solid #222; padding-bottom:8px; margin-bottom:12px; color:#64748b;">
                    🔒 SIMULATED LINUX WEB-SHELL (Vulnerable Upload host)
                </div>
                <div id="shellOutput" style="font-size:0.8rem; display:flex; flex-direction:column; gap:4px; max-height:160px; overflow-y:auto; margin-bottom:12px;">
                    <div>Welcome to interactive RCE backdoor console. Type commands.</div>
                </div>
            </div>
            <div style="display:flex; gap:8px;">
                <span>$</span>
                <input type="text" id="shellCmdIn" style="flex-grow:1; background:transparent; border:none; color:#10B981; font-family:monospace; font-size:0.8rem; outline:none;" placeholder="ls, cat..." autofocus>
            </div>
        </div>
    `;

    const cmdIn = document.getElementById("shellCmdIn");
    const outBox = document.getElementById("shellOutput");

    cmdIn.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const cmd = cmdIn.value.trim();
            if (!cmd) return;

            cmdIn.value = "";
            const line = document.createElement("div");
            line.innerHTML = `<span style="color:#64748b;">$ ${cmd}</span>`;
            outBox.appendChild(line);

            const res = document.createElement("div");
            
            if (cmd === "ls") {
                res.innerText = "assets  config  flag.txt  index.php  uploads";
            } else if (cmd === "cat flag.txt" || cmd === "cat /var/www/flag.txt") {
                if (isCtf) {
                    res.innerHTML = "<strong>Flag: [captured flag]</strong>";
                } else {
                    res.innerHTML = "<strong>Flag: [captured flag]</strong>";
                    markSandboxSolved("upload-shell", 300, "Web Shell RCE Execution");
                }
            } else if (cmd.startsWith("cat ")) {
                res.innerText = "cat: permission denied or file not found.";
            } else if (cmd === "whoami") {
                res.innerText = "www-data";
            } else if (cmd === "id") {
                res.innerText = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
            } else {
                res.innerText = `bash: command not found: ${cmd.split(" ")[0]}`;
            }

            outBox.appendChild(res);
            outBox.scrollTop = outBox.scrollHeight;
        }
    });
}

// Simulated Browser alerts
function alertSimulated(message) {
    // Renders a beautiful cyber alert pop-up inside the browser view
    const view = document.getElementById("browserViewport");
    const div = document.createElement("div");
    div.style.cssText = "position:absolute; top:20px; left:50%; transform:translateX(-50%); background:rgba(8,12,20,0.95); border:1px solid #8b5cf6; padding:16px; border-radius:8px; box-shadow:0 0 20px rgba(139,92,246,0.3); z-index:10000; text-align:center; min-width:240px; animation: fadeIn 0.3s;";
    div.innerHTML = `
        <h4 style="color:#8b5cf6; margin-bottom:8px;">⚠️ Simulated Browser Alert</h4>
        <p style="font-size:0.85rem; color:#fff; margin-bottom:12px;">${message}</p>
        <button class="btn btn-primary btn-sm" id="simAlertClose" style="padding:4px 12px; font-size:0.75rem;">OK</button>
    `;
    view.appendChild(div);
    document.getElementById("simAlertClose").onclick = () => div.remove();
}

// ==========================================
// 8. Progress System & Badges List
// ==========================================

function checkBadges() {
    // Define unlocks
    const badgesToUnlock = [];

    // First Blood
    if (userState.solvedLabs.length >= 1) badgesToUnlock.push("first-blood");

    // Check categories
    const isCategorySolved = (prefix) => {
        const list = VULNERABILITIES.find(v => v.id === prefix).labs.map(l => l.id);
        return list.every(id => userState.solvedLabs.includes(id));
    };

    if (isCategorySolved("xss")) badgesToUnlock.push("script-kiddie");
    if (isCategorySolved("sqli")) badgesToUnlock.push("sql-maestro");
    if (isCategorySolved("bac")) badgesToUnlock.push("gatekeeper-bypass");
    if (isCategorySolved("idor")) badgesToUnlock.push("idor-miner");
    if (isCategorySolved("csrf")) badgesToUnlock.push("csrf-ninja");
    if (isCategorySolved("upload")) badgesToUnlock.push("shell-operator");
    if (isCategorySolved("traversal")) badgesToUnlock.push("path-finder");
    if (isCategorySolved("auth")) badgesToUnlock.push("brute-forcer");
    if (isCategorySolved("ssrf")) badgesToUnlock.push("ssrf-agent");
    if (isCategorySolved("misconfig")) badgesToUnlock.push("system-auditor");

    // CTF Hunter (10 CTFs)
    if (userState.solvedCtfs.length >= 10) badgesToUnlock.push("ctf-hunter");

    // Update unlocked list
    let badgeAdded = false;
    badgesToUnlock.forEach(bid => {
        if (!userState.unlockedBadges.includes(bid)) {
            userState.unlockedBadges.push(bid);
            badgeAdded = true;
            const b = ACHIEVEMENTS.find(ac => ac.id === bid);
            if (b) showToast(`🏆 ACHIEVEMENT UNLOCKED: ${b.title}!`, "success");
        }
    });

    if (badgeAdded) saveState();
}

function renderProgressPage() {
    // Compute total metrics
    document.getElementById("unlockedBadgesCount").innerText = userState.unlockedBadges.length;

    // Skills Matrix
    const list = document.getElementById("skillsList");
    list.innerHTML = "";

    VULNERABILITIES.forEach(v => {
        const solved = v.labs.filter(l => userState.solvedLabs.includes(l.id)).length;
        const pct = Math.floor((solved / v.labs.length) * 100);

        list.innerHTML += `
            <div class="skill-row">
                <div class="skill-meta">
                    <span class="skill-name">${v.title.split(" ")[0]}</span>
                    <span class="skill-percent">${pct}%</span>
                </div>
                <div class="skill-bar-outer">
                    <div class="skill-bar-inner" style="width: ${pct}%"></div>
                </div>
            </div>
        `;
    });

    // Badges Grid
    const grid = document.getElementById("badgesGrid");
    grid.innerHTML = "";

    ACHIEVEMENTS.forEach(ac => {
        const isUnlocked = userState.unlockedBadges.includes(ac.id);
        const card = document.createElement("div");
        card.className = `badge-card ${isUnlocked ? '' : 'locked'}`;

        card.innerHTML = `
            <div class="badge-icon-large">${isUnlocked ? ac.icon : '🔒'}</div>
            <h4 class="badge-title">${ac.title}</h4>
            <p class="badge-desc">${ac.desc}</p>
        `;
        grid.appendChild(card);
    });
}

// ==========================================
// 9. Dashboard Overview Rendering
// ==========================================

function renderDashboard() {
    const totalLabsSolved = userState.solvedLabs.length;
    const totalCtfsSolved = userState.solvedCtfs.length;
    const badgeCount = userState.unlockedBadges.length;

    document.getElementById("dashLabsCount").innerText = `${totalLabsSolved} / 30`;
    document.getElementById("dashLabsProgress").innerText = `${Math.floor((totalLabsSolved / 30) * 100)}% Completed`;

    document.getElementById("dashCtfCount").innerText = `${totalCtfsSolved} / 30`;
    document.getElementById("dashCtfProgress").innerText = `${Math.floor((totalCtfsSolved / 30) * 100)}% Solved`;

    document.getElementById("dashBadgeCount").innerText = `${badgeCount} Badges`;
    
    const lastBadge = userState.unlockedBadges[userState.unlockedBadges.length - 1];
    if (lastBadge) {
        const b = ACHIEVEMENTS.find(a => a.id === lastBadge);
        document.getElementById("dashLastBadge").innerText = `Last: ${b.title}`;
    } else {
        document.getElementById("dashLastBadge").innerText = "None unlocked yet";
    }

    // Roadmap list
    const tree = document.getElementById("roadmapTree");
    tree.innerHTML = "";

    VULNERABILITIES.forEach((v, idx) => {
        const solved = v.labs.filter(l => userState.solvedLabs.includes(l.id)).length;
        const pct = Math.floor((solved / v.labs.length) * 100);

        const row = document.createElement("div");
        row.className = "roadmap-step";
        row.onclick = () => {
            switchTab("learn");
            selectVulnerability(idx);
        };

        row.innerHTML = `
            <div class="step-info">
                <span class="step-number">${String(idx + 1).padStart(2, '0')}</span>
                <div class="step-name-area">
                    <span class="step-title">${v.title}</span>
                    <span class="step-desc">${v.category} • ${solved}/3 labs mastered</span>
                </div>
            </div>
            <div class="step-status">
                <div class="completion-microbar">
                    <div class="completion-microbar-inner" style="width: ${pct}%"></div>
                </div>
                <span class="status-badge-icon">${pct === 100 ? '🏁' : '🔬'}</span>
            </div>
        `;
        tree.appendChild(row);
    });

    // Recent Achievements preview
    const dashAc = document.getElementById("dashboardAchievements");
    dashAc.innerHTML = "";

    const previewAchievements = ACHIEVEMENTS.slice(0, 3);
    previewAchievements.forEach(ac => {
        const unlocked = userState.unlockedBadges.includes(ac.id);
        dashAc.innerHTML += `
            <div class="achievement-preview-item ${unlocked ? '' : 'locked'}">
                <span class="badge-mini-icon">${unlocked ? ac.icon : '🔒'}</span>
                <div class="badge-preview-meta">
                    <span class="badge-preview-title">${ac.title}</span>
                    <span class="badge-preview-desc">${ac.desc}</span>
                </div>
            </div>
        `;
    });
}

// ==========================================
// 10. Global UI Header Stats & Search
// ==========================================

function updateUI() {
    // Top header indicators
    document.getElementById("headerXp").innerText = `${userState.xp} XP`;
    document.getElementById("headerLabs").innerText = `${userState.solvedLabs.length}/30 Labs`;
    document.getElementById("headerCtfs").innerText = `${userState.solvedCtfs.length}/30 CTF`;

    // Sidebar avatar
    document.getElementById("usernameDisplay").innerText = userState.username;
    document.getElementById("avatarImage").innerText = userState.avatar;

    // View specific updates
    renderDashboard();
    renderProgressPage();
}

// Toast Messages System
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-message">${message}</span>
        <button class="toast-close">&times;</button>
    `;
    container.appendChild(toast);

    toast.querySelector(".toast-close").onclick = () => toast.remove();

    // Auto remove
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// Search utility
document.getElementById("vulnSearch").addEventListener("input", (e) => {
    const val = e.target.value.toLowerCase().trim();
    if (!val) {
        renderVulnerabilities();
        renderCtfArena();
        return;
    }

    // Filter Navigation sidebar matches
    const listMenu = document.getElementById("vulnListMenu");
    listMenu.innerHTML = "";

    VULNERABILITIES.forEach((v, idx) => {
        if (v.title.toLowerCase().includes(val) || v.category.toLowerCase().includes(val)) {
            const li = document.createElement("li");
            li.innerHTML = `
                <button class="vuln-item-btn" onclick="switchTab('learn'); selectVulnerability(${idx})">
                    <span class="vuln-item-title">${v.title.split(" ")[0]} ${v.title.split(" ").slice(1).join(" ")}</span>
                    <span class="vuln-item-dots">⚡</span>
                </button>
            `;
            listMenu.appendChild(li);
        }
    });

    // Filter CTF Arena cards
    const ctfGrid = document.getElementById("ctfGrid");
    ctfGrid.innerHTML = "";

    CTF_CHALLENGES.forEach(c => {
        if (c.title.toLowerCase().includes(val) || c.category.toLowerCase().includes(val) || c.desc.toLowerCase().includes(val)) {
            const isSolved = userState.solvedCtfs.includes(c.id);
            const card = document.createElement("div");
            card.className = `ctf-challenge-card ${isSolved ? 'solved' : ''}`;
            card.onclick = () => launchSandbox(c.id, true);
            card.innerHTML = `
                <div class="challenge-top">
                    <span class="challenge-cat">${c.category}</span>
                    <h4 class="challenge-title">${c.title}</h4>
                    <p class="challenge-desc">${c.desc}</p>
                </div>
                <div class="challenge-bottom">
                    <span class="challenge-diff ${c.difficulty.toLowerCase()}">${c.difficulty}</span>
                    <span class="challenge-xp">${c.xp} XP</span>
                </div>
            `;
            ctfGrid.appendChild(card);
        }
    });
});

// ==========================================
// 11. Profile Settings Modals
// ==========================================

const profileModal = document.getElementById("editProfileModal");
const editNameBtn = document.getElementById("editNameBtn");
const closeProfileBtn = document.getElementById("closeProfileModalBtn");
const saveProfileBtn = document.getElementById("saveProfileBtn");
const usernameInput = document.getElementById("editUsernameInput");
const avatarGrid = document.getElementById("avatarSelectGrid");

let selectedAvatar = "⚡";

editNameBtn.onclick = () => {
    usernameInput.value = userState.username;
    selectedAvatar = userState.avatar;
    
    // Select avatar active class
    document.querySelectorAll(".avatar-option").forEach(opt => {
        if (opt.innerText === selectedAvatar) {
            opt.classList.add("selected");
        } else {
            opt.classList.remove("selected");
        }
    });

    profileModal.classList.add("active");
};

closeProfileBtn.onclick = () => profileModal.classList.remove("active");

document.querySelectorAll(".avatar-option").forEach(opt => {
    opt.onclick = (e) => {
        document.querySelectorAll(".avatar-option").forEach(o => o.classList.remove("selected"));
        e.target.classList.add("selected");
        selectedAvatar = e.target.innerText;
    };
});

saveProfileBtn.onclick = () => {
    const newName = usernameInput.value.trim();
    if (newName) {
        userState.username = newName;
        userState.avatar = selectedAvatar;
        saveState();
        profileModal.classList.remove("active");
        showToast("Profile settings saved successfully.", "success");
    }
};

// ==========================================
// 12. Theme Management (Light / Dark)
// ==========================================

const themeBtn = document.getElementById("themeToggleBtn");
themeBtn.onclick = () => {
    const currentTheme = document.body.getAttribute("data-theme") || "dark";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    document.body.setAttribute("data-theme", nextTheme);
    localStorage.setItem("sp_theme", nextTheme);
    showToast(`Switched to ${nextTheme} theme mode`, "info");
};

// Set initial theme
const savedTheme = localStorage.getItem("sp_theme") || "dark";
document.body.setAttribute("data-theme", savedTheme);

// ==========================================
// 13. Initialization Bootstrapper
// ==========================================

window.onload = () => {
    loadState();
    renderVulnerabilities();
    renderCtfArena();

    // Set navigation buttons listeners
    document.querySelectorAll(".nav-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.getAttribute("data-target");
            switchTab(target);
        });
    });

    // Set vulnerability tabs listeners
    document.querySelectorAll(".vuln-tab").forEach(tab => {
        tab.addEventListener("click", (e) => {
            document.querySelectorAll(".vuln-tab").forEach(t => t.classList.remove("active"));
            e.target.classList.add("active");

            document.querySelectorAll(".vuln-tab-content").forEach(c => c.classList.remove("active"));
            const targetId = `tab-${e.target.getAttribute("data-tab")}`;
            const targetContent = document.getElementById(targetId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
};
