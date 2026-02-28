// ═══════════════════════════════════════════════════════════
//  MachoAuth Backend  ·  server.js
//  Deploy to Railway / Render / any VPS
//  Commands: npm install    then    npm start
// ═══════════════════════════════════════════════════════════

const express = require("express");
const cors    = require("cors");
const fs      = require("fs");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;
const DB   = path.join(__dirname, "keys.json");

// ── Config (set these as Environment Variables on Railway/Render)
const HEARTBEAT_HOURS = 12;
const ADMIN_SECRET    = process.env.ADMIN_SECRET  || "change_me_in_env";
const TELEMETRY_ID    = process.env.TELEMETRY_ID  || "";
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK || "";

app.use(cors());
app.use(express.json());

// ── Logging middleware
app.use((req, res, next) => {
    const time = new Date().toISOString();
    console.log(`[${time}] ${req.method} ${req.path} | IP: ${req.ip}`);
    next();
});

// ── DB helpers
function readDB() {
    try {
        if (!fs.existsSync(DB)) fs.writeFileSync(DB, "{}");
        return JSON.parse(fs.readFileSync(DB, "utf8"));
    } catch (e) {
        console.error("DB read error:", e.message);
        return {};
    }
}
function writeDB(data) {
    try {
        fs.writeFileSync(DB, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error("DB write error:", e.message);
    }
}

// ── Discord webhook notify (optional)
async function discordNotify(content) {
    if (!DISCORD_WEBHOOK) return;
    try {
        await fetch(DISCORD_WEBHOOK, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content }),
        });
    } catch (e) {
        console.error("Discord webhook error:", e.message);
    }
}

// ── Expiry check
function isExpired(entry) {
    if (!entry.activatedAt) return false;
    if ((entry.durationDays || 0) >= 10000000) return false; // lifetime
    return Date.now() > (entry.expiresAt || 0);
}

// ════════════════════════════════════════════════════════════
//  ENDPOINT 1 — AUTHENTICATE
//  GET /api/authenticate?key=MACHO_AUTH_KEY
//
//  Returns:
//    { status: "success", expires_at: "2025-03-15T12:00:00Z", duration_days: 30 }
//    { status: "error",   message: "Invalid or expired key." }
// ════════════════════════════════════════════════════════════
app.get("/api/authenticate", (req, res) => {
    const { key } = req.query;

    if (!key) {
        return res.json({ status: "error", message: "No key provided." });
    }

    const db = readDB();

    // Find by authKey (Macho Auth Key bound at redemption)
    const productKey = Object.keys(db).find(k =>
        db[k].authKey === key && db[k].status === "active"
    );

    if (!productKey) {
        console.log(`[AUTH] DENIED — key not found: ${key.slice(0, 12)}...`);
        return res.json({ status: "error", message: "Invalid or expired key." });
    }

    const entry = db[productKey];

    // Check expiry
    if (isExpired(entry)) {
        db[productKey].status = "expired";
        writeDB(db);
        console.log(`[AUTH] EXPIRED — product key: ${productKey}`);
        return res.json({ status: "error", message: "Key has expired." });
    }

    const expiresDisplay = (entry.durationDays || 0) >= 10000000
        ? "lifetime"
        : new Date(entry.expiresAt).toISOString();

    console.log(`[AUTH] SUCCESS — product key: ${productKey} | discord: ${entry.discord || "none"}`);

    return res.json({
        status:       "success",
        expires_at:   expiresDisplay,
        duration_days: entry.durationDays || 0,
        discord:      entry.discord || null,
    });
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 2 — HEARTBEAT  (+12h extension on every load)
//  GET /api/heartbeat?key=MACHO_AUTH_KEY&ip=SERVER_IP
// ════════════════════════════════════════════════════════════
app.get("/api/heartbeat", (req, res) => {
    const { key, ip } = req.query;

    if (!key) return res.json({ status: "error", message: "No key." });

    const db = readDB();
    const productKey = Object.keys(db).find(k =>
        db[k].authKey === key && db[k].status === "active"
    );

    if (!productKey) {
        return res.json({ status: "error", message: "Key not found." });
    }

    const entry = db[productKey];

    // Don't extend lifetime keys
    if ((entry.durationDays || 0) < 10000000) {
        const baseTime  = Math.max(entry.expiresAt || Date.now(), Date.now());
        entry.expiresAt = baseTime + (HEARTBEAT_HOURS * 3600000);
        entry.lastSeen  = Date.now();
        entry.lastIp    = ip || "unknown";
        writeDB(db);
        console.log(`[HEARTBEAT] Extended +${HEARTBEAT_HOURS}h — key: ${productKey} | ip: ${ip}`);
    }

    return res.json({ status: "ok", extended_by_hours: HEARTBEAT_HOURS });
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 3 — TELEMETRY  (session logging + Discord ping)
//  GET /api/telemetry?telemetry_id=X&macho_key=Y&ip=Z
// ════════════════════════════════════════════════════════════
app.get("/api/telemetry", (req, res) => {
    const { telemetry_id, macho_key, ip } = req.query;

    if (TELEMETRY_ID && telemetry_id !== TELEMETRY_ID) {
        return res.json({ status: "error", message: "Invalid telemetry ID." });
    }

    const time = new Date().toISOString();
    console.log(`[TELEMETRY] key=${(macho_key||"").slice(0,12)}... ip=${ip} time=${time}`);

    // Optional Discord notification
    discordNotify(
        `📡 **New Session**\n` +
        `> Key: \`${(macho_key||"unknown").slice(0, 16)}...\`\n` +
        `> IP: \`${ip || "unknown"}\`\n` +
        `> Time: \`${time}\``
    );

    return res.json({ status: "ok" });
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 4 — RAW WHITELIST  (plain text, one auth key per line)
//  GET /api/keys/raw
// ════════════════════════════════════════════════════════════
app.get("/api/keys/raw", (req, res) => {
    const db = readDB();
    const active = Object.values(db)
        .filter(k => k.status === "active" && k.authKey && !isExpired(k))
        .map(k => k.authKey)
        .join("\n");

    res.setHeader("Content-Type", "text/plain");
    res.send(active || "");
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 5 — ADMIN SYNC  (push full key DB from dashboard)
//  POST /api/admin/sync
//  Headers: x-admin-secret: YOUR_ADMIN_SECRET
//  Body: { "keys": { ...full keys object... } }
// ════════════════════════════════════════════════════════════
app.post("/api/admin/sync", (req, res) => {
    const secret = req.headers["x-admin-secret"];

    if (secret !== ADMIN_SECRET) {
        console.warn(`[SYNC] Unauthorized attempt from IP: ${req.ip}`);
        return res.status(403).json({ status: "error", message: "Unauthorized." });
    }

    const { keys } = req.body;
    if (!keys || typeof keys !== "object") {
        return res.status(400).json({ status: "error", message: "Invalid payload — expected { keys: {...} }" });
    }

    writeDB(keys);
    const count = Object.keys(keys).length;
    console.log(`[SYNC] ${count} keys synced from dashboard`);

    return res.json({ status: "ok", count });
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 6 — ADMIN GET KEYS  (read DB from dashboard)
//  GET /api/admin/keys
//  Headers: x-admin-secret: YOUR_ADMIN_SECRET
// ════════════════════════════════════════════════════════════
app.get("/api/admin/keys", (req, res) => {
    const secret = req.headers["x-admin-secret"];

    if (secret !== ADMIN_SECRET) {
        return res.status(403).json({ status: "error", message: "Unauthorized." });
    }

    return res.json(readDB());
});

// ════════════════════════════════════════════════════════════
//  ENDPOINT 7 — HEALTH CHECK  (ping to keep server awake)
//  GET /api/health
// ════════════════════════════════════════════════════════════
app.get("/api/health", (req, res) => {
    const db    = readDB();
    const total = Object.keys(db).length;
    const active = Object.values(db).filter(k => k.status === "active" && !isExpired(k)).length;
    return res.json({
        status:    "online",
        timestamp: new Date().toISOString(),
        keys:      { total, active }
    });
});

// ── Root
app.get("/", (req, res) => {
    res.send("MachoAuth API is running. Endpoints: /api/authenticate /api/heartbeat /api/telemetry /api/keys/raw");
});

// ── 404
app.use((req, res) => {
    res.status(404).json({ status: "error", message: "Endpoint not found." });
});

// ── Start server
app.listen(PORT, () => {
    console.log("════════════════════════════════════════");
    console.log(`  MachoAuth API running on port ${PORT}`);
    console.log("════════════════════════════════════════");
    console.log(`  GET  /api/authenticate?key=X`);
    console.log(`  GET  /api/heartbeat?key=X&ip=Y`);
    console.log(`  GET  /api/telemetry?telemetry_id=X&macho_key=Y&ip=Z`);
    console.log(`  GET  /api/keys/raw`);
    console.log(`  POST /api/admin/sync`);
    console.log(`  GET  /api/admin/keys`);
    console.log(`  GET  /api/health`);
    console.log("════════════════════════════════════════");
});
