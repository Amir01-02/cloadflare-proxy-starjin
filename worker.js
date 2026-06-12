// ==StarJin Proxy - Complete Rewrite==
// Version: 2026-06-13
// Original: NovaProxy
// ==/StarJin Proxy==

const VERSION = "2026-06-13 18:00:00";

// ========== Subscription Plans ==========
const SUBSCRIPTION_PLANS = {
    "FREE_1G_DAILY": {
        name: "رایگان ۱ گیگ",
        data_limit_mb: 1024,
        duration_hours: 24,
        priority: 1
    },
    "FREE_5G_WEEKLY": {
        name: "رایگان ۵ گیگ",
        data_limit_mb: 5120,
        duration_hours: 168,
        priority: 2
    },
    "FREE_30G_MONTHLY": {
        name: "رایگان ۳۰ گیگ",
        data_limit_mb: 30720,
        duration_hours: 720,
        priority: 3
    },
    "UNLIMITED": {
        name: "نامحدود ویژه",
        data_limit_mb: -1,
        duration_hours: 720,
        priority: 4
    }
};

// ========== Global State ==========
let configJSON = null;
let proxyIP = "";
let socks5Enabled = null;
let socks5Global = false;
let socks5Account = "";
let parsedSocks5 = {};
let cachedWhitelist = null;
let cachedProxyIP = null;
let cachedProxyArray = null;
let cachedProxyIndex = 0;
let fallbackEnabled = true;
let debugMode = false;
let whitelistDomains = [
    "*tapecontent.net",
    "*cloudatacdn.com",
    "*loadshare.org",
    "*cdn-centaurus.com",
    "scholar.google.com"
];

const STATIC_URL = "https://starjin-panel.github.io/";
const WS_EARLY_MAX = 8192;
const WS_EARLY_HEADER_MAX = Math.ceil((WS_EARLY_MAX * 4) / 3) + 4;
const BUNDLE_TARGET = 16384;
const QUEUE_MAX_BYTES = 16777216;
const QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN = 32768;
const DOWNSTREAM_THRESHOLD = 512;
const DOWNSTREAM_SILENT_MS = 0;
const TCP_CONCURRENT = 2;

globalThis.__workerStart = Date.now();

// ========== Utility Functions ==========
function arrayToUint8(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || 0);
}

function concatBuffers(...buffers) {
    if (!buffers || buffers.length === 0) return new Uint8Array(0);
    const views = buffers.map(arrayToUint8);
    const total = views.reduce((sum, v) => sum + v.byteLength, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const v of views) {
        result.set(v, offset);
        offset += v.byteLength;
    }
    return result;
}

function log(...args) {
    if (debugMode) console.log("[StarJin]", ...args);
}

function maskString(str, prefix = 3, suffix = 2) {
    if (!str || typeof str !== "string") return str;
    if (str.length <= prefix + suffix) return str;
    return str.slice(0, prefix) + "*".repeat(str.length - prefix - suffix) + str.slice(-suffix);
}

function randomPath(base = "/") {
    const segments = [
        "api", "v1", "v2", "v3", "ws", "wss", "cdn", "static", "assets",
        "data", "json", "xml", "upload", "download", "stream", "live",
        "media", "video", "audio", "image", "files", "docs", "public",
        "private", "auth", "login", "logout", "register", "user", "users",
        "admin", "dashboard", "panel", "stats", "status", "health", "ping"
    ];
    const count = Math.floor(Math.random() * 3) + 1;
    const shuffled = [...segments].sort(() => 0.5 - Math.random());
    const path = shuffled.slice(0, count).join("/");
    if (base === "/") return "/" + path;
    return "/" + path + base;
}

function randomChars(str) {
    if (typeof str !== "string" || !str.includes("*")) return str;
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return str.replace(/\*/g, () => {
        let result = "";
        const len = Math.floor(Math.random() * 12) + 4;
        for (let i = 0; i < len; i++) {
            result += chars[Math.floor(Math.random() * chars.length)];
        }
        return result;
    });
}

// ========== MD5 Hash ==========
// Cloudflare Workers' WebCrypto does NOT support "MD5" (only SHA-1/256/384/512),
// so crypto.subtle.digest("MD5", ...) throws at runtime. Implemented in pure JS.
function md5Core(messageBytes) {
    function rotl(x, c) { return (x << c) | (x >>> (32 - c)); }
    const s = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    ];
    const K = new Int32Array([
        -680876936,-389564586,606105819,-1044525330,-176418897,1200080426,-1473231341,-45705983,
        1770035416,-1958414417,-42063,-1990404162,1804603682,-40341101,-1502002290,1236535329,
        -165796510,-1069501632,643717713,-373897302,-701558691,38016083,-660478335,-405537848,
        568446438,-1019803690,-187363961,1163531501,-1444681467,-51403784,1735328473,-1926607734,
        -378558,-2022574463,1839030562,-35309556,-1530992060,1272893353,-155497632,-1094730640,
        681279174,-358537222,-722521979,76029189,-640364487,-421815835,530742520,-995338651,
        -198630844,1126891415,-1416354905,-57434055,1700485571,-1894986606,-1051523,-2054922799,
        1873313359,-30611744,-1560198380,1309151649,-145523070,-1120210379,718787259,-343485551
    ]);

    const msgLen = messageBytes.length;
    const bitLen = msgLen * 8;
    const padLen = (msgLen % 64 < 56) ? (56 - (msgLen % 64)) : (120 - (msgLen % 64));
    const total = msgLen + padLen + 8;
    const buf = new Uint8Array(total);
    buf.set(messageBytes, 0);
    buf[msgLen] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, bitLen >>> 0, true);
    dv.setUint32(total - 4, Math.floor(bitLen / 0x100000000) >>> 0, true);

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    for (let chunk = 0; chunk < total; chunk += 64) {
        const M = new Int32Array(16);
        for (let i = 0; i < 16; i++) M[i] = dv.getInt32(chunk + i * 4, true);

        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F, g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * i) % 16; }
            F = (F + A + K[i] + M[g]) | 0;
            A = D; D = C; C = B;
            B = (B + rotl(F, s[i])) | 0;
        }
        a0 = (a0 + A) | 0;
        b0 = (b0 + B) | 0;
        c0 = (c0 + C) | 0;
        d0 = (d0 + D) | 0;
    }

    const out = new Uint8Array(16);
    const outDv = new DataView(out.buffer);
    outDv.setInt32(0, a0, true);
    outDv.setInt32(4, b0, true);
    outDv.setInt32(8, c0, true);
    outDv.setInt32(12, d0, true);
    return out;
}

async function md5Hash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const bytes = md5Core(data);
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
        result += bytes[i].toString(16).padStart(2, "0");
    }
    const secondBytes = md5Core(encoder.encode(result.slice(7, 27)));
    let final = "";
    for (let i = 0; i < secondBytes.length; i++) {
        final += secondBytes[i].toString(16).padStart(2, "0");
    }
    return final.toLowerCase();
}

// ========== SHA-224 Async ==========
// Cloudflare Workers' WebCrypto does NOT support "SHA-224". SHA-224 reuses
// SHA-256's compression function with different initial hash values and a
// truncated (224-bit) output, implemented directly here.
async function sha224(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);

    const K = new Uint32Array([
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ]);

    // SHA-224 initial hash values (differ from SHA-256)
    const h = new Uint32Array([
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ]);

    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const padLen = (msgLen % 64 < 56) ? (56 - (msgLen % 64)) : (120 - (msgLen % 64));
    const total = msgLen + padLen + 8;
    const buf = new Uint8Array(total);
    buf.set(data, 0);
    buf[msgLen] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000) >>> 0, false);
    dv.setUint32(total - 4, bitLen >>> 0, false);

    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));

    for (let chunk = 0; chunk < total; chunk += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getUint32(chunk + i * 4, false);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
            const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
            w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
        }

        let [a,b,c,d,e,f,g,hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (hh + S1 + ch + K[i] + w[i]) | 0;
            const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) | 0;
            hh = g; g = f; f = e; e = (d + temp1) | 0;
            d = c; c = b; b = a; a = (temp1 + temp2) | 0;
        }
        h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
        h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }

    // SHA-224 output: only first 7 of the 8 words (224 bits)
    let result = "";
    for (let i = 0; i < 7; i++) {
        result += (h[i] >>> 0).toString(16).padStart(8, "0");
    }
    return result;
}

// ========== Base64 Secret ==========
function base64EncodeSecret(data, key) {
    const enc = new TextEncoder();
    const dataBytes = enc.encode(data);
    const keyBytes = enc.encode(key);
    const result = new Uint8Array(dataBytes.length);
    for (let i = 0; i < dataBytes.length; i++) {
        result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    let binary = "";
    for (let i = 0; i < result.length; i++) {
        binary += String.fromCharCode(result[i]);
    }
    return btoa(binary);
}

function base64DecodeSecret(encoded, key) {
    const binary = atob(encoded);
    const dataBytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        dataBytes[i] = binary.charCodeAt(i);
    }
    const enc = new TextEncoder();
    const keyBytes = enc.encode(key);
    const result = new Uint8Array(dataBytes.length);
    for (let i = 0; i < dataBytes.length; i++) {
        result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return new TextDecoder().decode(result);
}

// ========== UUID Utilities ==========
const uuidCache = new Map();

function getUuidBytes(uuid) {
    const key = String(uuid || "");
    const cached = uuidCache.get(key);
    if (cached) return cached;
    
    const hex = key.replace(/-/g, "");
    if (hex.length !== 32) return null;
    
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        const high = parseInt(hex[i * 2], 16);
        const low = parseInt(hex[i * 2 + 1], 16);
        if (isNaN(high) || isNaN(low)) return null;
        bytes[i] = (high << 4) | low;
    }
    
    if (uuidCache.size >= 50) uuidCache.clear();
    uuidCache.set(key, bytes);
    return bytes;
}

function matchUuid(data, offset, uuid) {
    const uuidBytes = getUuidBytes(uuid);
    if (!uuidBytes || data.byteLength < offset + 16) return false;
    for (let i = 0; i < 16; i++) {
        if (data[offset + i] !== uuidBytes[i]) return false;
    }
    return true;
}

// ========== Subscription Manager ==========
class SubscriptionManager {
    constructor(kv, uuid, planId = "FREE_1G_DAILY") {
        this.kv = kv;
        this.uuid = uuid;
        this.planId = planId;
        this.plan = SUBSCRIPTION_PLANS[planId] || SUBSCRIPTION_PLANS["FREE_1G_DAILY"];
    }
    
    async get() {
        if (!this.kv || typeof this.kv.get !== "function") {
            return {
                uuid: this.uuid,
                plan_id: this.planId,
                created_at: Date.now(),
                expires_at: Date.now() + (this.plan.duration_hours * 3600000),
                data_used_mb: 0
            };
        }
        
        const key = `sub:${this.uuid}`;
        let data = await this.kv.get(key);
        
        if (!data) {
            data = {
                uuid: this.uuid,
                plan_id: this.planId,
                created_at: Date.now(),
                expires_at: Date.now() + (this.plan.duration_hours * 3600000),
                data_used_mb: 0
            };
            await this.kv.put(key, JSON.stringify(data));
        } else {
            data = JSON.parse(data);
        }
        
        return data;
    }
    
    async check(bytesUsed) {
        const sub = await this.get();
        const now = Date.now();
        const mbUsed = Math.ceil(bytesUsed / (1024 * 1024));
        
        if (now > sub.expires_at) {
            return { ok: false, reason: "اشتراک منقضی شده است" };
        }
        
        if (this.plan.data_limit_mb !== -1) {
            const total = (sub.data_used_mb || 0) + mbUsed;
            if (total > this.plan.data_limit_mb) {
                return { ok: false, reason: "حجم مصرفی تمام شده است" };
            }
            sub.data_used_mb = total;
            if (this.kv && typeof this.kv.put === "function") {
                await this.kv.put(`sub:${this.uuid}`, JSON.stringify(sub));
            }
        }
        
        return { ok: true, sub };
    }
    
    async info() {
        const sub = await this.get();
        const now = Date.now();
        const remainHours = Math.max(0, (sub.expires_at - now) / 3600000);
        const remainData = this.plan.data_limit_mb === -1 
            ? "نامحدود" 
            : `${Math.max(0, this.plan.data_limit_mb - (sub.data_used_mb || 0))} MB`;
        
        return {
            plan: this.plan.name,
            expires: `${remainHours.toFixed(1)} ساعت`,
            data_remaining: remainData,
            data_used: `${sub.data_used_mb || 0} MB`,
            active: now <= sub.expires_at
        };
    }
    
    async upgrade(newPlanId) {
        const newPlan = SUBSCRIPTION_PLANS[newPlanId];
        if (!newPlan) return false;
        
        const sub = {
            uuid: this.uuid,
            plan_id: newPlanId,
            created_at: Date.now(),
            expires_at: Date.now() + (newPlan.duration_hours * 3600000),
            data_used_mb: 0
        };
        if (this.kv && typeof this.kv.put === "function") {
            await this.kv.put(`sub:${this.uuid}`, JSON.stringify(sub));
        }
        return true;
    }
    
    async renew() {
        const sub = await this.get();
        const plan = SUBSCRIPTION_PLANS[sub.plan_id];
        sub.expires_at = Date.now() + (plan.duration_hours * 3600000);
        sub.data_used_mb = 0;
        if (this.kv && typeof this.kv.put === "function") {
            await this.kv.put(`sub:${this.uuid}`, JSON.stringify(sub));
        }
        return true;
    }
    
    async getToken() {
        return await md5Hash(this.uuid);
    }
}

// ========== Config Manager ==========
async function getConfig(env, host, uuid, fingerprint = "chrome", reset = false) {
    const key = "starjin_config";
    let config = null;
    
    if (!reset && env.KV && typeof env.KV.get === "function") {
        const stored = await env.KV.get(key);
        if (stored) {
            try {
                config = JSON.parse(stored);
            } catch(e) {}
        }
    }
    
    if (!config) {
        config = {
            version: VERSION,
            uuid: uuid,
            host: host,
            hosts: [host],
            path: "/",
            protocol: "vless",
            transport: "ws",
            grpc_mode: "gun",
            grpc_ua: fingerprint,
            skip_tls: false,
            enable_0rtt: false,
            tls_frag: null,
            random_path: false,
            ech: false,
            ech_dns: "https://cloudflare-dns.com/dns-query",
            ech_sni: "cloudflare-ech.com",
            ss: { cipher: "aes-128-gcm", tls: true },
            fingerprint: "chrome",
            sub: {
                local: true,
                ip_count: 16,
                custom_port: -1,
                sub: null,
                name: "StarJin",
                update_hours: 3,
                token: await md5Hash(host + uuid)
            },
            converter: {
                api: "https://subapi.starjin.ir",
                config: "https://raw.github.../starjin.ini",
                emoji: false
            },
            proxy: {
                none: "direct",
                socks5: { enabled: false, global: false, account: "", whitelist: whitelistDomains }
            },
            tg: { enabled: false, token: null, chat_id: null },
            cf: { email: null, api_key: null, account_id: null, token: null }
        };
    }
    
    config.host = host;
    config.uuid = uuid;
    config.sub.token = await md5Hash(host + uuid);
    
    return config;
}

// ========== Plan API Handler ==========
async function handlePlanAPI(request, env, uuid) {
    // Check KV availability
    if (!env.KV || typeof env.KV.get !== "function") {
        return new Response(JSON.stringify({ error: "KV storage not available" }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
    
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    const manager = new SubscriptionManager(env.KV, uuid);
    
    switch (action) {
        case "info": {
            const info = await manager.info();
            return new Response(JSON.stringify(info, null, 2), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
            
        case "upgrade": {
            const planId = url.searchParams.get("plan");
            if (await manager.upgrade(planId)) {
                return new Response(JSON.stringify({ success: true, plan: planId }), {
                    status: 200,
                    headers: { "Content-Type": "application/json" }
                });
            }
            return new Response(JSON.stringify({ error: "پلن نامعتبر است" }), { status: 400 });
        }
            
        case "renew": {
            await manager.renew();
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
            
        case "token": {
            const token = await manager.getToken();
            return new Response(JSON.stringify({ token: token }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
            
        default: {
            const plans = Object.keys(SUBSCRIPTION_PLANS).map(k => ({
                id: k,
                name: SUBSCRIPTION_PLANS[k].name,
                data: SUBSCRIPTION_PLANS[k].data_limit_mb === -1 ? "Unlimited" : `${SUBSCRIPTION_PLANS[k].data_limit_mb} MB`,
                days: SUBSCRIPTION_PLANS[k].duration_hours / 24
            }));
            return new Response(JSON.stringify({ plans }, null, 2), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
    }
}

// ========== WebSocket Early Data ==========
async function isValidWsEarlyData(data, uuid) {
    if (!data?.byteLength) return false;
    if (data.byteLength >= 18 && matchUuid(data, 1, uuid)) return true;
    if (data.byteLength < 58 || data[56] !== 13 || data[57] !== 10) return false;
    
    const hash = await sha224(uuid);
    for (let i = 0; i < 56; i++) {
        if (data[i] !== hash.charCodeAt(i)) return false;
    }
    return true;
}

async function decodeWsEarlyData(encoded, uuid) {
    if (!encoded) return null;
    if (encoded.length > WS_EARLY_HEADER_MAX) throw new Error("Early data too large");
    
    let bytes;
    if (typeof Uint8Array.fromBase64 === "function") {
        try {
            bytes = Uint8Array.fromBase64(encoded, { alphabet: "base64url" });
        } catch(e) {}
    }
    
    if (!bytes) {
        let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
        const pad = b64.length % 4;
        if (pad) b64 += "=".repeat(4 - pad);
        try {
            const binary = atob(b64);
            bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
        } catch(e) {
            return null;
        }
    }
    
    if (bytes.byteLength > WS_EARLY_MAX) throw new Error("Decoded data too large");
    const isValid = await isValidWsEarlyData(bytes, uuid);
    return isValid ? bytes : null;
}

// ========== Transport Helpers ==========
function getTransportType(config) {
    const isGrpc = config.transport === "grpc";
    return {
        type: isGrpc ? (config.grpc_mode === "gun" ? "grpc-gun" : "grpc-multi") : "ws",
        pathField: isGrpc ? "service" : "path",
        hostField: isGrpc ? "authority" : "host"
    };
}

function getTransportPath(config, defaultPath = "/", isSub = false) {
    if (isSub) return "/";
    if (config.random_path) return randomPath(defaultPath);
    return defaultPath;
}

// ========== Speed Test Detection ==========
function isSpeedTestSite(hostname) {
    const sites = ["speed.cloudflare.com", "speedtest.net", "fast.com", "ookla.com"];
    for (const site of sites) {
        if (hostname === site || hostname.endsWith("." + site)) return true;
    }
    return false;
}

// ========== Parse Trojan Request ==========
async function parseTrojanRequestAsync(data, uuid) {
    if (data.byteLength < 58) return { status: "need_more", hasError: false };
    
    const hash = await sha224(uuid);
    for (let i = 0; i < 56; i++) {
        if (data[i] !== hash.charCodeAt(i)) {
            return { status: "invalid", hasError: true, message: "Invalid hash" };
        }
    }
    
    if (data[56] !== 13 || data[57] !== 10) {
        return { status: "invalid", hasError: true, message: "Invalid header" };
    }
    
    let pos = 58;
    if (data.byteLength < pos + 6) return { status: "need_more", hasError: false };
    
    const command = data[pos];
    if (command !== 1 && command !== 3) {
        return { status: "invalid", hasError: true, message: "Invalid command" };
    }
    
    const isUDP = command === 3;
    const addrType = data[pos + 1];
    let hostname = "";
    let addrPos = pos + 2;
    
    switch (addrType) {
        case 1: // IPv4
            if (data.byteLength < addrPos + 4) return { status: "need_more", hasError: false };
            hostname = `${data[addrPos]}.${data[addrPos+1]}.${data[addrPos+2]}.${data[addrPos+3]}`;
            addrPos += 4;
            break;
        case 3: // Domain
            if (data.byteLength < addrPos + 1) return { status: "need_more", hasError: false };
            const domainLen = data[addrPos];
            addrPos++;
            if (data.byteLength < addrPos + domainLen) return { status: "need_more", hasError: false };
            hostname = new TextDecoder().decode(data.subarray(addrPos, addrPos + domainLen));
            addrPos += domainLen;
            break;
        case 4: // IPv6
            if (data.byteLength < addrPos + 16) return { status: "need_more", hasError: false };
            const parts = [];
            for (let i = 0; i < 8; i++) {
                const val = (data[addrPos + i*2] << 8) | data[addrPos + i*2 + 1];
                parts.push(val.toString(16));
            }
            hostname = parts.join(":");
            addrPos += 16;
            break;
        default:
            return { status: "invalid", hasError: true, message: "Invalid address type" };
    }
    
    if (!hostname) return { status: "invalid", hasError: true, message: "Empty hostname" };
    if (data.byteLength < addrPos + 4) return { status: "need_more", hasError: false };
    
    const port = (data[addrPos] << 8) | data[addrPos + 1];
    if (data[addrPos + 2] !== 13 || data[addrPos + 3] !== 10) {
        return { status: "invalid", hasError: true, message: "Invalid port terminator" };
    }
    
    const clientDataPos = addrPos + 4;
    
    return {
        status: "ok",
        hasError: false,
        result: {
            protocol: "trojan",
            hostname: hostname,
            port: port,
            isUDP: isUDP,
            rawData: data.subarray(clientDataPos),
            rawClientData: data.subarray(clientDataPos),
            respHeader: null
        }
    };
}

// ========== Parse VLESS Request ==========
function parseVlessRequest(data, uuid) {
    if (data.byteLength < 18) return { status: "need_more", hasError: false };
    if (!matchUuid(data, 1, uuid)) return { status: "invalid", hasError: true, message: "UUID mismatch" };
    
    const addrsLen = data[17];
    let pos = 18 + addrsLen;
    
    if (data.byteLength < pos + 4) return { status: "need_more", hasError: false };
    
    const isUDP = data[pos] === 2;
    const port = (data[pos + 1] << 8) | data[pos + 2];
    const addrType = data[pos + 3];
    let addrPos = pos + 4;
    let hostname = "";
    
    switch (addrType) {
        case 1: // IPv4
            if (data.byteLength < addrPos + 4) return { status: "need_more", hasError: false };
            hostname = `${data[addrPos]}.${data[addrPos+1]}.${data[addrPos+2]}.${data[addrPos+3]}`;
            addrPos += 4;
            break;
        case 2: // Domain
            if (data.byteLength < addrPos + 1) return { status: "need_more", hasError: false };
            const domainLen = data[addrPos];
            addrPos++;
            if (data.byteLength < addrPos + domainLen) return { status: "need_more", hasError: false };
            hostname = new TextDecoder().decode(data.subarray(addrPos, addrPos + domainLen));
            addrPos += domainLen;
            break;
        case 3: // IPv6
            if (data.byteLength < addrPos + 16) return { status: "need_more", hasError: false };
            const parts = [];
            for (let i = 0; i < 8; i++) {
                const val = (data[addrPos + i*2] << 8) | data[addrPos + i*2 + 1];
                parts.push(val.toString(16));
            }
            hostname = parts.join(":");
            addrPos += 16;
            break;
        default:
            return { status: "invalid", hasError: true, message: "Invalid address type" };
    }
    
    if (!hostname) return { status: "invalid", hasError: true, message: "Empty hostname" };
    
    return {
        status: "ok",
        hasError: false,
        result: {
            protocol: "vless",
            hostname: hostname,
            port: port,
            isUDP: isUDP,
            version: data[0],
            rawData: data.subarray(addrPos),
            rawClientData: data.subarray(addrPos),
            respHeader: new Uint8Array([data[0], 0])
        }
    };
}

// ========== Read XHTTP Packet ==========
async function readXHttpPacket(reader, uuid) {
    let buffer = new Uint8Array(1024);
    let size = 0;
    
    while (true) {
        const { value, done } = await reader.read();
        if (done) {
            if (size === 0) return null;
            break;
        }
        
        const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
        if (size + chunk.byteLength > buffer.byteLength) {
            const newBuf = new Uint8Array(Math.max(buffer.byteLength * 2, size + chunk.byteLength));
            newBuf.set(buffer.subarray(0, size));
            buffer = newBuf;
        }
        buffer.set(chunk, size);
        size += chunk.byteLength;
        
        const data = buffer.subarray(0, size);
        
        // Try VLESS parse
        const vlessResult = parseVlessRequest(data, uuid);
        if (vlessResult.status === "ok") {
            return { ...vlessResult.result, reader };
        }
        
        // Try Trojan parse (async)
        const trojanResult = await parseTrojanRequestAsync(data, uuid);
        if (trojanResult.status === "ok") {
            return { ...trojanResult.result, reader };
        }
        
        if (vlessResult.status !== "need_more" && trojanResult.status !== "need_more") {
            return null;
        }
    }
    
    const finalData = buffer.subarray(0, size);
    const finalVless = parseVlessRequest(finalData, uuid);
    if (finalVless.status === "ok") return { ...finalVless.result, reader };
    
    const finalTrojan = await parseTrojanRequestAsync(finalData, uuid);
    if (finalTrojan.status === "ok") return { ...finalTrojan.result, reader };
    
    return null;
}

// ========== XHTTP Handler ==========
async function handleXHttp(request, uuid) {
    if (!request.body) return new Response("Bad Request", { status: 400 });
    
    const reader = request.body.getReader();
    const packet = await readXHttpPacket(reader, uuid);
    
    if (!packet) {
        try { reader.releaseLock(); } catch(e) {}
        return new Response("Invalid Protocol", { status: 400 });
    }
    
    if (isSpeedTestSite(packet.hostname)) {
        try { reader.releaseLock(); } catch(e) {}
        return new Response("Blocked", { status: 403 });
    }
    
    if (packet.isUDP && packet.protocol !== "trojan" && packet.port !== 53) {
        try { reader.releaseLock(); } catch(e) {}
        return new Response("UDP not supported", { status: 400 });
    }
    
    const connection = { socket: null, connecting: null, retry: null };
    let writer = null;
    let writerLock = null;
    
    const headers = new Headers({
        "Content-Type": "application/octet-stream",
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-store"
    });
    
    const releaseWriter = () => {
        if (writerLock) {
            try { writerLock.releaseLock(); } catch(e) {}
            writerLock = null;
        }
        writer = null;
    };
    
    const getWriter = () => {
        const sock = connection.socket;
        if (!sock) return null;
        if (sock !== writer) {
            releaseWriter();
            writer = sock;
            writerLock = sock.writable.getWriter();
        }
        return writerLock;
    };
    
    let queue = null;
    
    return new Response(new ReadableStream({
        async start(controller) {
            let closed = false;
            let remainingData = packet.rawData;
            const udpCache = { buffer: new Uint8Array(0) };
            
            const wsLike = {
                readyState: WebSocket.OPEN,
                send(data) {
                    if (closed) return;
                    try {
                        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
                        controller.enqueue(bytes);
                    } catch(e) {
                        closed = true;
                        this.readyState = WebSocket.CLOSED;
                    }
                },
                close() {
                    if (closed) return;
                    closed = true;
                    this.readyState = WebSocket.CLOSED;
                    try { controller.close(); } catch(e) {}
                }
            };
            
            queue = createUpstreamQueue({
                getWriter: getWriter,
                releaseWriter: releaseWriter,
                retryConnect: async () => {
                    if (typeof connection.retry !== "function") throw new Error("Retry not available");
                    await connection.retry();
                },
                closeConnection: () => {
                    try { connection.socket?.close(); } catch(e) {}
                    closeSocketQuietly(wsLike);
                },
                name: "XHTTP-Queue"
            });
            
            const sendToUpstream = async (data, wait = true) => {
                return queue.writeAndWait(data, wait);
            };
            
            try {
                if (packet.isUDP) {
                    if (packet.protocol === "trojan") {
                        await forwardTrojanUdp(packet.rawData, wsLike, udpCache, request);
                    } else {
                        await forwardUdpData(packet.rawData, wsLike, remainingData, request);
                    }
                    remainingData = null;
                } else {
                    await forwardTcpData(
                        packet.hostname, packet.port, packet.rawData,
                        wsLike, null, connection, uuid, request
                    );
                }
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (!value || value.byteLength === 0) continue;
                    
                    if (packet.isUDP) {
                        if (packet.protocol === "trojan") {
                            await forwardTrojanUdp(value, wsLike, udpCache, request);
                        } else {
                            await forwardUdpData(value, wsLike, remainingData, request);
                        }
                        remainingData = null;
                    } else {
                        if (!(await sendToUpstream(value))) {
                            throw new Error("Remote socket not ready");
                        }
                    }
                }
                
                if (!packet.isUDP) {
                    await queue.flush();
                    const w = getWriter();
                    if (w) {
                        try { await w.close(); } catch(e) {}
                    }
                }
            } catch(e) {
                log("[XHTTP] Error:", e?.message || e);
                closeSocketQuietly(wsLike);
            } finally {
                queue?.clear();
                releaseWriter();
                try { reader.releaseLock(); } catch(e) {}
            }
        },
        cancel() {
            queue?.clear();
            try { connection.socket?.close(); } catch(e) {}
            releaseWriter();
            try { reader.releaseLock(); } catch(e) {}
        }
    }), { status: 200, headers });
}

// ========== gRPC Handler ==========
async function handleGrpc(request, uuid) {
    if (!request.body) return new Response("Bad Request", { status: 400 });
    
    const reader = request.body.getReader();
    const connection = { socket: null, connecting: null, retry: null };
    let isTrojan = false;
    const udpCache = { buffer: new Uint8Array(0) };
    let isVless = null;
    let writer = null;
    let writerLock = null;
    let queue = null;
    let pendingData = null;
    
    const GRAIN_SIZE = DOWNSTREAM_GRAIN;
    const FLUSH_DELAY = Math.max(DOWNSTREAM_SILENT_MS, 1);
    
    const headers = new Headers({
        "Content-Type": "application/grpc",
        "grpc-status": "0",
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-store"
    });
    
    return new Response(new ReadableStream({
        async start(controller) {
            let closed = false;
            let chunks = [];
            let totalSize = 0;
            let flushTimer = null;
            let isFlushing = false;
            
            const wsLike = {
                readyState: WebSocket.OPEN,
                send(data) {
                    if (closed) return;
                    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
                    const frames = [];
                    let remaining = bytes.byteLength;
                    while (remaining > 0) {
                        const chunkSize = Math.min(remaining, 0x7F);
                        frames.push(chunkSize | (remaining > 0x7F ? 0x80 : 0));
                        remaining >>= 7;
                    }
                    const headerLen = frames.length;
                    const totalLen = 1 + headerLen + bytes.byteLength;
                    const frame = new Uint8Array(5 + totalLen);
                    frame[0] = 0;
                    frame[1] = (totalLen >> 24) & 0xFF;
                    frame[2] = (totalLen >> 16) & 0xFF;
                    frame[3] = (totalLen >> 8) & 0xFF;
                    frame[4] = totalLen & 0xFF;
                    frame[5] = 10;
                    frame.set(frames, 6);
                    frame.set(bytes, 6 + headerLen);
                    chunks.push(frame);
                    totalSize += frame.byteLength;
                    flushIfNeeded();
                },
                close() {
                    if (closed) return;
                    closed = true;
                    this.readyState = WebSocket.CLOSED;
                    try { controller.close(); } catch(e) {}
                }
            };
            
            const flushIfNeeded = () => {
                if (totalSize >= GRAIN_SIZE) {
                    flush();
                    return;
                }
                if (flushTimer || isFlushing) return;
                isFlushing = true;
                queueMicrotask(() => {
                    isFlushing = false;
                    if (closed || totalSize === 0 || flushTimer) return;
                    flushTimer = setTimeout(flush, FLUSH_DELAY);
                });
            };
            
            const flush = () => {
                if (flushTimer) {
                    clearTimeout(flushTimer);
                    flushTimer = null;
                }
                if (closed || totalSize === 0) return;
                const combined = new Uint8Array(totalSize);
                let offset = 0;
                for (const chunk of chunks) {
                    combined.set(chunk, offset);
                    offset += chunk.byteLength;
                }
                chunks = [];
                totalSize = 0;
                try {
                    controller.enqueue(combined);
                } catch(e) {
                    closed = true;
                    wsLike.readyState = WebSocket.CLOSED;
                }
            };
            
            const closeAll = () => {
                queue?.clear();
                flush();
                closed = true;
                wsLike.readyState = WebSocket.CLOSED;
                if (flushTimer) clearTimeout(flushTimer);
                if (writerLock) {
                    try { writerLock.releaseLock(); } catch(e) {}
                    writerLock = null;
                }
                writer = null;
                try { reader.releaseLock(); } catch(e) {}
                try { connection.socket?.close(); } catch(e) {}
                try { controller.close(); } catch(e) {}
            };
            
            const releaseWriter = () => {
                if (writerLock) {
                    try { writerLock.releaseLock(); } catch(e) {}
                    writerLock = null;
                }
                writer = null;
            };
            
            const getWriter = () => {
                const sock = connection.socket;
                if (!sock) return null;
                if (sock !== writer) {
                    releaseWriter();
                    writer = sock;
                    writerLock = sock.writable.getWriter();
                }
                return writerLock;
            };
            
            queue = createUpstreamQueue({
                getWriter: getWriter,
                releaseWriter: releaseWriter,
                retryConnect: async () => {
                    if (typeof connection.retry !== "function") throw new Error("Retry not available");
                    await connection.retry();
                },
                closeConnection: closeAll,
                name: "gRPC-Queue"
            });
            
            const sendToUpstream = async (data, wait = true) => {
                return queue.writeAndWait(data, wait);
            };
            
            try {
                let buf = new Uint8Array(0);
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (!value || value.byteLength === 0) continue;
                    
                    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
                    buf = concatBuffers(buf, chunk);
                    
                    while (buf.byteLength >= 5) {
                        const msgLen = ((buf[1] << 24) >>> 0) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
                        const totalLen = 5 + msgLen;
                        if (buf.byteLength < totalLen) break;
                        
                        let payload = buf.subarray(5, totalLen);
                        buf = buf.subarray(totalLen);
                        
                        if (payload.byteLength >= 2 && payload[0] === 10) {
                            let varintLen = 0;
                            let pos = 1;
                            let hasMore = false;
                            while (pos < payload.length) {
                                const b = payload[pos++];
                                if ((b & 0x80) === 0) {
                                    hasMore = true;
                                    break;
                                }
                                varintLen += 7;
                                if (varintLen > 35) break;
                            }
                            if (hasMore) payload = payload.subarray(pos);
                        }
                        
                        if (!payload.byteLength) continue;
                        
                        if (isTrojan) {
                            if (isVless) {
                                await forwardTrojanUdp(payload, wsLike, udpCache, request);
                            } else {
                                await forwardUdpData(payload, wsLike, null, request);
                            }
                            continue;
                        }
                        
                        if (connection.socket) {
                            if (!(await sendToUpstream(payload))) {
                                throw new Error("Remote socket not ready");
                            }
                        } else {
                            const bytes = arrayToUint8(payload);
                            if (pendingData === null) {
                                pendingData = bytes.byteLength >= 58 && bytes[56] === 13 && bytes[57] === 10;
                            }
                            
                            if (pendingData) {
                                const trojan = await parseTrojanRequestAsync(bytes, uuid);
                                if (trojan.hasError) throw new Error(trojan.message || "Invalid trojan request");
                                
                                const { port, hostname, rawClientData, isUDP } = trojan.result;
                                log("[gRPC] Trojan packet:", hostname, ":", port, "| UDP:", isUDP);
                                
                                if (isSpeedTestSite(hostname)) {
                                    throw new Error("Speed test site blocked");
                                }
                                
                                if (isUDP) {
                                    isTrojan = true;
                                    if (rawClientData?.byteLength > 0) {
                                        await forwardTrojanUdp(rawClientData, wsLike, udpCache, request);
                                    }
                                } else {
                                    await forwardTcpData(hostname, port, rawClientData, wsLike, null, connection, uuid, request);
                                }
                            } else {
                                pendingData = false;
                                const vless = parseVlessRequest(bytes, uuid);
                                if (vless.hasError) throw new Error(vless.message || "Invalid vless request");
                                
                                const { port, hostname, version, isUDP, rawClientData } = vless.result;
                                log("[gRPC] VLESS packet:", hostname, ":", port, "| UDP:", isUDP);
                                
                                if (isSpeedTestSite(hostname)) {
                                    throw new Error("Speed test site blocked");
                                }
                                
                                if (isUDP) {
                                    if (port !== 53) throw new Error("UDP only supported for port 53");
                                    isTrojan = true;
                                    isVless = true;
                                }
                                
                                const respHeader = new Uint8Array([version, 0]);
                                wsLike.send(respHeader);
                                
                                if (isTrojan) {
                                    if (isVless) {
                                        await forwardTrojanUdp(rawClientData, wsLike, udpCache, request);
                                    } else {
                                        await forwardUdpData(rawClientData, wsLike, null, request);
                                    }
                                } else {
                                    await forwardTcpData(hostname, port, rawClientData, wsLike, respHeader, connection, uuid, request);
                                }
                            }
                        }
                    }
                    flush();
                }
                
                await queue.flush();
            } catch(e) {
                log("[gRPC] Error:", e?.message || e);
            } finally {
                queue?.clear();
                releaseWriter();
                closeAll();
            }
        },
        cancel() {
            queue?.clear();
            try { connection.socket?.close(); } catch(e) {}
            releaseWriter();
            try { reader.releaseLock(); } catch(e) {}
        }
    }), { status: 200, headers });
}

// ========== WebSocket Handler ==========
async function handleWebSocket(request, uuid, parsedUrl) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    
    try {
        server.accept({ allowHalfOpen: true });
    } catch(e) {
        server.accept();
    }
    
    server.binaryType = "arraybuffer";
    
    let connection = { socket: null, connecting: null, retry: null };
    let isTrojan = false;
    let writer = null;
    let writerLock = null;
    let queue = null;
    let pendingData = null;
    let closed = false;
    let socks5Protocol = null;
    let flowControl = 0;
    let seqNum = 0;
    
    const wsExt = parsedUrl.searchParams.get("Sec-WebSocket-Extensions") || "";
    const hasSocks5 = !!parsedUrl.searchParams.has("socks5");
    
    const releaseWriter = () => {
        if (writerLock) {
            try { writerLock.releaseLock(); } catch(e) {}
            writerLock = null;
        }
        writer = null;
    };
    
    const getWriter = () => {
        const sock = connection.socket;
        if (!sock) return null;
        if (sock !== writer) {
            releaseWriter();
            writer = sock;
            writerLock = sock.writable.getWriter();
        }
        return writerLock;
    };
    
    const closeConnection = () => {
        if (closed) return;
        closed = true;
        try { connection.socket?.close(); } catch(e) {}
        closeSocketQuietly(server);
    };
    
    queue = createUpstreamQueue({
        getWriter: getWriter,
        releaseWriter: releaseWriter,
        retryConnect: async () => {
            if (typeof connection.retry !== "function") throw new Error("Retry not available");
            await connection.retry();
        },
        closeConnection: closeConnection,
        name: "WebSocket-Queue"
    });
    
    const sendToUpstream = async (data, wait = true) => {
        return queue.writeAndWait(data, wait);
    };
    
    const processData = async (data) => {
        if (isTrojan) {
            await forwardTrojanUdp(data, server, { buffer: new Uint8Array(0) }, request);
            return;
        }
        
        if (await sendToUpstream(data)) return;
        
        if (socks5Protocol === null) {
            if (parsedUrl.searchParams.has("socks5")) socks5Protocol = "socks5";
            else if (parsedUrl.searchParams.has("http")) socks5Protocol = "http";
            else if (parsedUrl.searchParams.has("https")) socks5Protocol = "https";
            else if (parsedUrl.searchParams.has("turn")) socks5Protocol = "turn";
            else if (parsedUrl.searchParams.has("sstp")) socks5Protocol = "sstp";
        }
        
        if (socks5Protocol === "socks5") {
            isTrojan = true;
            await forwardUdpData(data, server, null, request);
            return;
        }
        
        const bytes = arrayToUint8(data);
        
        if (socks5Protocol === null) {
            if (parsedUrl.searchParams.has("ss")) {
                socks5Protocol = "ss";
            } else {
                const isTrojanPacket = bytes.byteLength >= 58 && bytes[56] === 13 && bytes[57] === 10;
                socks5Protocol = isTrojanPacket ? "trojan" : "vless";
            }
            isTrojan = socks5Protocol === "trojan";
            log("[WebSocket] Detected protocol:", socks5Protocol, "| UA:", request.headers.get("User-Agent") || "unknown");
        }
        
        if (socks5Protocol === "ss") {
            await handleSsData(bytes, server, request);
            return;
        }
        
        if (socks5Protocol === "trojan") {
            const trojan = await parseTrojanRequestAsync(bytes, uuid);
            if (trojan.hasError) throw new Error(trojan.message || "Invalid trojan request");
            
            const { port, hostname, rawClientData, isUDP } = trojan.result;
            log("[WebSocket] Trojan packet:", hostname, ":", port, "| UDP:", isUDP);
            
            if (isSpeedTestSite(hostname)) {
                throw new Error("Speed test site blocked");
            }
            
            if (isUDP) {
                isTrojan = true;
                if (rawClientData?.byteLength > 0) {
                    await forwardTrojanUdp(rawClientData, server, { buffer: new Uint8Array(0) }, request);
                }
                return;
            }
            
            await forwardTcpData(hostname, port, rawClientData, server, null, connection, uuid, request);
            return;
        }
        
        // VLESS
        const vless = parseVlessRequest(bytes, uuid);
        if (vless.hasError) throw new Error(vless.message || "Invalid vless request");
        
        const { port, hostname, version, isUDP, rawClientData } = vless.result;
        log("[WebSocket] VLESS packet:", hostname, ":", port, "| UDP:", isUDP);
        
        if (isSpeedTestSite(hostname)) {
            throw new Error("Speed test site blocked");
        }
        
        if (isUDP) {
            if (port !== 53) throw new Error("UDP only supported for port 53");
            isTrojan = true;
        }
        
        const respHeader = new Uint8Array([version, 0]);
        server.send(respHeader);
        
        if (isTrojan) {
            await forwardTrojanUdp(rawClientData, server, { buffer: new Uint8Array(0) }, request);
            return;
        }
        
        await forwardTcpData(hostname, port, rawClientData, server, respHeader, connection, uuid, request);
    };
    
    const onError = (error) => {
        if (closed) return;
        closed = true;
        flowControl = 0;
        seqNum = 0;
        const msg = error?.message || String(error);
        if (msg.includes("Connection lost") || msg.includes("ReadableStream closed")) {
            log("[WebSocket] Connection ended:", msg);
        } else {
            log("[WebSocket] Error:", msg);
        }
        queue?.clear();
        releaseWriter();
        closeSocketQuietly(server);
    };
    
    server.addEventListener("message", (event) => {
        if (closed) return;
        const data = event.data;
        const len = arrayToUint8(data).byteLength;
        const newFlow = flowControl + len;
        const newSeq = seqNum + 1;
        
        if (newFlow > QUEUE_MAX_BYTES || newSeq > QUEUE_MAX_ITEMS) {
            onError(new Error("Queue overflow"));
            return;
        }
        
        flowControl = newFlow;
        seqNum = newSeq;
        
        (async () => {
            try {
                flowControl = Math.max(0, flowControl - len);
                seqNum = Math.max(0, seqNum - 1);
                if (closed) return;
                await processData(data);
            } catch(e) {
                onError(e);
            }
        })();
    });
    
    server.addEventListener("close", () => {
        if (closed) return;
        closed = true;
        (async () => {
            if (closed) return;
            await queue.flush();
            releaseWriter();
        })();
    });
    
    server.addEventListener("error", onError);
    
    if (!hasSocks5 && wsExt) {
        try {
            const decoded = await decodeWsEarlyData(wsExt, uuid);
            if (decoded?.byteLength) {
                await processData(decoded.buffer);
            }
        } catch(e) {
            onError(e);
        }
    }
    
    return new Response(null, {
        status: 101,
        webSocket: client,
        headers: { "Sec-WebSocket-Extensions": "" }
    });
}

// ========== SS Handler ==========
async function handleSsData(data, ws, request) {
    const decoder = new TextDecoder();
    const bytes = arrayToUint8(data);
    
    if (bytes.byteLength < 3) throw new Error("SS packet too short");
    
    const cmd = bytes[0];
    let pos = 1;
    let hostname = "";
    
    if (cmd === 1) { // IPv4
        if (bytes.byteLength < pos + 4 + 2) throw new Error("SS IPv4 packet too short");
        hostname = `${bytes[pos]}.${bytes[pos+1]}.${bytes[pos+2]}.${bytes[pos+3]}`;
        pos += 4;
    } else if (cmd === 3) { // Domain
        if (bytes.byteLength < pos + 1) throw new Error("SS domain packet too short");
        const domainLen = bytes[pos];
        pos++;
        if (bytes.byteLength < pos + domainLen + 2) throw new Error("SS domain packet too short");
        hostname = decoder.decode(bytes.subarray(pos, pos + domainLen));
        pos += domainLen;
    } else if (cmd === 4) { // IPv6
        if (bytes.byteLength < pos + 16 + 2) throw new Error("SS IPv6 packet too short");
        const parts = [];
        for (let i = 0; i < 8; i++) {
            const val = (bytes[pos + i*2] << 8) | bytes[pos + i*2 + 1];
            parts.push(val.toString(16));
        }
        hostname = parts.join(":");
        pos += 16;
    } else {
        throw new Error(`Invalid SS address type: ${cmd}`);
    }
    
    if (!hostname) throw new Error("SS empty hostname");
    
    const port = (bytes[pos] << 8) | bytes[pos + 1];
    const clientData = bytes.subarray(pos + 2);
    
    if (isSpeedTestSite(hostname)) {
        throw new Error("Speed test site blocked");
    }
    
    log("[SS] Connecting to:", hostname, ":", port);
    await forwardTcpData(hostname, port, clientData, ws, null, { socket: null, connecting: null, retry: null }, null, request);
}

// ========== UDP Forwarding ==========
async function forwardUdpData(data, ws, respHeader, request, transformCallback = null) {
    const bytes = arrayToUint8(data);
    log("[UDP] Forwarding:", bytes.byteLength, "B -> 8.8.4.4:53");
    
    try {
        const connector = createTcpConnector(request);
        const socket = connector({ hostname: "8.8.4.4", port: 53 });
        let header = respHeader;
        const writer = socket.writable.getWriter();
        
        await writer.write(bytes);
        log("[UDP] Request written:", bytes.byteLength, "B");
        writer.releaseLock();
        
        await socket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                let dataBytes = arrayToUint8(chunk);
                log("[UDP] Response:", dataBytes.byteLength, "B");
                
                if (transformCallback) {
                    const transformed = await transformCallback(dataBytes);
                    if (transformed && transformed.length) {
                        for (const frame of transformed) {
                            const toSend = header ? concatBuffers(header, frame) : frame;
                            if (ws.readyState === WebSocket.OPEN) {
                                await webSocketSendAndWait(ws, toSend);
                            }
                            header = null;
                        }
                        return;
                    }
                }
                
                const toSend = header ? concatBuffers(header, dataBytes) : dataBytes;
                if (ws.readyState === WebSocket.OPEN) {
                    await webSocketSendAndWait(ws, toSend);
                    header = null;
                }
            }
        }));
    } catch(e) {
        log("[UDP] Error:", e?.message || e);
    }
}

async function forwardTrojanUdp(data, ws, cache, request) {
    const bytes = arrayToUint8(data);
    let buffer = cache.buffer instanceof Uint8Array ? cache.buffer : new Uint8Array(0);
    const combined = buffer.byteLength ? concatBuffers(buffer, bytes) : bytes;
    let pos = 0;
    
    while (pos < combined.byteLength) {
        const addrType = combined[pos];
        let addrLen = 0;
        let addrPos = pos + 1;
        
        if (addrType === 1) addrLen = 4;
        else if (addrType === 4) addrLen = 16;
        else if (addrType === 3) {
            if (combined.byteLength < addrPos + 1) break;
            addrLen = 1 + combined[addrPos];
        } else {
            throw new Error(`Invalid UDP address type: ${addrType}`);
        }
        
        const packetEnd = addrPos + addrLen;
        if (combined.byteLength < packetEnd + 6) break;
        
        const port = (combined[packetEnd] << 8) | combined[packetEnd + 1];
        const udpLen = (combined[packetEnd + 2] << 8) | combined[packetEnd + 3];
        
        if (combined[packetEnd + 4] !== 13 || combined[packetEnd + 5] !== 10) {
            throw new Error("Invalid UDP header");
        }
        
        const dataStart = packetEnd + 6;
        const dataEnd = dataStart + udpLen;
        if (combined.byteLength < dataEnd) break;
        
        const headerBytes = combined.slice(pos, packetEnd + 2);
        const udpData = combined.slice(dataStart, dataEnd);
        pos = dataEnd;
        
        if (port !== 53) throw new Error("UDP only supported for port 53");
        if (!udpData.byteLength) continue;
        
        let payload = udpData;
        if (udpData.byteLength < 2 || ((udpData[0] << 8) | udpData[1]) !== udpData.byteLength - 2) {
            const wrapped = new Uint8Array(udpData.byteLength + 2);
            wrapped[0] = (udpData.byteLength >> 8) & 0xFF;
            wrapped[1] = udpData.byteLength & 0xFF;
            wrapped.set(udpData, 2);
            payload = wrapped;
        }
        
        const udpCacheLocal = { buffer: new Uint8Array(0) };
        await forwardUdpData(payload, ws, null, request, async (response) => {
            const respBytes = arrayToUint8(response);
            const combinedResp = udpCacheLocal.buffer.byteLength ? concatBuffers(udpCacheLocal.buffer, respBytes) : respBytes;
            const frames = [];
            let framePos = 0;
            
            while (framePos + 2 <= combinedResp.byteLength) {
                const frameLen = (combinedResp[framePos] << 8) | combinedResp[framePos + 1];
                const frameEnd = framePos + 2 + frameLen;
                if (frameEnd > combinedResp.byteLength) break;
                
                const frameData = combinedResp.slice(framePos + 2, frameEnd);
                const responseFrame = new Uint8Array(headerBytes.byteLength + 4 + frameData.byteLength);
                responseFrame.set(headerBytes, 0);
                responseFrame[headerBytes.byteLength] = (frameData.byteLength >> 8) & 0xFF;
                responseFrame[headerBytes.byteLength + 1] = frameData.byteLength & 0xFF;
                responseFrame[headerBytes.byteLength + 2] = 13;
                responseFrame[headerBytes.byteLength + 3] = 10;
                responseFrame.set(frameData, headerBytes.byteLength + 4);
                frames.push(responseFrame);
                framePos = frameEnd;
            }
            
            udpCacheLocal.buffer = combinedResp.slice(framePos);
            return frames.length ? frames : null;
        });
    }
    
    if (cache) cache.buffer = combined.slice(pos);
}

// ========== TCP Forwarding ==========
async function forwardTcpData(host, port, earlyData, ws, respHeader, connection, uuid, request) {
    log("[TCP] Forwarding:", host, ":", port, "| ProxyIP:", proxyIP, "| Fallback:", fallbackEnabled);
    
    const TIMEOUT_MS = 10000;
    let earlySent = false;
    const tcpConnector = createTcpConnector(request);
    
    async function connectWithTimeout(promise, timeoutMs) {
        await Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error("Connect timeout")), timeoutMs))]);
    }
    
    async function writeData(socket, data) {
        if (arrayToUint8(data).byteLength <= 0) return;
        const writer = socket.writable.getWriter();
        try {
            await writer.write(arrayToUint8(data));
        } finally {
            try { writer.releaseLock(); } catch(e) {}
        }
    }
    
    async function tryConnect(targets, early) {
        if (targets.length === 1) {
            const target = targets[0];
            const socket = await tcpConnector({ hostname: target.hostname, port: target.port });
            await connectWithTimeout(socket.opened, TIMEOUT_MS);
            if (early?.byteLength) await writeData(socket, early);
            return socket;
        }
        
        const pending = targets.map(t => tcpConnector({ hostname: t.hostname, port: t.port }));
        const result = await Promise.race(pending.map((p, idx) => p.then(socket => ({ socket, candidate: targets[idx] }))));
        
        for (const p of pending) {
            p.catch(() => {}).then(s => { if (s !== result.socket) try { s?.close?.(); } catch(e) {} });
        }
        
        await connectWithTimeout(result.socket.opened, TIMEOUT_MS);
        if (early?.byteLength) await writeData(result.socket, early);
        return result.socket;
    }
    
    async function connectDirect(early, useFallback = true) {
        if (useFallback && !earlySent && earlyData?.byteLength > 0) {
            const directTargets = [];
            for (let i = 0; i < TCP_CONCURRENT; i++) {
                directTargets.push({ hostname: host, port: port, attempt: i });
            }
            log("[TCP] Direct connecting to:", host, ":", port);
            return await tryConnect(directTargets, early);
        } else {
            const parsed = await parseProxyAddress(proxyIP, host, uuid);
            log("[TCP] Proxy connecting via:", parsed.length, "candidates");
            return await tryConnect(parsed, early);
        }
    }
    
    async function connectWithRetry(useEarly = true) {
        if (connection.connecting) {
            await connection.connecting;
            return;
        }
        
        const shouldUseEarly = useEarly && !earlySent && earlyData?.byteLength > 0;
        const early = shouldUseEarly ? earlyData : null;
        
        const connectPromise = (async () => {
            let socket;
            
            if (socks5Enabled === null) {
                log("[TCP] Direct connect to:", host, ":", port);
                socket = await connectDirect(early, fallbackEnabled);
            } else {
                const socksType = socks5Enabled;
                log(`[${socksType.toUpperCase()} Proxy] Connecting to:`, host, ":", port);
                
                if (socksType === "socks5") {
                    socket = await socks5Connect(host, port, early, tcpConnector);
                } else if (socksType === "http") {
                    socket = await httpConnect(host, port, early, false, tcpConnector);
                } else if (socksType === "https") {
                    socket = await httpsConnect(host, port, early, tcpConnector);
                } else if (socksType === "turn") {
                    socket = await turnConnect(parsedSocks5, host, port, tcpConnector);
                    if (early?.byteLength) {
                        const writer = socket.writable.getWriter();
                        try {
                            await writer.write(arrayToUint8(early));
                        } finally {
                            try { writer.releaseLock(); } catch(e) {}
                        }
                    }
                } else if (socksType === "sstp") {
                    socket = await sstpConnect(parsedSocks5, host, port, tcpConnector);
                    if (early?.byteLength) {
                        const writer = socket.writable.getWriter();
                        try {
                            await writer.write(arrayToUint8(early));
                        } finally {
                            try { writer.releaseLock(); } catch(e) {}
                        }
                    }
                } else {
                    log("[TCP] Direct (no proxy):", host, ":", port);
                    socket = await connectDirect(early, fallbackEnabled);
                }
            }
            
            if (shouldUseEarly) earlySent = true;
            connection.socket = socket;
            socket.closed.finally(() => closeSocketQuietly(ws));
            connectStreams(socket, ws, respHeader, null);
            return socket;
        })();
        
        connection.connecting = connectPromise;
        try {
            await connectPromise;
        } finally {
            if (connection.connecting === connectPromise) {
                connection.connecting = null;
            }
        }
    }
    
    connection.retry = async () => connectWithRetry(!earlySent);
    
    if (socks5Enabled && (socks5Global || whitelistDomains.some(pattern => {
        const regex = new RegExp("^" + pattern.replace(/\*/g, ".*") + "$", "i");
        return regex.test(host);
    }))) {
        log("[TCP] Using proxy due to whitelist match");
        try {
            await connectWithRetry();
        } catch(e) {
            log("[TCP] Proxy failed:", e?.message);
            throw e;
        }
    } else {
        try {
            log("[TCP] Direct attempt:", host, ":", port);
            const socket = await connectDirect(earlyData);
            connection.socket = socket;
            socket.closed.finally(() => closeSocketQuietly(ws));
            connectStreams(socket, ws, respHeader, async () => {
                if (connection.socket !== socket) return;
                await connectWithRetry();
            });
        } catch(e) {
            log("[TCP] Direct failed:", e?.message);
            await connectWithRetry();
        }
    }
}

// ========== Socket Helpers ==========
function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
            socket.close();
        }
    } catch(e) {}
}

async function webSocketSendAndWait(ws, data) {
    const result = ws.send(data);
    if (result && typeof result.then === "function") await result;
}

function connectStreams(source, dest, prefix, onEnd) {
    let hasData = false;
    let reader, writer;
    let writerMode = false;
    const CHUNK_SIZE = 16384;
    
    try {
        reader = source.readable.getReader({ mode: "byob" });
        writerMode = true;
    } catch(e) {
        reader = source.readable.getReader();
        writerMode = false;
    }
    
    let downstream = createDownstreamSender(dest, prefix);
    
    (async () => {
        try {
            if (!writerMode) {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (!value || value.byteLength === 0) continue;
                    hasData = true;
                    await downstream.send(value);
                }
            } else {
                let buffer = new ArrayBuffer(CHUNK_SIZE);
                while (true) {
                    const { done, value } = await reader.read(new Uint8Array(buffer, 0, CHUNK_SIZE));
                    if (done) break;
                    if (!value || value.byteLength === 0) continue;
                    hasData = true;
                    if (value.byteLength >= DOWNSTREAM_GRAIN) {
                        await downstream.flush();
                        await downstream.sendDirect(value);
                        buffer = new ArrayBuffer(CHUNK_SIZE);
                    } else {
                        await downstream.send(value);
                        buffer = value.byteLength >= CHUNK_SIZE ? value.buffer : new ArrayBuffer(CHUNK_SIZE);
                    }
                }
            }
            await downstream.flush();
        } catch(e) {
            closeSocketQuietly(dest);
        } finally {
            try { reader.releaseLock(); } catch(e) {}
            try { reader.cancel(); } catch(e) {}
        }
        if (!hasData && onEnd) await onEnd();
    })();
}

function createDownstreamSender(dest, prefix) {
    const GRAIN_SIZE = DOWNSTREAM_GRAIN;
    const THRESHOLD = DOWNSTREAM_THRESHOLD;
    
    let pendingPrefix = prefix;
    let buffer = new Uint8Array(GRAIN_SIZE);
    let bufferSize = 0;
    let flushTimer = null;
    let isFlushing = false;
    let lastWriteSeq = 0;
    let writeSeq = 0;
    let pendingFlush = null;
    
    const withPrefix = (data) => {
        if (!pendingPrefix) return data;
        const result = new Uint8Array(pendingPrefix.byteLength + data.byteLength);
        result.set(pendingPrefix, 0);
        result.set(data, pendingPrefix.byteLength);
        pendingPrefix = null;
        return result;
    };
    
    const doFlush = async () => {
        if (flushTimer) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }
        if (isFlushing) return;
        if (!bufferSize) return;
        
        const data = buffer.subarray(0, bufferSize);
        buffer = new Uint8Array(GRAIN_SIZE);
        bufferSize = 0;
        writeSeq++;
        const currentSeq = writeSeq;
        
        isFlushing = true;
        try {
            await webSocketSendAndWait(dest, withPrefix(data));
        } finally {
            isFlushing = false;
            if (pendingFlush && currentSeq === pendingFlush.seq) {
                const resolve = pendingFlush.resolve;
                pendingFlush = null;
                resolve();
            }
        }
    };
    
    const scheduleFlush = () => {
        if (flushTimer || isFlushing) return;
        isFlushing = true;
        queueMicrotask(() => {
            isFlushing = false;
            if (bufferSize === 0 || flushTimer) return;
            flushTimer = setTimeout(doFlush, Math.max(DOWNSTREAM_SILENT_MS, 1));
        });
    };
    
    return {
        async send(data) {
            let bytes = arrayToUint8(data);
            if (!bytes.byteLength) return;
            bytes = withPrefix(bytes);
            
            let offset = 0;
            const total = bytes.byteLength;
            
            while (offset < total) {
                if (bufferSize === 0 && total - offset >= GRAIN_SIZE) {
                    const chunkSize = Math.min(GRAIN_SIZE, total - offset);
                    const chunk = offset === 0 && chunkSize === total ? bytes : bytes.subarray(offset, offset + chunkSize);
                    await webSocketSendAndWait(dest, chunk);
                    offset += chunkSize;
                    continue;
                }
                
                const copySize = Math.min(GRAIN_SIZE - bufferSize, total - offset);
                buffer.set(bytes.subarray(offset, offset + copySize), bufferSize);
                bufferSize += copySize;
                offset += copySize;
                lastWriteSeq++;
                
                if (bufferSize === GRAIN_SIZE || GRAIN_SIZE - bufferSize < THRESHOLD) {
                    await doFlush();
                } else {
                    scheduleFlush();
                }
            }
        },
        async sendDirect(data) {
            await doFlush();
            await webSocketSendAndWait(dest, withPrefix(arrayToUint8(data)));
        },
        async flush() {
            if (bufferSize === 0 && !isFlushing) return;
            if (!isFlushing && bufferSize > 0) {
                await doFlush();
                return;
            }
            await new Promise(resolve => {
                pendingFlush = { seq: writeSeq, resolve };
            });
        }
    };
}

// ========== Queue System ==========
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "Queue" }) {
    let queue = [];
    let queueSize = 0;
    let queueItems = 0;
    let isProcessing = false;
    let isClosed = false;
    let isFailed = false;
    let pendingCompletions = [];
    let pendingWrites = [];
    let currentWriter = null;
    
    const completeAll = (error = null) => {
        if (error) {
            for (const p of pendingCompletions) p.reject(error);
            for (const p of pendingWrites) p?.reject?.(error);
        } else {
            for (const p of pendingCompletions) p.resolve();
            for (const p of pendingWrites) p?.resolve?.();
        }
        pendingCompletions = [];
        pendingWrites = [];
    };
    
    const resetQueue = (error = null) => {
        if (error && !isFailed) {
            isFailed = true;
            completeAll(error);
        }
        queue = [];
        queueSize = 0;
        queueItems = 0;
        isProcessing = false;
        currentWriter = null;
    };
    
    const processQueue = async () => {
        if (isProcessing || isClosed || isFailed) return;
        isProcessing = true;
        
        try {
            while (!isClosed && !isFailed) {
                const item = getNextItem();
                if (!item) break;
                
                let writer = getWriter();
                if (!writer) {
                    throw new Error(`${name}: Remote writer not available`);
                }
                
                currentWriter = writer;
                const completions = item.completions || null;
                
                try {
                    try {
                        await writer.write(item.chunk);
                    } catch(e) {
                        releaseWriter?.();
                        if (!item.allowRetry || typeof retryConnect !== "function") throw e;
                        await retryConnect();
                        writer = getWriter();
                        if (!writer) throw e;
                        await writer.write(item.chunk);
                    }
                    if (completions) {
                        for (const c of completions) c.resolve();
                    }
                } catch(e) {
                    if (completions) {
                        for (const c of completions) c.reject(e);
                    }
                    throw e;
                } finally {
                    currentWriter = null;
                }
            }
        } catch(e) {
            isFailed = true;
            isClosed = true;
            resetQueue(e);
            log(`[${name}] Fatal error:`, e?.message || e);
            try { closeConnection?.(); } catch(e2) {}
        } finally {
            isProcessing = false;
            if (!isClosed && !isFailed && queue.length > 0) {
                queueMicrotask(processQueue);
            } else {
                flushPendingWrites();
            }
        }
    };
    
    const getNextItem = () => {
        if (queueItems === 0) return null;
        const item = queue[queueItems - 1];
        queueItems--;
        if (item.chunk.byteLength >= BUNDLE_TARGET || queueItems === 0) {
            return item;
        }
        
        let totalSize = item.chunk.byteLength;
        let combinedChunk = new Uint8Array(BUNDLE_TARGET);
        combinedChunk.set(item.chunk);
        let offset = item.chunk.byteLength;
        let allowRetry = item.allowRetry;
        let completions = item.completions ? [...item.completions] : null;
        
        while (queueItems > 0) {
            const next = queue[queueItems - 1];
            const newSize = totalSize + next.chunk.byteLength;
            if (newSize > BUNDLE_TARGET) break;
            totalSize = newSize;
            combinedChunk.set(next.chunk, offset);
            offset += next.chunk.byteLength;
            allowRetry = allowRetry && next.allowRetry;
            if (next.completions) {
                completions = completions ? completions.concat(next.completions) : next.completions;
            }
            queueItems--;
        }
        
        return {
            chunk: combinedChunk.subarray(0, totalSize),
            allowRetry: allowRetry,
            completions: completions
        };
    };
    
    const flushPendingWrites = () => {
        while (pendingWrites.length) {
            const w = pendingWrites.shift();
            w?.();
        }
    };
    
    const addToQueue = (chunk, allowRetry, withPromise) => {
        if (isClosed || isFailed) return false;
        
        const writer = getWriter();
        if (!writer) return false;
        
        const bytes = arrayToUint8(chunk);
        if (!bytes.byteLength) return true;
        
        const newSize = queueSize + bytes.byteLength;
        const newCount = queueItems + 1;
        
        if (newSize > QUEUE_MAX_BYTES || newCount > QUEUE_MAX_ITEMS) {
            isClosed = true;
            isFailed = true;
            const error = Object.assign(new Error(`${name}: Queue overflow (${newSize}B/${newCount})`), { isQueueOverflow: true });
            resetQueue(error);
            log(`[${name}] Queue overflow`);
            try { closeConnection?.(error); } catch(e) {}
            throw error;
        }
        
        let completions = null;
        let promise = null;
        
        if (withPromise) {
            completions = [];
            promise = new Promise((resolve, reject) => {
                completions.push({ resolve, reject });
            });
        }
        
        queue.unshift({ chunk: bytes, allowRetry, completions });
        queueSize = newSize;
        queueItems = newCount;
        
        if (!isProcessing) queueMicrotask(processQueue);
        
        if (withPromise) {
            return promise.then(() => true);
        }
        return true;
    };
    
    return {
        write(data, wait = false) {
            return addToQueue(data, false, wait);
        },
        writeAndWait(data, wait = false) {
            return addToQueue(data, wait, true);
        },
        async flush() {
            if (!queueSize && !isProcessing) return;
            await new Promise(resolve => {
                pendingWrites.push(resolve);
                if (!isProcessing && queueSize > 0) queueMicrotask(processQueue);
            });
        },
        clear() {
            isClosed = true;
            resetQueue();
        }
    };
}

// ========== Proxy Configuration ==========
async function loadProxyParams(url, uuid) {
    const params = url.searchParams;
    const pathname = decodeURIComponent(url.pathname);
    const pathLower = pathname.toLowerCase();
    
    const videoMatch = pathname.match(/\/video\/(.+)$/i);
    if (videoMatch) {
        try {
            const decoded = base64DecodeSecret(videoMatch[1], uuid);
            const { type, ...config } = JSON.parse(decoded);
            if (!type || !PROXY_DEFAULT_PORTS[String(type).toLowerCase()]) {
                throw new Error("Invalid proxy type");
            }
            if (!config.username || !config.password) {
                throw new Error("Missing auth credentials");
            }
            socks5Account = "";
            proxyIP = "direct";
            fallbackEnabled = false;
            socks5Global = true;
            socks5Enabled = String(type).toLowerCase();
            parsedSocks5 = {
                username: config.username,
                password: config.password,
                hostname: config.hostname,
                port: Number(config.port)
            };
            if (isNaN(parsedSocks5.port)) throw new Error("Invalid port");
            return;
        } catch(e) {
            console.error("Proxy decode error:", e.message);
        }
    }
    
    socks5Account = params.get("socks5") || params.get("http") || params.get("https") || params.get("socks") || params.get("proxy") || null;
    socks5Global = params.has("globalproxy");
    
    if (params.has("socks5")) socks5Enabled = "socks5";
    else if (params.has("http")) socks5Enabled = "http";
    else if (params.has("https")) socks5Enabled = "https";
    else if (params.has("turn")) socks5Enabled = "turn";
    else if (params.has("sstp")) socks5Enabled = "sstp";
    
    const inlineMatch = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathLower);
    if (inlineMatch) {
        const proto = inlineMatch[1].toLowerCase();
        socks5Enabled = proto === "sock" || proto === "socks" ? "socks5" : proto;
        socks5Account = inlineMatch[2].split("/")[0];
        socks5Global = true;
    }
    
    const paramMatch = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathLower);
    if (paramMatch) {
        const flag = paramMatch[1].toLowerCase();
        socks5Account = paramMatch[2].split("/")[0];
        if (flag.includes("g5") || flag === "gs5") socks5Enabled = "socks5";
        else if (flag.includes("http")) socks5Enabled = "http";
        else if (flag.includes("https")) socks5Enabled = "https";
        else if (flag.includes("turn")) socks5Enabled = "turn";
        else if (flag.includes("sstp")) socks5Enabled = "sstp";
        if (flag.startsWith("g")) socks5Global = true;
    }
    
    const ipMatch = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/i.exec(pathLower);
    if (ipMatch) {
        const ip = normalizeProxyIp(ipMatch[2]);
        if (!tryParseProxyUrl(ip, true)) {
            setProxyIp(ip);
        }
    }
    
    if (!socks5Account) {
        socks5Enabled = null;
        return;
    }
    
    try {
        parsedSocks5 = await parseSocks5Account(socks5Account, getDefaultProxyPort(socks5Enabled));
        if (params.has("socks5")) socks5Enabled = "socks5";
        else if (params.has("http")) socks5Enabled = "http";
        else if (params.has("https")) socks5Enabled = "https";
        else if (params.has("turn")) socks5Enabled = "turn";
        else if (params.has("sstp")) socks5Enabled = "sstp";
        else socks5Enabled = socks5Enabled || "direct";
    } catch(e) {
        console.error("SOCKS5 parse error:", e.message);
        socks5Enabled = null;
    }
}

function tryParseProxyUrl(url, isIpOnly = false) {
    const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(url || "");
    if (!match) return false;
    socks5Enabled = match[1].toLowerCase();
    socks5Account = match[2].split("/")[0];
    if (isIpOnly) socks5Global = true;
    return true;
}

function setProxyIp(ip) {
    proxyIP = ip;
    socks5Enabled = null;
    fallbackEnabled = false;
}

function normalizeProxyIp(ip) {
    if (!ip.includes("://")) {
        const slashIndex = ip.indexOf("/");
        return slashIndex > 0 ? ip.slice(0, slashIndex) : ip;
    }
    const parts = ip.split("://");
    if (parts.length !== 2) return ip;
    const slashIndex = parts[1].indexOf("/");
    return slashIndex > 0 ? parts[0] + "://" + parts[1].slice(0, slashIndex) : ip;
}

const PROXY_DEFAULT_PORTS = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };

function getDefaultProxyPort(protocol) {
    return PROXY_DEFAULT_PORTS[String(protocol || "").toLowerCase()] || 80;
}

const SOCKS5_BASE64_REGEX = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
const IPV6_BRACKET_REGEX = /^\[.*\]$/;

async function parseSocks5Account(account, defaultPort = 80) {
    let cleaned = String(account || "").trim().toLowerCase();
    cleaned = cleaned.replace(/^(socks5|http|https|turn|sstp):\/\//i, "");
    cleaned = cleaned.split("#")[0].trim();
    
    const atIndex = cleaned.indexOf("@");
    if (atIndex !== -1) {
        let authPart = cleaned.slice(0, atIndex).replace(/=+$/, "");
        if (!authPart.includes(":") && SOCKS5_BASE64_REGEX.test(authPart)) {
            authPart = atob(authPart);
        }
        cleaned = authPart + "@" + cleaned.slice(atIndex + 1);
    }
    
    const lastAtIndex = cleaned.lastIndexOf("@");
    const hostPart = lastAtIndex === -1 ? cleaned : cleaned.slice(lastAtIndex + 1);
    const authPart = lastAtIndex === -1 ? "" : cleaned.slice(0, lastAtIndex);
    const hostCleaned = hostPart.split("/")[0];
    
    const [username, password] = authPart ? authPart.split(":") : [];
    if (authPart && !password) {
        throw new Error("Invalid SOCKS5 account format (missing password)");
    }
    
    let hostname = hostCleaned;
    let port = defaultPort;
    
    if (hostCleaned.includes("]:")) {
        const [hostWithBracket, portStr = ""] = hostCleaned.split("]:");
        hostname = hostWithBracket + "]";
        port = Number(portStr.replace(/[^\d]/g, "")) || port;
    } else if (!hostCleaned.startsWith("[")) {
        const parts = hostCleaned.split(":");
        if (parts.length === 2) {
            hostname = parts[0];
            port = Number(parts[1].replace(/[^\d]/g, "")) || port;
        }
    }
    
    if (isNaN(port)) throw new Error("Port must be a number");
    if (hostname.includes(":") && !IPV6_BRACKET_REGEX.test(hostname)) {
        throw new Error("Invalid SOCKS5 address, use [ipv6]:port format");
    }
    
    return { username, password, hostname, port };
}

// ========== SOCKS5 Connect ==========
async function socks5Connect(host, port, earlyData, connector) {
    const { username, password, hostname: proxyHost, port: proxyPort } = parsedSocks5;
    const socket = connector({ hostname: proxyHost, port: proxyPort });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethod = username && password ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
        await writer.write(authMethod);
        
        let result = await reader.read();
        if (result.done || result.value?.byteLength < 2) {
            throw new Error("SOCKS5 auth negotiation failed");
        }
        const method = new Uint8Array(result.value)[1];
        
        if (method === 2) {
            if (!username || !password) throw new Error("SOCKS5 requires username/password");
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authMsg = new Uint8Array([1, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
            await writer.write(authMsg);
            result = await reader.read();
            if (result.done || new Uint8Array(result.value)[1] !== 0) {
                throw new Error("SOCKS5 authentication failed");
            }
        } else if (method !== 0) {
            throw new Error(`SOCKS5 unsupported auth method: ${method}`);
        }
        
        const hostBytes = new TextEncoder().encode(host);
        const connectMsg = new Uint8Array([5, 1, 0, 3, hostBytes.length, ...hostBytes, port >> 8, port & 0xFF]);
        await writer.write(connectMsg);
        result = await reader.read();
        
        if (result.done || new Uint8Array(result.value)[1] !== 0) {
            throw new Error("SOCKS5 connection failed");
        }
        
        if (earlyData?.byteLength) await writer.write(earlyData);
        
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch(e) {
        try { writer.releaseLock(); } catch(e2) {}
        try { reader.releaseLock(); } catch(e2) {}
        try { socket.close(); } catch(e2) {}
        throw e;
    }
}

// ========== HTTP Connect ==========
async function httpConnect(host, port, earlyData, isHttps = false, connector) {
    const { username, password, hostname: proxyHost, port: proxyPort } = parsedSocks5;
    const socket = isHttps ? connector({ hostname: proxyHost, port: proxyPort }, { secureTransport: "on", allowHalfOpen: false }) : connector({ hostname: proxyHost, port: proxyPort });
    
    if (isHttps) await socket.opened;
    
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(username + ":" + password)}\r\n` : "";
        const request = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}Connection: keep-alive\r\n\r\n`;
        await writer.write(encoder.encode(request));
        writer.releaseLock();
        
        let response = new Uint8Array(0);
        let headerEnd = -1;
        let attempts = 0;
        
        while (headerEnd === -1 && attempts < 8192) {
            const { done, value } = await reader.read();
            if (done || !value) throw new Error("HTTP proxy connection closed");
            response = concatBuffers(response, value);
            attempts = response.byteLength;
            
            for (let i = 0; i < response.byteLength - 3; i++) {
                if (response[i] === 13 && response[i+1] === 10 && response[i+2] === 13 && response[i+3] === 10) {
                    headerEnd = i + 4;
                    break;
                }
            }
        }
        
        if (headerEnd === -1) throw new Error("HTTP proxy invalid response");
        
        const statusLine = decoder.decode(response.subarray(0, headerEnd)).split("\r\n")[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
        
        if (isNaN(statusCode) || statusCode < 200 || statusCode >= 300) {
            throw new Error(`HTTP proxy returned ${statusCode}`);
        }
        
        reader.releaseLock();
        
        if (earlyData?.byteLength) {
            const earlyWriter = socket.writable.getWriter();
            try {
                await earlyWriter.write(earlyData);
            } finally {
                earlyWriter.releaseLock();
            }
        }
        
        if (response.byteLength > headerEnd) {
            const { readable, writable } = new TransformStream();
            const leftoverWriter = writable.getWriter();
            await leftoverWriter.write(response.subarray(headerEnd));
            leftoverWriter.releaseLock();
            socket.readable.pipeTo(writable).catch(() => {});
            return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
        }
        
        return socket;
    } catch(e) {
        try { writer.releaseLock(); } catch(e2) {}
        try { reader.releaseLock(); } catch(e2) {}
        try { socket.close(); } catch(e2) {}
        throw e;
    }
}

// ========== HTTPS Connect ==========
async function httpsConnect(host, port, earlyData, connector) {
    const { username, password, hostname: proxyHost, port: proxyPort } = parsedSocks5;
    const rawSocket = connector({ hostname: proxyHost, port: proxyPort });
    await rawSocket.opened;
    
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const proxyHostCleaned = stripIPv6Brackets(proxyHost);
    
    const tlsSocket = new TlsClient(rawSocket, {
        serverName: proxyHostCleaned,
        insecure: true,
        allowChacha: false
    });
    
    await tlsSocket.handshake();
    
    const writer = tlsSocket.writable.getWriter();
    const reader = tlsSocket.readable.getReader();
    
    try {
        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(username + ":" + password)}\r\n` : "";
        const request = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}Connection: keep-alive\r\n\r\n`;
        await writer.write(encoder.encode(request));
        
        let response = new Uint8Array(0);
        let headerEnd = -1;
        let attempts = 0;
        
        while (headerEnd === -1 && attempts < 8192) {
            const chunk = await reader.read();
            if (!chunk) throw new Error("HTTPS proxy no response");
            response = concatBuffers(response, chunk);
            attempts = response.byteLength;
            
            for (let i = 0; i < response.byteLength - 3; i++) {
                if (response[i] === 13 && response[i+1] === 10 && response[i+2] === 13 && response[i+3] === 10) {
                    headerEnd = i + 4;
                    break;
                }
            }
        }
        
        if (headerEnd === -1) throw new Error("HTTPS proxy invalid response");
        
        const statusLine = decoder.decode(response.subarray(0, headerEnd)).split("\r\n")[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
        
        if (isNaN(statusCode) || statusCode < 200 || statusCode >= 300) {
            throw new Error(`HTTPS proxy returned ${statusCode}`);
        }
        
        if (earlyData?.byteLength) {
            await tlsSocket.write(earlyData);
        }
        
        const remaining = response.byteLength > headerEnd ? response.subarray(headerEnd) : null;
        
        let isClosed = false;
        let resolveClosed, rejectClosed;
        const closedPromise = new Promise((resolve, reject) => { resolveClosed = resolve; rejectClosed = reject; });
        
        const readable = new ReadableStream({
            start(controller) {
                if (remaining?.byteLength) controller.enqueue(remaining);
                (async () => {
                    try {
                        while (true) {
                            const chunk = await tlsSocket.read();
                            if (!chunk) break;
                            if (chunk.byteLength > 0) controller.enqueue(chunk);
                        }
                        controller.close();
                        resolveClosed();
                    } catch(e) {
                        controller.error(e);
                        rejectClosed(e);
                    }
                })();
            },
            cancel() {
                isClosed = true;
                tlsSocket.close();
                resolveClosed();
            }
        });
        
        const writable = new WritableStream({
            async write(chunk) {
                await tlsSocket.write(chunk);
            },
            close() {
                tlsSocket.close();
                resolveClosed();
            },
            abort(e) {
                tlsSocket.close();
                rejectClosed(e);
            }
        });
        
        return { readable, writable, closed: closedPromise, close: () => tlsSocket.close() };
    } catch(e) {
        try { writer.releaseLock(); } catch(e2) {}
        try { reader.releaseLock(); } catch(e2) {}
        try { tlsSocket.close(); } catch(e2) {}
        throw e;
    }
}

// ========== TURN Connect ==========
async function turnConnect(config, targetHost, targetPort, connector) {
    const { username, password, hostname: turnHost, port: turnPort } = config;
    const strippedTarget = stripIPv6Brackets(targetHost);
    
    let targetIP = null;
    if (isIPv4(strippedTarget)) {
        targetIP = strippedTarget;
    } else {
        const dnsResult = await dohQuery(strippedTarget, "A");
        const ipv4 = dnsResult.find(r => r.type === 1 && isIPv4(r.data));
        targetIP = typeof ipv4?.data === "string" ? ipv4.data : null;
    }
    
    if (!targetIP) throw new Error(`Cannot resolve ${targetHost} to IPv4`);
    
    const controlSocket = connector({ hostname: turnHost, port: turnPort });
    await controlSocket.opened;
    
    let controlWriter = controlSocket.writable.getWriter();
    let controlReader = controlSocket.readable.getReader();
    let dataSocket = null;
    let dataWriter = null;
    let dataReader = null;
    let isClosed = false;
    let authKey = null;
    let nonce = null;
    let realm = null;
    let extraAttributes = [];
    
    const closeAll = () => {
        if (isClosed) return;
        isClosed = true;
        try { controlWriter?.releaseLock(); } catch(e) {}
        try { controlReader?.releaseLock(); } catch(e) {}
        try { dataWriter?.releaseLock(); } catch(e) {}
        try { dataReader?.releaseLock(); } catch(e) {}
        try { controlSocket.close(); } catch(e) {}
        try { dataSocket?.close(); } catch(e) {}
    };
    
    const sendStun = async (writer, type, transactionId, attributes = []) => {
        const attrData = [];
        for (const attr of attributes) {
            const attrBytes = createStunAttribute(attr.type, attr.value);
            attrData.push(attrBytes);
        }
        const message = createStunMessage(type, transactionId, attrData);
        await writer.write(message);
    };
    
    const readStun = async (reader, timeoutMsg) => {
        let buffer = new Uint8Array(0);
        while (buffer.byteLength < 20) {
            const { done, value } = await withTimeout(reader.read(), 10000, timeoutMsg);
            if (done) throw new Error("TURN server closed");
            if (value?.byteLength) buffer = concatBuffers(buffer, value);
        }
        
        const totalLen = 20 + ((buffer[2] << 8) | buffer[3]);
        if (totalLen > 65555) throw new Error("TURN message too large");
        
        while (buffer.byteLength < totalLen) {
            const { done, value } = await withTimeout(reader.read(), 10000, timeoutMsg);
            if (done) throw new Error("TURN server closed");
            if (value?.byteLength) buffer = concatBuffers(buffer, value);
        }
        
        const message = buffer.subarray(0, totalLen);
        const magicCookie = message.subarray(4, 8);
        for (let i = 0; i < 4; i++) {
            if (magicCookie[i] !== TURN_STUN_MAGIC_COOKIE[i]) {
                throw new Error("Invalid STUN magic cookie");
            }
        }
        
        const attributes = {};
        let pos = 20;
        while (pos + 4 <= totalLen) {
            const attrType = (message[pos] << 8) | message[pos + 1];
            const attrLen = (message[pos + 2] << 8) | message[pos + 3];
            if (pos + 4 + attrLen > totalLen) break;
            attributes[attrType] = message.subarray(pos + 4, pos + 4 + attrLen);
            pos += 4 + attrLen + ((4 - (attrLen % 4)) % 4);
        }
        
        return { type: (message[0] << 8) | message[1], attributes, extra: buffer.subarray(totalLen) };
    };
    
    const addIntegrity = async (msg) => {
        if (!authKey) return msg;
        const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
        view.setUint16(2, view.getUint16(2) + 20);
        const key = await crypto.subtle.importKey("raw", authKey, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", key, msg);
        return concatBuffers(msg, createStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
    };
    
    try {
        const transactionId = randomTurnTransactionId();
        const transportAttr = createStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, new Uint8Array([6, 0, 0, 0]));
        await sendStun(controlWriter, TURN_STUN_TYPE.ALLOCATE_REQUEST, transactionId, [transportAttr]);
        
        let response = await readStun(controlReader, "TURN Allocate request timeout");
        
        if (response.type === TURN_STUN_TYPE.ALLOCATE_ERROR_RESPONSE && response.attributes[TURN_STUN_ATTR.ERROR_CODE]) {
            const errorCode = parseTurnErrorCode(response.attributes[TURN_STUN_ATTR.ERROR_CODE]);
            if (errorCode === 401 && username && password) {
                const realmAttr = response.attributes[TURN_STUN_ATTR.REALM];
                const nonceAttr = response.attributes[TURN_STUN_ATTR.NONCE];
                if (!realmAttr || !nonceAttr?.byteLength) throw new Error("TURN auth missing realm/nonce");
                
                realm = new TextDecoder().decode(realmAttr);
                nonce = nonceAttr;
                const credentials = `${username}:${realm}:${password}`;
                const keyMaterial = new TextEncoder().encode(credentials);
                authKey = md5Core(keyMaterial);
                
                const usernameAttr = createStunAttribute(TURN_STUN_ATTR.USERNAME, new TextEncoder().encode(username));
                const realmAttr2 = createStunAttribute(TURN_STUN_ATTR.REALM, new TextEncoder().encode(realm));
                const nonceAttr2 = createStunAttribute(TURN_STUN_ATTR.NONCE, nonce);
                extraAttributes = [usernameAttr, realmAttr2, nonceAttr2];
                
                const newTransactionId = randomTurnTransactionId();
                const authMsg = await addIntegrity(createStunMessage(TURN_STUN_TYPE.ALLOCATE_REQUEST, newTransactionId, [transportAttr, usernameAttr, realmAttr2, nonceAttr2]));
                await controlWriter.write(authMsg);
                response = await readStun(controlReader, "TURN Allocate (auth) timeout");
            }
        }
        
        if (response.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS_RESPONSE) {
            const errCode = parseTurnErrorCode(response.attributes[TURN_STUN_ATTR.ERROR_CODE]);
            throw new Error(`TURN allocate failed: ${errCode || "unknown"}`);
        }
        
        const peerIPBytes = targetIP.split(".").map(n => Number(n) ^ TURN_STUN_MAGIC_COOKIE[n]);
        const xorPeerAddr = new Uint8Array(8);
        xorPeerAddr[1] = 1;
        xorPeerAddr[2] = targetPort ^ 0x2112;
        xorPeerAddr.set(peerIPBytes, 4);
        const xorPeerAttr = createStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddr);
        
        const permTransId = randomTurnTransactionId();
        const permMsg = await addIntegrity(createStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, permTransId, [xorPeerAttr, ...extraAttributes]));
        await controlWriter.write(permMsg);
        const permResp = await readStun(controlReader, "TURN permission timeout");
        if (permResp.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS_RESPONSE) {
            throw new Error("TURN create permission failed");
        }
        
        const connectTransId = randomTurnTransactionId();
        const connectMsg = await addIntegrity(createStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, connectTransId, [xorPeerAttr, ...extraAttributes]));
        await controlWriter.write(connectMsg);
        const connectResp = await readStun(controlReader, "TURN connect timeout");
        if (connectResp.type !== TURN_STUN_TYPE.CONNECT_SUCCESS_RESPONSE) {
            throw new Error("TURN connect failed");
        }
        
        const connectionIdAttr = connectResp.attributes[TURN_STUN_ATTR.CONNECTION_ID];
        if (!connectionIdAttr?.byteLength) throw new Error("TURN connect missing connection ID");
        const connectionId = connectionIdAttr;
        
        dataSocket = connector({ hostname: turnHost, port: turnPort });
        await dataSocket.opened;
        dataWriter = dataSocket.writable.getWriter();
        dataReader = dataSocket.readable.getReader();
        
        const bindTransId = randomTurnTransactionId();
        const bindMsg = await addIntegrity(createStunMessage(TURN_STUN_TYPE.CONNECTION_BIND_REQUEST, bindTransId, [
            createStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, connectionId),
            ...extraAttributes
        ]));
        await dataWriter.write(bindMsg);
        const bindResp = await readStun(dataReader, "TURN connection bind timeout");
        if (bindResp.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS_RESPONSE) {
            throw new Error("TURN connection bind failed");
        }
        
        controlWriter.releaseLock();
        controlReader.releaseLock();
        controlWriter = null;
        controlReader = null;
        
        const readable = new ReadableStream({
            start(controller) {
                if (bindResp.extra?.byteLength) controller.enqueue(bindResp.extra);
                (async () => {
                    try {
                        while (true) {
                            const { done, value } = await dataReader.read();
                            if (done) break;
                            if (value?.byteLength) controller.enqueue(new Uint8Array(value));
                        }
                        controller.close();
                    } catch(e) {
                        controller.error(e);
                    } finally {
                        closeAll();
                    }
                })();
            },
            cancel() {
                closeAll();
            }
        });
        
        const writable = new WritableStream({
            async write(chunk) {
                await dataWriter.write(arrayToUint8(chunk));
            },
            close() {
                closeAll();
            },
            abort() {
                closeAll();
            }
        });
        
        return { readable, writable, closed: dataSocket.closed, close: closeAll };
    } catch(e) {
        closeAll();
        throw e;
    }
}

// ========== TURN Constants ==========
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const TURN_STUN_TYPE = {
    ALLOCATE_REQUEST: 0x0003,
    ALLOCATE_SUCCESS_RESPONSE: 0x0103,
    ALLOCATE_ERROR_RESPONSE: 0x0113,
    CREATE_PERMISSION_REQUEST: 0x0008,
    CREATE_PERMISSION_SUCCESS_RESPONSE: 0x0108,
    CONNECT_REQUEST: 0x000A,
    CONNECT_SUCCESS_RESPONSE: 0x010A,
    CONNECTION_BIND_REQUEST: 0x000B,
    CONNECTION_BIND_SUCCESS_RESPONSE: 0x010B
};
const TURN_STUN_ATTR = {
    USERNAME: 0x0006,
    MESSAGE_INTEGRITY: 0x0008,
    ERROR_CODE: 0x0009,
    XOR_PEER_ADDRESS: 0x0012,
    REALM: 0x0014,
    NONCE: 0x0015,
    REQUESTED_TRANSPORT: 0x0019,
    CONNECTION_ID: 0x002A
};

function createStunAttribute(type, value) {
    const valueBytes = arrayToUint8(value);
    const padding = (4 - (valueBytes.byteLength % 4)) % 4;
    const result = new Uint8Array(4 + valueBytes.byteLength + padding);
    const view = new DataView(result.buffer);
    view.setUint16(0, type);
    view.setUint16(2, valueBytes.byteLength);
    result.set(valueBytes, 4);
    return result;
}

function createStunMessage(type, transactionId, attributes) {
    const attrData = concatBuffers(...attributes);
    const result = new Uint8Array(20 + attrData.byteLength);
    const view = new DataView(result.buffer);
    view.setUint16(0, type);
    view.setUint16(2, attrData.byteLength);
    result.set(TURN_STUN_MAGIC_COOKIE, 4);
    result.set(transactionId, 8);
    result.set(attrData, 20);
    return result;
}

function parseTurnErrorCode(attr) {
    if (!attr?.byteLength) return 0;
    const classCode = attr[2] & 0x07;
    const number = attr[3];
    return classCode * 100 + number;
}

function randomTurnTransactionId() {
    return crypto.getRandomValues(new Uint8Array(12));
}

async function withTimeout(promise, ms, errorMsg) {
    let timer;
    try {
        return await Promise.race([
            promise,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error(errorMsg)), ms);
            })
        ]);
    } finally {
        clearTimeout(timer);
    }
}

// ========== SSTP Connect ==========
async function sstpConnect(config, targetHost, targetPort, connector) {
    const { username, password, hostname: sstpHost, port: sstpPort } = config;
    const strippedHost = stripIPv6Brackets(sstpHost);
    
    let targetIP = null;
    if (isIPv4(strippedHost)) {
        targetIP = strippedHost;
    } else {
        const dnsResult = await dohQuery(strippedHost, "A");
        const ipv4 = dnsResult.find(r => r.type === 1 && isIPv4(r.data));
        targetIP = typeof ipv4?.data === "string" ? ipv4.data : null;
    }
    
    if (!targetIP) throw new Error(`Cannot resolve ${sstpHost} to IPv4`);
    
    const rawSocket = connector({ hostname: sstpHost, port: sstpPort }, { secureTransport: "on", allowHalfOpen: false });
    await rawSocket.opened;
    
    const writer = rawSocket.writable.getWriter();
    const reader = rawSocket.readable.getReader();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    
    let buffer = new Uint8Array(0);
    let callId = 1;
    let sequence = 0;
    
    const readLine = async () => {
        while (true) {
            const newlinePos = buffer.indexOf(10);
            if (newlinePos >= 0) {
                const line = decoder.decode(buffer.subarray(0, newlinePos));
                buffer = buffer.subarray(newlinePos + 1);
                return line.replace(/\r$/, "");
            }
            const { done, value } = await reader.read();
            if (done) throw new Error("SSTP connection closed");
            if (value?.byteLength) buffer = concatBuffers(buffer, value);
        }
    };
    
    const readBytes = async (len) => {
        while (buffer.byteLength < len) {
            const { done, value } = await reader.read();
            if (done) throw new Error("SSTP connection closed");
            if (value?.byteLength) buffer = concatBuffers(buffer, value);
        }
        const data = buffer.subarray(0, len);
        buffer = buffer.subarray(len);
        return data;
    };
    
    try {
        const hostForHeader = strippedHost.includes(":") ? `[${strippedHost}]` : strippedHost;
        const request = `CONNECT ${hostForHeader}:${sstpPort} HTTP/1.1\r\nHost: ${hostForHeader}:${sstpPort}\r\n\r\n`;
        await writer.write(encoder.encode(request));
        
        let response = await readLine();
        if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(response)) {
            throw new Error(`SSTP HTTP error: ${response}`);
        }
        
        while (true) {
            const line = await readLine();
            if (line === "") break;
        }
        
        const callIdBytes = new Uint8Array(2);
        new DataView(callIdBytes.buffer).setUint16(0, callId++);
        
        const magic = new Uint8Array([0x10, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]);
        const attrData = concatBuffers(callIdBytes, new Uint8Array([0x00, 0x00]));
        const sstpPacket = concatBuffers(magic, new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), attrData);
        await writer.write(sstpPacket);
        
        const respHeader = await readBytes(8);
        if (respHeader[0] !== 0x10) throw new Error("Invalid SSTP response");
        const respLen = ((respHeader[2] & 0x0F) << 8) | respHeader[3];
        await readBytes(respLen - 8);
        
        const configReq = new Uint8Array([0x01, 0x00, 0x00, 0x04]);
        await writer.write(createSstpPacket(0xC021, 0x01, callId++, configReq));
        
        const lcpResp = await readSstpPacket(reader);
        if (lcpResp.protocol !== 0xC021) throw new Error("Invalid LCP response");
        
        if (username && password) {
            const userBytes = encoder.encode(username);
            const passBytes = encoder.encode(password);
            const authPacket = new Uint8Array(6 + userBytes.length + passBytes.length);
            authPacket[0] = 0xC0;
            authPacket[1] = 0x23;
            authPacket[2] = 0x01;
            authPacket[3] = callId++;
            new DataView(authPacket.buffer).setUint16(4, 6 + userBytes.length + passBytes.length);
            authPacket[6] = userBytes.length;
            authPacket.set(userBytes, 7);
            authPacket[7 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 8 + userBytes.length);
            await writer.write(createSstpPacket(0xC023, 0x01, callId++, authPacket));
            
            const authResp = await readSstpPacket(reader);
            if (authResp.protocol !== 0xC023 || authResp.code !== 0x02) {
                throw new Error("SSTP authentication failed");
            }
        }
        
        const ipcpReq = new Uint8Array([
            0x80, 0x21, 0x01, 0x00, 0x00, 0x0A,
            0x03, 0x06, 0x00, 0x00, 0x00, 0x00
        ]);
        await writer.write(createSstpPacket(0x8021, 0x01, callId++, ipcpReq));
        
        const ipcpResp = await readSstpPacket(reader);
        if (ipcpResp.protocol !== 0x8021) throw new Error("Invalid IPCP response");
        
        let clientIP = null;
        for (let i = 0; i < ipcpResp.payload.byteLength - 4; i++) {
            if (ipcpResp.payload[i] === 0x03 && ipcpResp.payload[i+1] === 0x06) {
                clientIP = `${ipcpResp.payload[i+2]}.${ipcpResp.payload[i+3]}.${ipcpResp.payload[i+4]}.${ipcpResp.payload[i+5]}`;
                break;
            }
        }
        
        if (!clientIP) throw new Error("Could not get client IP from SSTP");
        
        const targetCleaned = stripIPv6Brackets(targetHost);
        let targetIPAddr = null;
        if (isIPv4(targetCleaned)) {
            targetIPAddr = targetCleaned;
        } else {
            const dnsResult = await dohQuery(targetCleaned, "A");
            const ipv4 = dnsResult.find(r => r.type === 1 && isIPv4(r.data));
            targetIPAddr = typeof ipv4?.data === "string" ? ipv4.data : null;
        }
        
        if (!targetIPAddr) throw new Error(`Cannot resolve ${targetHost} to IPv4`);
        
        const srcIP = clientIP.split(".").map(Number);
        const dstIP = targetIPAddr.split(".").map(Number);
        const randomID = crypto.getRandomValues(new Uint16Array(1))[0];
        
        const tcpHeader = new Uint8Array(20);
        tcpHeader[0] = 0x45;
        tcpHeader[1] = 0x00;
        tcpHeader[8] = 0x40;
        tcpHeader[9] = 0x06;
        tcpHeader.set(srcIP, 12);
        tcpHeader.set(dstIP, 16);
        
        const pseudoHeader = new Uint8Array(12);
        pseudoHeader.set(srcIP, 0);
        pseudoHeader.set(dstIP, 4);
        pseudoHeader[9] = 0x06;
        
        const tcpPayload = new Uint8Array([
            0x00, 0x00, targetPort >> 8, targetPort & 0xFF,
            (randomID >> 8) & 0xFF, randomID & 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        
        const fullPacket = concatBuffers(tcpHeader, tcpPayload);
        const checksum = internetChecksum(concatBuffers(pseudoHeader, fullPacket));
        fullPacket[16] = (checksum >> 8) & 0xFF;
        fullPacket[17] = checksum & 0xFF;
        
        await writer.write(createSstpPacket(0x0021, 0x00, callId++, fullPacket));
        
        const readable = new ReadableStream({
            start(controller) {
                (async () => {
                    try {
                        while (true) {
                            const packet = await readSstpPacket(reader);
                            if (packet.protocol === 0x0021) {
                                const ipHeaderLen = (packet.payload[0] & 0x0F) * 4;
                                const tcpHeaderLen = ((packet.payload[ipHeaderLen + 12] >> 4) & 0x0F) * 4;
                                const dataStart = ipHeaderLen + tcpHeaderLen;
                                if (packet.payload.byteLength > dataStart) {
                                    controller.enqueue(packet.payload.subarray(dataStart));
                                }
                            } else if (packet.protocol === 0x0021 && (packet.payload[13] & 0x01)) {
                                break;
                            }
                        }
                        controller.close();
                    } catch(e) {
                        controller.error(e);
                    }
                })();
            },
            cancel() {
                rawSocket.close();
            }
        });
        
        const writable = new WritableStream({
            async write(chunk) {
                const bytes = arrayToUint8(chunk);
                if (!bytes.byteLength) return;
                
                const mss = 1400;
                for (let i = 0; i < bytes.byteLength; i += mss) {
                    const fragment = bytes.subarray(i, Math.min(i + mss, bytes.byteLength));
                    await writer.write(createSstpPacket(0x0021, 0x18, callId++, fragment));
                    sequence++;
                }
            },
            close() {
                rawSocket.close();
            }
        });
        
        return { readable, writable, closed: rawSocket.closed, close: () => rawSocket.close() };
    } catch(e) {
        try { writer.releaseLock(); } catch(e2) {}
        try { reader.releaseLock(); } catch(e2) {}
        try { rawSocket.close(); } catch(e2) {}
        throw e;
    }
}

function createSstpPacket(protocol, flags, callId, payload) {
    const payloadBytes = arrayToUint8(payload);
    const totalLen = 8 + payloadBytes.byteLength;
    const packet = new Uint8Array(totalLen);
    const view = new DataView(packet.buffer);
    packet[0] = 0x10;
    packet[1] = 0x00;
    packet[2] = 0x80 | ((totalLen >> 8) & 0x0F);
    packet[3] = totalLen & 0xFF;
    view.setUint16(4, protocol);
    packet[6] = flags;
    packet[7] = callId;
    packet.set(payloadBytes, 8);
    return packet;
}

async function readSstpPacket(reader) {
    const header = await readBytesExact(reader, 8);
    const totalLen = ((header[2] & 0x0F) << 8) | header[3];
    const payload = totalLen > 8 ? await readBytesExact(reader, totalLen - 8) : new Uint8Array(0);
    return {
        protocol: (header[4] << 8) | header[5],
        flags: header[6],
        callId: header[7],
        payload
    };
}

async function readBytesExact(reader, len) {
    let buffer = new Uint8Array(0);
    while (buffer.byteLength < len) {
        const { done, value } = await reader.read();
        if (done) throw new Error("Stream ended");
        if (value?.byteLength) buffer = concatBuffers(buffer, value);
    }
    return buffer.subarray(0, len);
}

function internetChecksum(data, offset = 0, length = data.byteLength) {
    let sum = 0;
    for (let i = offset; i < offset + length - 1; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    if (length & 1) sum += data[offset + length - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum & 0xFFFF;
}

// ========== TLS Client ==========
const TLS_VERSION_10 = 0x0301;
const TLS_VERSION_12 = 0x0303;
const TLS_VERSION_13 = 0x0304;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
const CONTENT_TYPE_ALERT = 0x15;
const CONTENT_TYPE_HANDSHAKE = 0x16;
const CONTENT_TYPE_APPLICATION_DATA = 0x17;
const HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
const HANDSHAKE_TYPE_SERVER_HELLO = 0x02;
const HANDSHAKE_TYPE_NEW_SESSION_TICKET = 0x04;
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08;
const HANDSHAKE_TYPE_CERTIFICATE = 0x0B;
const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0C;
const HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0D;
const HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0E;
const HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F;
const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 0x10;
const HANDSHAKE_TYPE_FINISHED = 0x14;
const HANDSHAKE_TYPE_KEY_UPDATE = 0x18;
const EXT_SERVER_NAME = 0x0000;
const EXT_SUPPORTED_GROUPS = 0x000A;
const EXT_EC_POINT_FORMATS = 0x000B;
const EXT_SIGNATURE_ALGORITHMS = 0x000D;
const EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010;
const EXT_SUPPORTED_VERSIONS = 0x002B;
const EXT_PSK_KEY_EXCHANGE_MODES = 0x002D;
const EXT_KEY_SHARE = 0x0033;
const ALERT_CLOSE_NOTIFY = 0x00;
const ALERT_LEVEL_WARNING = 0x01;
const ALERT_UNRECOGNIZED_NAME = 0x70;

const CIPHER_SUITES = new Map([
    [0x1301, { keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: true }],
    [0x1302, { keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: true }],
    [0x1303, { keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: true, chacha: true }],
    [0xC02F, { keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
    [0xC030, { keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
    [0xCCA8, { keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: true }],
]);

const GROUPS = new Map([[0x1D, "X25519"], [0x17, "P-256"]]);
const SIGNATURE_ALGS = [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603];

function tlsBytes(...args) {
    const flatten = (item) => {
        if (item instanceof Uint8Array) return [...item];
        if (Array.isArray(item)) return item.flatMap(flatten);
        return [item];
    };
    return new Uint8Array(flatten(args));
}

function uint16be(value) {
    return [(value >> 8) & 0xFF, value & 0xFF];
}

function readUint16(data, offset) {
    return (data[offset] << 8) | data[offset + 1];
}

function readUint24(data, offset) {
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
}

function randomBytes(len) {
    return crypto.getRandomValues(new Uint8Array(len));
}

function constantTimeEqual(a, b) {
    if (!a || !b || a.byteLength !== b.byteLength) return false;
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

function hashByteLength(hash) {
    if (hash === "SHA-512") return 64;
    if (hash === "SHA-384") return 48;
    return 32;
}

async function hmac(hash, key, data) {
    const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}

async function digestBytes(algorithm, data) {
    return new Uint8Array(await crypto.subtle.digest(algorithm, data));
}

async function hkdfExtract(hash, salt, ikm) {
    if (!salt?.byteLength) salt = new Uint8Array(hashByteLength(hash));
    return hmac(hash, salt, ikm);
}

async function hkdfExpandLabel(hash, secret, label, context, length) {
    const labelBytes = new TextEncoder().encode("tls13 " + label);
    const info = tlsBytes(uint16be(length), uint16be(labelBytes.byteLength), labelBytes, uint16be(context.byteLength), context);
    return hkdfExpand(hash, secret, info, length);
}

async function hkdfExpand(hash, prk, info, length) {
    const hashLen = hashByteLength(hash);
    const iterations = Math.ceil(length / hashLen);
    let result = new Uint8Array(0);
    let t = new Uint8Array(0);
    for (let i = 1; i <= iterations; i++) {
        t = await hmac(hash, prk, concatBuffers(t, info, [i]));
        result = concatBuffers(result, t);
    }
    return result.subarray(0, length);
}

async function generateKeyShare(curve = "P-256") {
    const algorithm = curve === "X25519" ? { name: "X25519" } : { name: "ECDH", namedCurve: curve };
    const keyPair = await crypto.subtle.generateKey(algorithm, true, ["deriveKey", "deriveBits"]);
    const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    return { keyPair, publicKeyRaw };
}

async function deriveSharedSecret(privateKey, publicKey, curve = "P-256") {
    const algorithm = curve === "X25519" ? { name: "X25519" } : { name: "ECDH", namedCurve: curve };
    const publicCryptoKey = await crypto.subtle.importKey("raw", publicKey, algorithm, true, []);
    const bits = curve === "P-384" ? 384 : curve === "P-521" ? 521 : 256;
    return new Uint8Array(await crypto.subtle.deriveBits({ name: algorithm.name, public: publicCryptoKey }, privateKey, bits));
}

class TlsRecordParser {
    constructor() {
        this.buffer = new Uint8Array(0);
    }
    feed(data) {
        const bytes = arrayToUint8(data);
        this.buffer = this.buffer.byteLength ? concatBuffers(this.buffer, bytes) : bytes;
    }
    next() {
        if (this.buffer.byteLength < 5) return null;
        const type = this.buffer[0];
        const version = readUint16(this.buffer, 1);
        const length = readUint16(this.buffer, 3);
        if (this.buffer.byteLength < 5 + length) return null;
        const fragment = this.buffer.subarray(5, 5 + length);
        this.buffer = this.buffer.subarray(5 + length);
        return { type, version, length, fragment };
    }
}

class TlsHandshakeParser {
    constructor() {
        this.buffer = new Uint8Array(0);
    }
    feed(data) {
        const bytes = arrayToUint8(data);
        this.buffer = this.buffer.byteLength ? concatBuffers(this.buffer, bytes) : bytes;
    }
    next() {
        if (this.buffer.byteLength < 4) return null;
        const type = this.buffer[0];
        const length = readUint24(this.buffer, 1);
        if (this.buffer.byteLength < 4 + length) return null;
        const body = this.buffer.subarray(4, 4 + length);
        const raw = this.buffer.subarray(0, 4 + length);
        this.buffer = this.buffer.subarray(4 + length);
        return { type, length, body, raw };
    }
}

function parseServerHello(data) {
    let pos = 0;
    const version = readUint16(data, pos); pos += 2;
    const random = data.subarray(pos, pos + 32); pos += 32;
    const sessionIdLen = data[pos++];
    const sessionId = data.subarray(pos, pos + sessionIdLen); pos += sessionIdLen;
    const cipherSuite = readUint16(data, pos); pos += 2;
    const compression = data[pos++];
    
    let selectedVersion = version;
    let keyShare = null;
    let alpn = null;
    
    if (pos < data.byteLength) {
        const extLen = readUint16(data, pos); pos += 2;
        const extEnd = pos + extLen;
        while (pos + 4 <= extEnd) {
            const extType = readUint16(data, pos); pos += 2;
            const extLen = readUint16(data, pos); pos += 2;
            const extData = data.subarray(pos, pos + extLen); pos += extLen;
            
            if (extType === EXT_SUPPORTED_VERSIONS && extLen >= 2) {
                selectedVersion = readUint16(extData, 0);
            } else if (extType === EXT_KEY_SHARE && extLen >= 4) {
                const group = readUint16(extData, 0);
                const keyLen = readUint16(extData, 2);
                keyShare = { group, key: extData.subarray(4, 4 + keyLen) };
            } else if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
                alpn = new TextDecoder().decode(extData.subarray(3, 3 + extData[2]));
            }
        }
    }
    
    const hrrMarker = new Uint8Array([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02,
        0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ]);
    
    return {
        version, serverRandom: random, sessionId, cipherSuite, compression,
        selectedVersion, keyShare, alpn,
        isHRR: constantTimeEqual(random, hrrMarker),
        isTls13: selectedVersion === TLS_VERSION_13
    };
}

function buildClientHello(random, serverName, keyShares, options = {}) {
    const cipherSuites = [];
    if (options.tls13 !== false) {
        cipherSuites.push(0x1301, 0x1302);
        if (options.chacha) cipherSuites.push(0x1303);
    }
    if (options.tls12 !== false) {
        cipherSuites.push(0xC02F, 0xC030, 0xC02B, 0xC02C);
        if (options.chacha) cipherSuites.push(0xCCA8, 0xCCA9);
    }
    
    const cipherBytes = tlsBytes(...cipherSuites.flatMap(uint16be));
    const extensions = [];
    
    if (serverName) {
        const nameBytes = new TextEncoder().encode(serverName);
        const sniExt = tlsBytes(
            uint16be(EXT_SERVER_NAME),
            uint16be(nameBytes.byteLength + 2),
            uint16be(nameBytes.byteLength),
            nameBytes
        );
        extensions.push(sniExt);
    }
    
    extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0x00, 0x02, 0x01, 0x00));
    extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0x00, 0x06, 0x00, 0x04, 0x00, 0x1D, 0x00, 0x17));
    
    const sigAlgs = tlsBytes(...SIGNATURE_ALGS.flatMap(uint16be));
    extensions.push(tlsBytes(
        uint16be(EXT_SIGNATURE_ALGORITHMS),
        uint16be(sigAlgs.byteLength + 2),
        uint16be(sigAlgs.byteLength),
        sigAlgs
    ));
    
    if (options.alpn?.length) {
        const alpnBytes = concatBuffers(...options.alpn.map(p => tlsBytes(p.length, new TextEncoder().encode(p))));
        extensions.push(tlsBytes(
            uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
            uint16be(alpnBytes.byteLength + 2),
            uint16be(alpnBytes.byteLength),
            alpnBytes
        ));
    }
    
    if (options.tls13 !== false && keyShares) {
        let keyShareBytes;
        if (keyShares.x25519 && keyShares.p256) {
            keyShareBytes = concatBuffers(
                tlsBytes(0x00, 0x1D, uint16be(keyShares.x25519.byteLength), keyShares.x25519),
                tlsBytes(0x00, 0x17, uint16be(keyShares.p256.byteLength), keyShares.p256)
            );
        } else if (keyShares.x25519) {
            keyShareBytes = tlsBytes(0x00, 0x1D, uint16be(keyShares.x25519.byteLength), keyShares.x25519);
        } else if (keyShares.p256) {
            keyShareBytes = tlsBytes(0x00, 0x17, uint16be(keyShares.p256.byteLength), keyShares.p256);
        } else if (keyShares instanceof Uint8Array) {
            keyShareBytes = tlsBytes(0x00, 0x17, uint16be(keyShares.byteLength), keyShares);
        } else {
            throw new Error("Invalid key share");
        }
        
        extensions.push(tlsBytes(
            uint16be(EXT_KEY_SHARE),
            uint16be(keyShareBytes.byteLength + 2),
            uint16be(keyShareBytes.byteLength),
            keyShareBytes
        ));
        
        const versionBytes = options.tls12 !== false
            ? tlsBytes(0x04, 0x03, 0x04, 0x03, 0x03)
            : tlsBytes(0x02, 0x03, 0x04);
        extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0x00, versionBytes.byteLength + 2, uint16be(versionBytes.byteLength), versionBytes));
        extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0x00, 0x02, 0x01, 0x01));
    }
    
    const extensionsBytes = concatBuffers(...extensions);
    
    return buildHandshakeMessage(
        HANDSHAKE_TYPE_CLIENT_HELLO,
        tlsBytes(
            uint16be(TLS_VERSION_12),
            random,
            0x00,
            uint16be(cipherBytes.byteLength),
            cipherBytes,
            0x01,
            0x00,
            uint16be(extensionsBytes.byteLength),
            extensionsBytes
        )
    );
}

function buildHandshakeMessage(msgType, body) {
    return tlsBytes(msgType, (body.byteLength >> 16) & 0xFF, (body.byteLength >> 8) & 0xFF, body.byteLength & 0xFF, body);
}

function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
    const bytes = arrayToUint8(fragment);
    const record = new Uint8Array(5 + bytes.byteLength);
    record[0] = contentType;
    record[1] = (version >> 8) & 0xFF;
    record[2] = version & 0xFF;
    record[3] = (bytes.byteLength >> 8) & 0xFF;
    record[4] = bytes.byteLength & 0xFF;
    record.set(bytes, 5);
    return record;
}

class TlsClient {
    constructor(socket, options = {}) {
        this.socket = socket;
        this.serverName = options.serverName || "";
        this.supportTls13 = options.tls13 !== false;
        this.supportTls12 = options.tls12 !== false;
        this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null;
        this.allowChacha = options.allowChacha !== false;
        this.timeout = options.timeout ?? 30000;
        this.clientRandom = randomBytes(32);
        this.serverRandom = null;
        this.handshakeMessages = [];
        this.handshakeComplete = false;
        this.cipherConfig = null;
        this.negotiatedAlpn = null;
        this.isTls13 = true;
        this.masterSecret = null;
        this.handshakeSecret = null;
        this.clientHandshakeKey = null;
        this.serverHandshakeKey = null;
        this.clientHandshakeIv = null;
        this.serverHandshakeIv = null;
        this.clientAppKey = null;
        this.serverAppKey = null;
        this.clientAppIv = null;
        this.serverAppIv = null;
        this.clientSeqNum = 0n;
        this.serverSeqNum = 0n;
        this.recordParser = new TlsRecordParser();
        this.handshakeParser = new TlsHandshakeParser();
        this.keyPairs = new Map();
        this.ecdhKeyPair = null;
        this.sawCert = true;
    }
    
    recordHandshake(data) {
        this.handshakeMessages.push(data);
    }
    
    transcript() {
        if (this.handshakeMessages.length === 1) return this.handshakeMessages[0];
        return concatBuffers(...this.handshakeMessages);
    }
    
    getCipherConfig(id) {
        return CIPHER_SUITES.get(id) || null;
    }
    
    async readChunk(reader) {
        if (this.timeout) {
            return Promise.race([
                reader.read(),
                new Promise((_, reject) => setTimeout(() => reject(new Error("TLS read timeout")), this.timeout))
            ]);
        }
        return reader.read();
    }
    
    async readRecordsUntil(reader, predicate, errorMsg) {
        while (true) {
            let record;
            while ((record = this.recordParser.next())) {
                if (await predicate(record)) return;
            }
            const { value, done } = await this.readChunk(reader);
            if (done) throw new Error(errorMsg);
            this.recordParser.feed(value);
        }
    }
    
    async readHandshakeUntil(reader, predicate, errorMsg) {
        while (true) {
            let hs;
            while ((hs = this.handshakeParser.next())) {
                if (await predicate(hs)) return;
            }
            await this.readRecordsUntil(reader, async (record) => {
                if (record.type === CONTENT_TYPE_ALERT) {
                    if (record.fragment[0] === ALERT_LEVEL_WARNING && record.fragment[1] === ALERT_UNRECOGNIZED_NAME) {
                        return false;
                    }
                    throw new Error(`TLS Alert: ${record.fragment[1]}`);
                }
                if (record.type === CONTENT_TYPE_HANDSHAKE) {
                    this.handshakeParser.feed(record.fragment);
                }
                return false;
            }, errorMsg);
        }
    }
    
    async acceptCertificate(cert) {
        if (!cert?.byteLength) throw new Error("Missing certificate");
        this.sawCert = true;
    }
    
    async handshake() {
        const [p256Key, x25519Key] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
        this.keyPairs.set(0x17, p256Key);
        this.keyPairs.set(0x1D, x25519Key);
        this.ecdhKeyPair = p256Key.keyPair;
        
        const reader = this.socket.readable.getReader();
        const writer = this.socket.writable.getWriter();
        
        try {
            const clientHello = buildClientHello(this.clientRandom, this.serverName, {
                x25519: x25519Key.publicKeyRaw,
                p256: p256Key.publicKeyRaw
            }, {
                tls13: this.supportTls13,
                tls12: this.supportTls12,
                alpn: this.alpnProtocols,
                chacha: this.allowChacha
            });
            
            this.recordHandshake(clientHello);
            await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
            
            const serverHello = await this.receiveServerHello(reader);
            if (serverHello.isHRR) {
                throw new Error("TLS 1.3 HRR not supported");
            }
            
            if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
                const keyPair = this.keyPairs.get(serverHello.keyShare.group);
                this.ecdhKeyPair = keyPair.keyPair;
            }
            
            if (serverHello.isTls13) {
                await this.handshakeTls13(reader, writer, serverHello);
            } else {
                await this.handshakeTls12(reader, writer);
            }
            
            this.handshakeComplete = true;
        } finally {
            reader.releaseLock();
            writer.releaseLock();
        }
    }
    
    async receiveServerHello(reader) {
        while (true) {
            const { value, done } = await this.readChunk(reader);
            if (done) throw new Error("Connection closed before ServerHello");
            
            let record;
            this.recordParser.feed(value);
            while ((record = this.recordParser.next())) {
                if (record.type === CONTENT_TYPE_ALERT) {
                    if (record.fragment[0] === ALERT_LEVEL_WARNING && record.fragment[1] === ALERT_UNRECOGNIZED_NAME) {
                        continue;
                    }
                    throw new Error(`TLS Alert: ${record.fragment[1]}`);
                }
                if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
                
                let hs;
                this.handshakeParser.feed(record.fragment);
                while ((hs = this.handshakeParser.next())) {
                    if (hs.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
                    this.recordHandshake(hs.raw);
                    const parsed = parseServerHello(hs.body);
                    this.serverRandom = parsed.serverRandom;
                    this.cipherConfig = this.getCipherConfig(parsed.cipherSuite);
                    this.isTls13 = parsed.isTls13;
                    this.negotiatedAlpn = parsed.alpn || null;
                    if (!this.cipherConfig) {
                        throw new Error(`Unsupported cipher suite: 0x${parsed.cipherSuite.toString(16)}`);
                    }
                    return parsed;
                }
            }
        }
    }
    
    async handshakeTls12(reader, writer) {
        let serverKeyExchange = null;
        let serverHelloDone = false;
        
        await this.readHandshakeUntil(reader, async (hs) => {
            switch (hs.type) {
                case HANDSHAKE_TYPE_CERTIFICATE:
                    this.recordHandshake(hs.raw);
                    const leafCert = this.extractLeafCertificate(hs.body, 1);
                    if (!leafCert) throw new Error("No certificate received");
                    await this.acceptCertificate(leafCert);
                    break;
                case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
                    this.recordHandshake(hs.raw);
                    serverKeyExchange = this.parseServerKeyExchange(hs.body);
                    break;
                case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
                    this.recordHandshake(hs.raw);
                    serverHelloDone = true;
                    return true;
                case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
                    throw new Error("Client certificate not supported");
                default:
                    this.recordHandshake(hs.raw);
            }
            return false;
        }, "TLS 1.2 handshake failed");
        
        if (!this.sawCert) throw new Error("No certificate received");
        if (!serverKeyExchange) throw new Error("Missing ServerKeyExchange");
        
        const curveName = GROUPS.get(serverKeyExchange.namedCurve);
        if (!curveName) throw new Error(`Unsupported curve: 0x${serverKeyExchange.namedCurve.toString(16)}`);
        
        const keyPair = this.keyPairs.get(serverKeyExchange.namedCurve);
        if (!keyPair) throw new Error(`Missing key pair for curve: 0x${serverKeyExchange.namedCurve.toString(16)}`);
        
        const premasterSecret = await deriveSharedSecret(keyPair.keyPair.privateKey, serverKeyExchange.serverPublicKey, curveName);
        const hash = this.cipherConfig.hash;
        
        this.masterSecret = await tls12Prf(premasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hash);
        
        const keyLen = this.cipherConfig.keyLen;
        const ivLen = this.cipherConfig.ivLen;
        const keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hash);
        
        this.clientWriteKey = keyBlock.subarray(0, keyLen);
        this.serverWriteKey = keyBlock.subarray(keyLen, 2 * keyLen);
        this.clientWriteIv = keyBlock.subarray(2 * keyLen, 2 * keyLen + ivLen);
        this.serverWriteIv = keyBlock.subarray(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
        
        if (!this.cipherConfig.chacha) {
            this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
            this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
        }
        
        const finishedKey = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hash, this.transcript()), 12, hash);
        const clientFinished = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, finishedKey);
        this.recordHandshake(clientFinished);
        
        await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientFinished));
        await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(0x01)));
        
        let seenChangeCipher = false;
        await this.readHandshakeUntil(reader, async (hs) => {
            if (hs.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
                seenChangeCipher = true;
                return false;
            }
            if (hs.type !== CONTENT_TYPE_HANDSHAKE || !seenChangeCipher) return false;
            if (hs.body[0] !== HANDSHAKE_TYPE_FINISHED) return false;
            
            const serverFinishedKey = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hash, this.transcript()), 12, hash);
            const received = hs.body.subarray(4);
            if (!constantTimeEqual(received, serverFinishedKey)) {
                throw new Error("TLS 1.2 server finished mismatch");
            }
            return true;
        }, "TLS 1.2 server finished missing");
    }
    
    async handshakeTls13(reader, writer, serverHello) {
        const hash = this.cipherConfig.hash;
        const hashLen = hashByteLength(hash);
        const keyLen = this.cipherConfig.keyLen;
        const ivLen = this.cipherConfig.ivLen;
        
        const curve = GROUPS.get(serverHello.keyShare.group);
        if (!curve || !serverHello.keyShare?.key) throw new Error("Missing or invalid key share");
        
        const sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, curve);
        const earlySecret = await hkdfExtract(hash, null, new Uint8Array(hashLen));
        const derivedSecret = await hkdfExpandLabel(hash, earlySecret, "derived", await digestBytes(hash, EMPTY_BYTES), hashLen);
        this.handshakeSecret = await hkdfExtract(hash, derivedSecret, sharedSecret);
        
        const transcriptHash = await digestBytes(hash, this.transcript());
        const clientHandshakeSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen);
        const serverHandshakeSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
        
        [this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hash, clientHandshakeSecret, keyLen, ivLen);
        [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hash, serverHandshakeSecret, keyLen, ivLen);
        
        if (!this.cipherConfig.chacha) {
            this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
            this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"]);
        }
        
        let serverFinished = false;
        await this.readHandshakeUntil(reader, async (hs) => {
            if (hs.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return false;
            if (hs.type === CONTENT_TYPE_ALERT) {
                if (hs.fragment[0] === ALERT_LEVEL_WARNING && hs.fragment[1] === ALERT_UNRECOGNIZED_NAME) return false;
                throw new Error(`TLS Alert: ${hs.fragment[1]}`);
            }
            if (hs.type !== CONTENT_TYPE_APPLICATION_DATA) return false;
            
            const decrypted = await this.decryptTls13Handshake(hs.fragment);
            const lastByte = decrypted[decrypted.length - 1];
            const handshakeData = decrypted.subarray(0, -1);
            
            if (lastByte === CONTENT_TYPE_HANDSHAKE) {
                this.handshakeParser.feed(handshakeData);
                let hsMsg;
                while ((hsMsg = this.handshakeParser.next())) {
                    await this.processHandshakeMessage(hsMsg);
                    if (hsMsg.type === HANDSHAKE_TYPE_FINISHED) serverFinished = true;
                }
            }
            return serverFinished;
        }, "TLS 1.3 handshake failed");
        
        const serverFinishedSecret = await hkdfExpandLabel(hash, serverHandshakeSecret, "finished", EMPTY_BYTES, hashLen);
        const expectedVerifyData = await hmac(hash, serverFinishedSecret, await digestBytes(hash, this.transcript()));
        
        const trafficSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "derived", await digestBytes(hash, EMPTY_BYTES), hashLen);
        const masterSecret = await hkdfExtract(hash, trafficSecret, new Uint8Array(hashLen));
        const clientTrafficSecret = await hkdfExpandLabel(hash, masterSecret, "c ap traffic", transcriptHash, hashLen);
        const serverTrafficSecret = await hkdfExpandLabel(hash, masterSecret, "s ap traffic", transcriptHash, hashLen);
        
        [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hash, clientTrafficSecret, keyLen, ivLen);
        [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hash, serverTrafficSecret, keyLen, ivLen);
        
        if (!this.cipherConfig.chacha) {
            this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
            this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"]);
        }
        
        const clientFinishedSecret = await hkdfExpandLabel(hash, clientHandshakeSecret, "finished", EMPTY_BYTES, hashLen);
        const clientVerifyData = await hmac(hash, clientFinishedSecret, await digestBytes(hash, this.transcript()));
        const clientFinishedMsg = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
        this.recordHandshake(clientFinishedMsg);
        
        const encryptedFinished = await this.encryptTls13Handshake(concatBuffers(clientFinishedMsg, [CONTENT_TYPE_HANDSHAKE]));
        await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encryptedFinished));
        
        this.clientSeqNum = 0n;
        this.serverSeqNum = 0n;
    }
    
    async processHandshakeMessage(hs) {
        switch (hs.type) {
            case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:
                this.recordHandshake(hs.raw);
                const parsed = this.parseEncryptedExtensions(hs.body);
                if (parsed.alpn) this.negotiatedAlpn = parsed.alpn;
                break;
            case HANDSHAKE_TYPE_CERTIFICATE:
                const leafCert = this.extractLeafCertificate(hs.body);
                if (!leafCert) throw new Error("TLS 1.3 missing certificate");
                await this.acceptCertificate(leafCert);
                this.recordHandshake(hs.raw);
                break;
            case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
                throw new Error("Client certificate not supported");
            case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
                this.recordHandshake(hs.raw);
                break;
            case HANDSHAKE_TYPE_FINISHED:
                this.recordHandshake(hs.raw);
                break;
            default:
                this.recordHandshake(hs.raw);
        }
    }
    
    parseEncryptedExtensions(data) {
        const result = { alpn: null };
        let pos = 2;
        const extLen = 2 + readUint16(data, 0);
        while (pos + 4 <= extLen) {
            const extType = readUint16(data, pos); pos += 2;
            const extLen = readUint16(data, pos); pos += 2;
            if (extType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extLen >= 3) {
                const alpnLen = data[pos + 2];
                if (alpnLen > 0) {
                    result.alpn = new TextDecoder().decode(data.subarray(pos + 3, pos + 3 + alpnLen));
                }
            }
            pos += extLen;
        }
        return result;
    }
    
    extractLeafCertificate(data, skipCertLen = 0) {
        let pos = 0;
        if (skipCertLen) {
            const certsLen = readUint24(data, pos); pos += 3;
        }
        if (pos + 3 > data.byteLength) return null;
        const certLen = readUint24(data, pos); pos += 3;
        if (!certLen || pos + 3 > data.byteLength) return null;
        const leafLen = readUint24(data, pos); pos += 3;
        return leafLen ? data.subarray(pos, pos + leafLen) : null;
    }
    
    parseServerKeyExchange(data) {
        let pos = 1;
        const namedCurve = readUint16(data, pos); pos += 2;
        const pubKeyLen = data[pos++];
        const serverPublicKey = data.subarray(pos, pos + pubKeyLen);
        return { namedCurve, serverPublicKey };
    }
    
    async encryptTls12(data, contentType) {
        const seq = this.clientSeqNum++;
        const seqBytes = uint64be(seq);
        const additional = concatBuffers(seqBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(data.byteLength));
        
        if (this.cipherConfig.chacha) {
            const iv = xorSequenceIntoIv(this.clientWriteIv, seq);
            return chacha20Poly1305Encrypt(this.clientWriteKey, iv, data, additional);
        }
        
        const nonce = randomBytes(8);
        if (!this.clientWriteCryptoKey) {
            this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
        }
        return concatBuffers(nonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBuffers(this.clientWriteIv, nonce), data, additional));
    }
    
    async decryptTls12(data, contentType) {
        const seq = this.serverSeqNum++;
        const seqBytes = uint64be(seq);
        const additional = concatBuffers(seqBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(data.byteLength - 16));
        
        if (this.cipherConfig.chacha) {
            const iv = xorSequenceIntoIv(this.serverWriteIv, seq);
            return chacha20Poly1305Decrypt(this.serverWriteKey, iv, data, additional);
        }
        
        const nonce = data.subarray(0, 8);
        const ciphertext = data.subarray(8);
        if (!this.serverWriteCryptoKey) {
            this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
        }
        return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBuffers(this.serverWriteIv, nonce), ciphertext, additional);
    }
    
    async encryptTls13Handshake(data) {
        const seq = this.clientSeqNum++;
        const iv = xorSequenceIntoIv(this.clientHandshakeIv, seq);
        const additional = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, uint16be(data.byteLength + 16));
        
        if (this.cipherConfig.chacha) {
            return chacha20Poly1305Encrypt(this.clientHandshakeKey, iv, data, additional);
        }
        if (!this.clientHandshakeCryptoKey) {
            this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
        }
        return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, iv, data, additional);
    }
    
    async decryptTls13Handshake(data) {
        const seq = this.serverSeqNum++;
        const iv = xorSequenceIntoIv(this.serverHandshakeIv, seq);
        const additional = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, uint16be(data.byteLength));
        
        const decrypted = this.cipherConfig.chacha
            ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, iv, data, additional)
            : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey, iv, data, additional);
        
        let lastNonZero = decrypted.length - 1;
        while (lastNonZero >= 0 && decrypted[lastNonZero] === 0) lastNonZero--;
        return lastNonZero < 0 ? EMPTY_BYTES : decrypted.subarray(0, lastNonZero + 1);
    }
    
    async encryptTls13(data) {
        const seq = this.clientSeqNum++;
        const iv = xorSequenceIntoIv(this.clientAppIv, seq);
        const padded = concatBuffers(data, [CONTENT_TYPE_APPLICATION_DATA]);
        const additional = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, uint16be(padded.byteLength + 16));
        
        if (this.cipherConfig.chacha) {
            return chacha20Poly1305Encrypt(this.clientAppKey, iv, padded, additional);
        }
        if (!this.clientAppCryptoKey) {
            this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
        }
        return aesGcmEncryptWithKey(this.clientAppCryptoKey, iv, padded, additional);
    }
    
    async decryptTls13(data) {
        const seq = this.serverSeqNum++;
        const iv = xorSequenceIntoIv(this.serverAppIv, seq);
        const additional = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 0x03, 0x03, uint16be(data.byteLength));
        
        const decrypted = this.cipherConfig.chacha
            ? await chacha20Poly1305Decrypt(this.serverAppKey, iv, data, additional)
            : await aesGcmDecryptWithKey(this.serverAppCryptoKey, iv, data, additional);
        
        let lastNonZero = decrypted.length - 1;
        while (lastNonZero >= 0 && decrypted[lastNonZero] === 0) lastNonZero--;
        if (lastNonZero < 0) return { data: EMPTY_BYTES, type: 0 };
        return { data: decrypted.subarray(0, lastNonZero), type: decrypted[lastNonZero] };
    }
    
    async write(data) {
        if (!this.handshakeComplete) throw new Error("Handshake not complete");
        const bytes = arrayToUint8(data);
        if (!bytes.byteLength) return;
        
        const writer = this.socket.writable.getWriter();
        try {
            const fragments = [];
            for (let i = 0; i < bytes.byteLength; i += 16384) {
                const fragment = bytes.subarray(i, Math.min(i + 16384, bytes.byteLength));
                const encrypted = this.isTls13 ? await this.encryptTls13(fragment) : await this.encryptTls12(fragment, CONTENT_TYPE_APPLICATION_DATA);
                fragments.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
            }
            await writer.write(fragments.length === 1 ? fragments[0] : concatBuffers(...fragments));
        } finally {
            writer.releaseLock();
        }
    }
    
    async read() {
        while (true) {
            let record;
            while ((record = this.recordParser.next())) {
                if (record.type === CONTENT_TYPE_ALERT) {
                    if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
                    throw new Error(`TLS Alert: ${record.fragment[1]}`);
                }
                if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
                
                if (!this.isTls13) {
                    return await this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
                }
                const { data, type } = await this.decryptTls13(record.fragment);
                if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
                if (type === CONTENT_TYPE_ALERT) {
                    if (data[1] === ALERT_CLOSE_NOTIFY) return null;
                    throw new Error(`TLS Alert: ${data[1]}`);
                }
            }
            const reader = this.socket.readable.getReader();
            try {
                const { value, done } = await this.readChunk(reader);
                if (done) return null;
                this.recordParser.feed(value);
            } finally {
                reader.releaseLock();
            }
        }
    }
    
    close() {
        this.socket.close();
    }
}

const EMPTY_BYTES = new Uint8Array(0);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function uint64be(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

function xorSequenceIntoIv(iv, seq) {
    const result = iv.slice();
    const seqBytes = uint64be(seq);
    for (let i = 0; i < 8; i++) {
        result[result.length - 8 + i] ^= seqBytes[i];
    }
    return result;
}

async function deriveTrafficKeys(hash, secret, keyLen, ivLen) {
    const [key, iv] = await Promise.all([
        hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen),
        hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)
    ]);
    return [key, iv];
}

async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
    const labelBytes = textEncoder.encode(label);
    const seedBytes = arrayToUint8(seed);
    const a0 = concatBuffers(labelBytes, seedBytes);
    let result = new Uint8Array(0);
    let a = a0;
    while (result.byteLength < length) {
        a = await hmac(hash, secret, a);
        const p = await hmac(hash, secret, concatBuffers(a, labelBytes, seedBytes));
        result = concatBuffers(result, p);
    }
    return result.subarray(0, length);
}

async function importAesGcmKey(key, usages) {
    return await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, usages);
}

async function aesGcmEncryptWithKey(key, iv, data, additionalData) {
    return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, key, data));
}

async function aesGcmDecryptWithKey(key, iv, data, additionalData) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData, tagLength: 128 }, key, data));
}

// ========== ChaCha20-Poly1305 ==========
function rotateLeft32(value, shift) {
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function chachaQuarterRound(state, a, b, c, d) {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotateLeft32(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateLeft32(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotateLeft32(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateLeft32(state[b] ^ state[c], 7);
}

function chacha20Block(key, counter, nonce) {
    const constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];
    const keyWords = new Uint32Array(key.buffer, key.byteOffset, 8);
    const nonceWords = new Uint32Array(nonce.buffer, nonce.byteOffset, 3);
    
    const state = new Uint32Array(16);
    state.set(constants, 0);
    state.set(keyWords, 4);
    state[12] = counter;
    state[13] = nonceWords[0];
    state[14] = nonceWords[1];
    state[15] = nonceWords[2];
    
    const working = new Uint32Array(state);
    for (let i = 0; i < 10; i++) {
        chachaQuarterRound(working, 0, 4, 8, 12);
        chachaQuarterRound(working, 1, 5, 9, 13);
        chachaQuarterRound(working, 2, 6, 10, 14);
        chachaQuarterRound(working, 3, 7, 11, 15);
        chachaQuarterRound(working, 0, 5, 10, 15);
        chachaQuarterRound(working, 1, 6, 11, 12);
        chachaQuarterRound(working, 2, 7, 8, 13);
        chachaQuarterRound(working, 3, 4, 9, 14);
    }
    
    for (let i = 0; i < 16; i++) {
        working[i] = (working[i] + state[i]) >>> 0;
    }
    
    return new Uint8Array(working.buffer);
}

function chacha20Xor(key, nonce, data) {
    const result = new Uint8Array(data.byteLength);
    let counter = 1;
    for (let i = 0; i < data.byteLength; i += 64) {
        const block = chacha20Block(key, counter++, nonce);
        const chunkSize = Math.min(64, data.byteLength - i);
        for (let j = 0; j < chunkSize; j++) {
            result[i + j] = data[i + j] ^ block[j];
        }
    }
    return result;
}

function poly1305Mac(key, message) {
    const r = new Uint8Array(16);
    for (let i = 0; i < 16; i++) r[i] = key[i];
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    
    const h = [0n, 0n, 0n, 0n, 0n];
    const clamp = [
        0x3FFFFFFn & BigInt(r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24)),
        0x3FFFFFFn & BigInt((r[3] >> 2) | (r[4] << 6) | (r[5] << 14) | (r[6] << 22)),
        0x3FFFFFFn & BigInt((r[6] >> 4) | (r[7] << 4) | (r[8] << 12) | (r[9] << 20)),
        0x3FFFFFFn & BigInt((r[9] >> 6) | (r[10] << 2) | (r[11] << 10) | (r[12] << 18)),
        0x3FFFFFFn & BigInt(r[13] | (r[14] << 8) | (r[15] << 16))
    ];
    
    for (let i = 0; i < message.byteLength; i += 16) {
        const chunk = message.subarray(i, i + 16);
        const padded = new Uint8Array(17);
        padded.set(chunk);
        padded[chunk.byteLength] = 1;
        
        h[0] += BigInt(padded[0] | (padded[1] << 8) | (padded[2] << 16) | ((padded[3] & 3) << 24));
        h[1] += BigInt((padded[3] >> 2) | (padded[4] << 6) | (padded[5] << 14) | ((padded[6] & 15) << 22));
        h[2] += BigInt((padded[6] >> 4) | (padded[7] << 4) | (padded[8] << 12) | ((padded[9] & 63) << 20));
        h[3] += BigInt((padded[9] >> 6) | (padded[10] << 2) | (padded[11] << 10) | (padded[12] << 18));
        h[4] += BigInt(padded[13] | (padded[14] << 8) | (padded[15] << 16) | (padded[16] << 24));
        
        const newH = [0n, 0n, 0n, 0n, 0n];
        for (let j = 0; j < 5; j++) {
            for (let k = 0; k < 5; k++) {
                const idx = j + k;
                const mul = h[j] * clamp[k];
                if (idx < 5) newH[idx] += mul;
                else newH[idx - 5] += mul * 5n;
            }
        }
        
        let carry = 0n;
        for (let j = 0; j < 5; j++) {
            newH[j] += carry;
            h[j] = newH[j] & 0x3FFFFFFn;
            carry = newH[j] >> 26n;
        }
        h[0] += carry * 5n;
        carry = h[0] >> 26n;
        h[0] &= 0x3FFFFFFn;
        h[1] += carry;
    }
    
    let result = h[0] | (h[1] << 26n) | (h[2] << 52n) | (h[3] << 78n) | (h[4] << 104n);
    const s = key.subarray(16, 32);
    result = (result + BigInt(s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24) |
        (BigInt(s[4]) << 32n) | (BigInt(s[5]) << 40n) | (BigInt(s[6]) << 48n) | (BigInt(s[7]) << 56n))) &
        ((1n << 128n) - 1n);
    
    const tag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        tag[i] = Number((result >> BigInt(i * 8)) & 0xFFn);
    }
    return tag;
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
    const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
    const ciphertext = chacha20Xor(key, nonce, plaintext);
    
    const padAad = (16 - (additionalData.byteLength % 16)) % 16;
    const padCipher = (16 - (ciphertext.byteLength % 16)) % 16;
    const macData = new Uint8Array(additionalData.byteLength + padAad + ciphertext.byteLength + padCipher + 16);
    let pos = 0;
    macData.set(additionalData, pos);
    pos += additionalData.byteLength;
    pos += padAad;
    macData.set(ciphertext, pos);
    pos += ciphertext.byteLength;
    pos += padCipher;
    const view = new DataView(macData.buffer, pos);
    view.setBigUint64(0, BigInt(additionalData.byteLength), true);
    view.setBigUint64(8, BigInt(ciphertext.byteLength), true);
    
    const tag = poly1305Mac(otk, macData);
    return concatBuffers(ciphertext, tag);
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
    if (ciphertext.byteLength < 16) throw new Error("Ciphertext too short");
    const tag = ciphertext.subarray(-16);
    const encrypted = ciphertext.subarray(0, -16);
    
    const otk = chacha20Block(key, 0, nonce).subarray(0, 32);
    const padAad = (16 - (additionalData.byteLength % 16)) % 16;
    const padEnc = (16 - (encrypted.byteLength % 16)) % 16;
    const macData = new Uint8Array(additionalData.byteLength + padAad + encrypted.byteLength + padEnc + 16);
    let pos = 0;
    macData.set(additionalData, pos);
    pos += additionalData.byteLength;
    pos += padAad;
    macData.set(encrypted, pos);
    pos += encrypted.byteLength;
    pos += padEnc;
    const view = new DataView(macData.buffer, pos);
    view.setBigUint64(0, BigInt(additionalData.byteLength), true);
    view.setBigUint64(8, BigInt(encrypted.byteLength), true);
    
    const expectedTag = poly1305Mac(otk, macData);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= tag[i] ^ expectedTag[i];
    if (diff !== 0) throw new Error("ChaCha20-Poly1305 authentication failed");
    
    return chacha20Xor(key, nonce, encrypted);
}

// ========== IP Utilities ==========
function stripIPv6Brackets(host = "") {
    const str = String(host || "").trim();
    if (str.startsWith("[") && str.endsWith("]")) return str.slice(1, -1);
    return str;
}

function isIPv4(host = "") {
    const stripped = stripIPv6Brackets(host);
    const parts = stripped.split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6(host = "") {
    const stripped = stripIPv6Brackets(host);
    if (!stripped.includes(":")) return false;
    try {
        new URL("https://[" + stripped + "]/");
        return true;
    } catch(e) {
        return false;
    }
}

function isIPHostname(host = "") {
    return isIPv4(host) || isIPv6(host);
}

// ========== DNS over HTTPS ==========
async function dohQuery(name, type, endpoint = "https://cloudflare-dns.com/dns-query") {
    const startTime = performance.now();
    log("[DoH] Querying:", name, type, endpoint);
    
    try {
        const typeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
        const qtype = typeMap[String(type).toUpperCase()] || 1;
        
        function encodeName(domain) {
            const parts = domain.split(".");
            const result = [];
            for (const part of parts) {
                const partBytes = new TextEncoder().encode(part);
                result.push(new Uint8Array([partBytes.length]), partBytes);
            }
            result.push(new Uint8Array([0]));
            return concatBuffers(...result);
        }
        
        const nameBytes = encodeName(name);
        const packet = new Uint8Array(12 + nameBytes.byteLength + 4);
        const view = new DataView(packet.buffer);
        view.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
        view.setUint16(2, 0x0100);
        view.setUint16(4, 1);
        packet.set(nameBytes, 12);
        view.setUint16(12 + nameBytes.byteLength, qtype);
        view.setUint16(14 + nameBytes.byteLength, 1);
        
        log("[DoH] Request size:", packet.byteLength, "bytes");
        
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
            body: packet
        });
        
        if (!response.ok) {
            console.warn("[DoH] Failed:", name, type, endpoint, response.status);
            return [];
        }
        
        const data = new Uint8Array(await response.arrayBuffer());
        const dataView = new DataView(data.buffer);
        const qdcount = dataView.getUint16(4);
        const ancount = dataView.getUint16(6);
        
        let pos = 12;
        for (let i = 0; i < qdcount; i++) {
            while (data[pos] !== 0) pos++;
            pos += 5;
        }
        
        const decodeName = (start) => {
            let result = [];
            let pos = start;
            let jumped = false;
            let jumpPos = -1;
            let maxJumps = 64;
            
            while (maxJumps-- > 0) {
                const len = data[pos++];
                if (len === 0) break;
                if ((len & 0xC0) === 0xC0) {
                    if (!jumped) jumpPos = pos + 1;
                    pos = ((len & 0x3F) << 8) | data[pos];
                    jumped = true;
                    continue;
                }
                result.push(new TextDecoder().decode(data.subarray(pos, pos + len)));
                pos += len;
            }
            return [result.join("."), jumped ? jumpPos : pos];
        };
        
        for (let i = 0; i < qdcount; i++) {
            const [_, newPos] = decodeName(pos);
            pos = newPos + 4;
        }
        
        const records = [];
        for (let i = 0; i < ancount && pos < data.byteLength; i++) {
            const [recordName, newPos] = decodeName(pos);
            pos = newPos;
            const rtype = dataView.getUint16(pos); pos += 2;
            const rclass = dataView.getUint16(pos); pos += 2;
            const ttl = dataView.getUint32(pos); pos += 4;
            const rdlen = dataView.getUint16(pos); pos += 2;
            const rdata = data.subarray(pos, pos + rdlen);
            pos += rdlen;
            
            let recordData = "";
            if (rtype === 1 && rdlen === 4) {
                recordData = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
            } else if (rtype === 28 && rdlen === 16) {
                const parts = [];
                for (let j = 0; j < 16; j += 2) {
                    parts.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
                }
                recordData = parts.join(":");
            } else if (rtype === 16) {
                let textPos = 0;
                const texts = [];
                while (textPos < rdlen) {
                    const len = rdata[textPos++];
                    texts.push(new TextDecoder().decode(rdata.subarray(textPos, textPos + len)));
                    textPos += len;
                }
                recordData = texts.join("");
            } else if (rtype === 5) {
                const [cname, _] = decodeName(pos - rdlen);
                recordData = cname;
            } else {
                recordData = Array.from(rdata).map(b => b.toString(16).padStart(2, "0")).join("");
            }
            
            records.push({ name: recordName, type: rtype, TTL: ttl, data: recordData, rdata });
        }
        
        const elapsed = (performance.now() - startTime).toFixed(2);
        log("[DoH] Completed:", name, type, elapsed, "ms,", records.length, "records");
        return records;
    } catch(e) {
        const elapsed = (performance.now() - startTime).toFixed(2);
        console.warn("[DoH] Error:", name, type, endpoint, elapsed, "ms", e);
        return [];
    }
}

// ========== Proxy IP Parsing ==========
async function parseProxyAddress(proxyInput, targetHost, uuid) {
    if (!cachedProxyIP || !cachedProxyArray || cachedProxyIP !== proxyInput) {
        const cleanInput = proxyInput.toLowerCase().trim();
        
        const parseHostPort = (addr) => {
            let host = addr;
            let port = 443;
            if (addr.includes("]:")) {
                const parts = addr.split("]:");
                host = parts[0] + "]";
                port = parseInt(parts[1], 10) || port;
            } else if (!addr.startsWith("[") && (addr.match(/:/g) || []).length === 1) {
                const lastColon = addr.lastIndexOf(":");
                host = addr.slice(0, lastColon);
                port = parseInt(addr.slice(lastColon + 1), 10) || port;
            }
            return [host, port];
        };
        
        const parseLine = (line) => {
            const parts = line.split(",");
            const results = [];
            for (const part of parts) {
                const trimmed = part.trim();
                if (trimmed.includes('"') && trimmed.includes('"')) {
                    results.push(trimmed.slice(1, -1));
                } else {
                    results.push(trimmed);
                }
            }
            return results;
        };
        
        const addresses = await toArray(cleanInput);
        let parsed = [];
        
        const ipv4Pattern = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
        const ipv6Pattern = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
        
        for (const addr of addresses) {
            let [host, port] = parseHostPort(addr);
            
            if (addr.includes(".tp")) {
                const tpMatch = addr.match(/\.tp(\d+)/);
                if (tpMatch) port = parseInt(tpMatch[1], 10);
            }
            
            if (ipv4Pattern.test(host) || ipv6Pattern.test(host)) {
                log("[ProxyIP] Direct IP:", host);
                parsed.push([host, port]);
                continue;
            }
            
            const [txtRecords, aRecords] = await Promise.all([dohQuery(host, "TXT"), dohQuery(host, "A")]);
            const txtData = txtRecords.filter(r => r.type === 16).map(r => r.data);
            const parsedTxt = parseLine(txtData.join(""));
            
            if (parsedTxt.length > 0) {
                log("[ProxyIP] TXT records for", host, ":", parsedTxt.length);
                parsed.push(...parsedTxt.map(p => parseHostPort(p)));
                continue;
            }
            
            const ipv4Data = aRecords.filter(r => r.type === 1).map(r => r.data);
            if (ipv4Data.length > 0) {
                log("[ProxyIP] A records for", host, ":", ipv4Data.length);
                parsed.push(...ipv4Data.map(ip => [ip, port]));
                continue;
            }
            
            const aaaaRecords = await dohQuery(host, "AAAA");
            const ipv6Data = aaaaRecords.filter(r => r.type === 28).map(r => "[" + r.data + "]");
            if (ipv6Data.length > 0) {
                log("[ProxyIP] AAAA records for", host, ":", ipv6Data.length);
                parsed.push(...ipv6Data.map(ip => [ip, port]));
                continue;
            }
            
            log("[ProxyIP] No records for", host, ", using original");
            parsed.push([host, port]);
        }
        
        const unique = [];
        for (const item of parsed) {
            if (!unique.some(u => u[0] === item[0])) unique.push(item);
        }
        
        const seedBase = targetHost.split(".").slice(-2).join(".");
        let seed = [...(seedBase + uuid)].reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
        log("[ProxyIP] Random seed:", seed, "base:", seedBase);
        
        const shuffled = [...unique].sort(() => {
            seed = (seed * 0x41C64E6D + 0x3039) & 0x7FFFFFFF;
            return seed / 0x7FFFFFFF - 0.5;
        });
        
        cachedProxyArray = shuffled.slice(0, 8);
        log("[ProxyIP] Total:", cachedProxyArray.length, "\n" + cachedProxyArray.map(([h, p], i) => `${i+1}. ${h}:${p}`).join("\n"));
        cachedProxyIP = proxyInput;
    } else {
        log("[ProxyIP] Using cached:", cachedProxyArray.length, "entries\n" + cachedProxyArray.map(([h, p], i) => `${i+1}. ${h}:${p}`).join("\n"));
    }
    
    return cachedProxyArray;
}

// ========== Array Utilities ==========
async function toArray(input) {
    let cleaned = String(input || "").replace(/[	"'\r\n]+/g, ",").replace(/,+/g, ",");
    if (cleaned.startsWith(",")) cleaned = cleaned.slice(1);
    if (cleaned.endsWith(",")) cleaned = cleaned.slice(0, -1);
    return cleaned.split(",").filter(s => s.trim());
}

// ========== Logging ==========
async function logRequest(env, request, ip, type = "Get_SUB", config, enabled = true) {
    try {
        const now = new Date();
        const logEntry = {
            type: type,
            ip: ip,
            asn: "AS" + (request.cf?.asn || "0") + " " + (request.cf?.asOrganization || "Unknown"),
            cc: (request.cf?.country || "XX") + " " + (request.cf?.city || "Unknown"),
            url: request.url,
            ua: request.headers.get("User-Agent") || "Unknown",
            time: now.toISOString()
        };
        
        if (config?.tg?.enabled && env.KV) {
            try {
                const tgConfig = await env.KV.get("tg.json");
                if (tgConfig) {
                    const tg = JSON.parse(tgConfig);
                    if (tg.BotToken && tg.ChatID) {
                        const timeStr = now.toLocaleString("fa-IR", { timeZone: "Asia/Tehran" });
                        const urlObj = new URL(request.url);
                        const typeNames = {
                            Get_SUB: "دریافت اشتراک",
                            Get_Best_SUB: "دریافت بهترین اشتراک",
                            Init_Config: "تنظیمات اولیه",
                            Save_Config: "ذخیره تنظیمات",
                            Admin_Login: "ورود به پنل"
                        };
                        const message = `<b>${typeNames[type] || type}</b>\n` +
                            `🌐 IP: <code>${ip}</code>\n` +
                            `📍 ${logEntry.cc}\n` +
                            `🔗 <a href="${request.url}">Link</a>\n` +
                            `🤖 UA: <code>${logEntry.ua}</code>\n` +
                            `⏰ ${timeStr}`;
                        
                        await fetch(`https://api.telegram.org/bot${tg.BotToken}/sendMessage`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                chat_id: tg.ChatID,
                                text: message,
                                parse_mode: "HTML",
                                disable_web_page_preview: true
                            })
                        });
                    }
                }
            } catch(e) {
                console.error("Telegram log error:", e.message);
            }
        }
        
        const shouldLog = enabled && !["1", "true"].includes(env.OFF_LOG);
        if (!shouldLog || !env.KV) return;
        
        let logs = [];
        const stored = await env.KV.get("log.json");
        const MAX_SIZE_MB = 4;
        
        if (stored) {
            try {
                logs = JSON.parse(stored);
                if (!Array.isArray(logs)) logs = [logEntry];
                else {
                    if (type !== "Admin_Login") {
                        const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
                        const exists = logs.some(l => l.type !== "Admin_Login" && l.ip === ip && l.url === request.url && l.ua === (request.headers.get("User-Agent") || "Unknown") && new Date(l.time).getTime() >= oneDayAgo);
                        if (exists) return;
                    }
                    logs.push(logEntry);
                    while (JSON.stringify(logs).length > MAX_SIZE_MB * 1024 * 1024 && logs.length > 0) {
                        logs.shift();
                    }
                }
            } catch(e) {
                logs = [logEntry];
            }
        } else {
            logs = [logEntry];
        }
        
        await env.KV.put("log.json", JSON.stringify(logs));
    } catch(e) {
        console.error("Log error:", e.message);
    }
}

// ========== Random IP Generation ==========
async function generateRandomIP(request, count = 16, customPort = -1) {
    const url = new URL(request.url);
    const asOrg = String(url.searchParams.get("asOrg") || "").toLowerCase();
    const carrier = asOrg || identifyCarrier(request);
    
    const carrierMap = {
        cmcc: "移动优选",
        cu: "联通优选",
        ct: "电信优选",
        cf: "Cloudflare优选"
    };
    
    const apiUrl = carrier === "cf" 
        ? "https://raw.github.../cf-ips.txt"
        : `https://raw.github.../${carrier}-ips.txt`;
    
    const defaultPorts = [443, 2053, 2083, 2087, 2096, 8443];
    let ipList = [];
    
    try {
        const response = await fetch(apiUrl);
        if (response.ok) {
            ipList = await toArray(await response.text());
        } else {
            ipList = ["104.16.0.0/12"];
        }
    } catch(e) {
        ipList = ["104.16.0.0/12"];
    }
    
    const parseCIDR = (cidr) => {
        const [network, prefix] = cidr.split("/");
        const prefixLen = parseInt(prefix);
        const mask = 0xFFFFFFFF << (32 - prefixLen) >>> 0;
        const parts = network.split(".").map(Number);
        const ipInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        const base = ipInt & mask;
        const range = Math.pow(2, 32 - prefixLen);
        const offset = Math.floor(Math.random() * range);
        const result = (base + offset) >>> 0;
        return [
            (result >>> 24) & 0xFF,
            (result >>> 16) & 0xFF,
            (result >>> 8) & 0xFF,
            result & 0xFF
        ].join(".");
    };
    
    const ips = Array.from({ length: count }, () => {
        const cidr = ipList[Math.floor(Math.random() * ipList.length)];
        const ip = parseCIDR(cidr);
        const port = customPort === -1 ? defaultPorts[Math.floor(Math.random() * defaultPorts.length)] : customPort;
        const randomId = Array.from(crypto.getRandomValues(new Uint8Array(6)), v => "abcdefghijklmnopqrstuvwxyz0123456789"[v % 36]).join("");
        return `${ip}:${port}#${randomId}`;
    });
    
    return [ips, ips.join("\n")];
}

// ========== Carrier Identification ==========
function identifyCarrier(request) {
    const cf = request?.cf;
    if (String(cf?.country || "").toLowerCase() !== "cn") return "cf";
    
    const asn = String(cf?.asn || "");
    const asnMap = {
        4134: "ct", 4809: "ct", 4811: "ct", 4812: "ct", 4815: "ct",
        4837: "cu", 4814: "cu", 9929: "cu", 17623: "cu", 17816: "cu",
        9808: "cmcc", 24400: "cmcc", 56040: "cmcc", 56041: "cmcc", 56044: "cmcc"
    };
    
    const org = String(cf?.asOrganization || "").toLowerCase();
    const patterns = [
        { code: "ct", regex: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
        { code: "cmcc", regex: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
        { code: "cu", regex: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ }
    ];
    
    for (const pattern of patterns) {
        if (pattern.regex.test(org)) return pattern.code;
    }
    
    return asnMap[asn] || "cf";
}

// ========== HTML Pages ==========
async function nginxPage() {
    return `<!DOCTYPE html>
<html>
<head><title>StarJin Proxy</title></head>
<body>
<h1>StarJin Proxy</h1>
<p>Advanced proxy service</p>
</body>
</html>`;
}

async function html1101(host, ip) {
    const now = new Date();
    const dateStr = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")} ${String(now.getHours()).padStart(2,"0")}:${String(now.getMinutes()).padStart(2,"0")}:${String(now.getSeconds()).padStart(2,"0")}`;
    const rayId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2,"0")).join("");
    
    return `<!DOCTYPE html>
<html>
<head><title>StarJin - Error 1101</title></head>
<body>
<h1>Error 1101</h1>
<p>Ray ID: ${rayId}</p>
<p>Time: ${dateStr}</p>
<p>Host: ${host}</p>
<p>IP: ${ip}</p>
<p>Worker restarted or took too long to respond.</p>
</body>
</html>`;
}

// ========== TCP Connector ==========
function createTcpConnector(request) {
    const env = request?.env || {};
    const connect = env?.connect;
    if (!connect || typeof connect !== "function") {
        throw new Error("Missing env.connect - not running in Cloudflare Workers");
    }
    return (options, secureOptions) => {
        if (secureOptions === undefined) return connect(options);
        return connect(options, secureOptions);
    };
}

// ========== Main Fetch Handler ==========
globalThis.__workerStart = Date.now();

export default {
    async fetch(request, env, ctx) {
        let url = request.url
            .replace(/%5[Cc]/g, "")
            .replace(/\\/g, "");
        
        const hashIndex = url.indexOf("#");
        const cleanUrl = hashIndex === -1 ? url : url.slice(0, hashIndex);
        
        if (!cleanUrl.includes("?") && /%3f/i.test(cleanUrl)) {
            const fragment = hashIndex === -1 ? "" : url.slice(hashIndex);
            url = cleanUrl.replace(/%3f/i, "?") + fragment;
        }
        
        const parsedUrl = new URL(url);
        const userAgent = request.headers.get("User-Agent") || "Mozilla/5.0";
        const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
        const method = request.method.toLowerCase();
        
        const authKey = env.KEY || env.PASSWORD || env.TOKEN || env.UUID || env.AUTH || "starjin-default-key";
        const hashedKey = await md5Hash(authKey);
        
        const uuidPattern = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const inputUuid = env.UUID || env.uuid;
        const uuid = inputUuid && uuidPattern.test(inputUuid) 
            ? inputUuid.toLowerCase() 
            : [
                hashedKey.slice(0, 8),
                hashedKey.slice(8, 12),
                "4" + hashedKey.slice(13, 16),
                "8" + hashedKey.slice(17, 20),
                hashedKey.slice(20, 32)
            ].join("-");
        
        const hosts = env.HOST 
            ? (await toArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0])
            : [parsedUrl.hostname.split(":")[0]];
        const mainHost = hosts[0];
        const protocol = parsedUrl.protocol.slice(0, -1).toLowerCase();
        
        debugMode = ["1", "true"].includes(env.DEBUG) || debugMode;
        
        if (env.PROXYIP) {
            const ips = await toArray(env.PROXYIP);
            proxyIP = ips[Math.floor(Math.random() * ips.length)];
            fallbackEnabled = false;
        } else {
            proxyIP = (request.cf?.colo + "-starjin.ir").toLowerCase();
        }
        
        const clientIp = request.headers.get("X-Forwarded-For") ||
                         request.headers.get("CF-Connecting-IP") ||
                         request.headers.get("True-Client-IP") ||
                         request.headers.get("X-Real-IP") ||
                         request.cf?.ip || "unknown";
        
        if (cachedWhitelist === null) {
            if (env.GO2SOCKS5) {
                whitelistDomains = [...new Set(whitelistDomains.concat(await toArray(env.GO2SOCKS5)))];
            }
            cachedWhitelist = whitelistDomains;
        } else {
            whitelistDomains = cachedWhitelist;
        }
        
        if (protocol === "starjin" && parsedUrl.searchParams.get("uuid") === uuid) {
            return new Response(JSON.stringify({
                version: parseInt(String(VERSION).replace(/\D/g, "")),
                plans: Object.keys(SUBSCRIPTION_PLANS)
            }), {
                status: 200,
                headers: { "Content-Type": "application/json; charset=utf-8" }
            });
        }
        
        if (parsedUrl.pathname === "/api/plan") {
            return await handlePlanAPI(request, env, uuid);
        }
        
        if (authKey && contentType === "websocket") {
            await loadProxyParams(parsedUrl, uuid);
            log("[WebSocket] Request:", parsedUrl.hostname + parsedUrl.search);
            return await handleWebSocket(request, uuid, parsedUrl);
        }
        
        if (authKey && !parsedUrl.pathname.startsWith("/admin/") && parsedUrl.pathname !== "/favicon.ico" && request.method === "POST") {
            await loadProxyParams(parsedUrl, uuid);
            const referer = request.headers.get("Referer") || "";
            const grpcDetect = referer.includes("/arvan.vless.service") || referer.includes("/arvan.vless");
            
            if (grpcDetect || contentType.startsWith("application/grpc")) {
                log("[gRPC] Request:", parsedUrl.hostname + parsedUrl.search);
                return await handleGrpc(request, uuid);
            }
            
            log("[XHTTP] Request:", parsedUrl.hostname + parsedUrl.search);
            return await handleXHttp(request, uuid);
        }
        
        if (parsedUrl.protocol === "starjin:") {
            return Response.redirect(parsedUrl.href.replace("starjin://", "http://"), 301);
        }
        
        if (!authKey) {
            return fetch(STATIC_URL + parsedUrl.pathname).then(async res => {
                const headers = new Headers(res.headers);
                headers.set("Cache-Control", "public, max-age=3600, must-revalidate, proxy-revalidate");
                headers.set("CDN-Cache-Control", "public, max-age=3600");
                headers.set("Expires", "0");
                let html = await res.text();
                html = html.replace(/"\.\.\/logo\.png"/g, `"${STATIC_URL}logo.png"`);
                html = html.replace(/src=['"]\.\.\/logo\.png['"]/g, `src="${STATIC_URL}logo.png"`);
                return new Response(html, { status: 200, statusText: res.statusText, headers });
            });
        }
        
        if (parsedUrl.pathname === "/favicon.ico") {
            return fetch(STATIC_URL + parsedUrl.pathname).catch(() => {});
        }
        
        if (parsedUrl.pathname === "/cdn-cgi/starjin") {
            return new Response(JSON.stringify({ version: VERSION }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }
        
        if (!env.CONFIG_URL) {
            ctx.waitUntil(logRequest(env, request, clientIp, "Admin_Login", configJSON));
            return fetch(STATIC_URL + "/admin/" + parsedUrl.hostname).then(async res => {
                let html = await res.text();
                html = html.replace(/"\.\.\/logo\.png"/g, `"${STATIC_URL}logo.png"`);
                html = html.replace(/src=['"]\.\.\/logo\.png['"]/g, `src="${STATIC_URL}logo.png"`);
                return new Response(html, { status: res.status, statusText: res.statusText, headers: res.headers });
            }).catch(() => fetch(STATIC_URL + "/404.html").catch(() => new Response("Not Found", { status: 404 })));
        }
        
        let targetUrl = env.CONFIG_URL || "https://example.com";
        if (targetUrl && targetUrl !== "1101" && targetUrl !== "none") {
            targetUrl = targetUrl.toLowerCase().replace(/\/$/, "");
            if (!targetUrl.match(/^https?:\/\//i)) targetUrl = "https://" + targetUrl;
            if (targetUrl.toLowerCase().startsWith("http://worker/")) targetUrl = "https://" + targetUrl.slice(12);
            
            try {
                const target = new URL(targetUrl);
                const headers = new Headers(request.headers);
                headers.set("Host", target.hostname);
                headers.set("Origin", target.origin);
                if (!headers.has("Referer") && userAgent && userAgent !== "unknown") {
                    headers.set("Referer", userAgent);
                }
                
                const response = await fetch(target.href + parsedUrl.pathname + parsedUrl.search, {
                    method: request.method,
                    headers: headers,
                    body: request.body,
                    cf: request.cf
                });
                
                const respType = response.headers.get("Content-Type") || "";
                if (/text|javascript|json|xml/.test(respType)) {
                    let text = await response.text();
                    text = text.replaceAll(target.hostname, parsedUrl.hostname);
                    return new Response(text, {
                        status: response.status,
                        headers: { ...Object.fromEntries(response.headers), "Cache-Control": "no-store" }
                    });
                }
                return response;
            } catch(e) {}
        }
        
        return new Response(await nginxPage(), {
            status: 200,
            headers: { "Content-Type": "text/html; charset=UTF-8" }
        });
    }
};