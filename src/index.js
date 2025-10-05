export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, info: "marxia-save-lite ready" });
    }

    if (request.method === "POST" && url.pathname === "/api/save") {
      return handleSave(request, env);
    }

    return json({ ok: false, error: "not_found", path: url.pathname, method: request.method }, 404);
  }
};

/* ---------------- OPS CySec (lite) core ---------------- */

async function handleSave(request, env) {
  // 1) Input limit & parse (no CORS/CSP)
  const MAX = 64 * 1024; // 64KB hard cap
  const buf = await readLimited(request, MAX);
  if (!buf) return json({ ok: false, error: "payload_too_large" }, 413);

  const raw = new TextDecoder().decode(buf);
  let rows;
  try { rows = JSON.parse(raw); } catch { return json({ ok: false, error: "invalid_json" }, 400); }

  // Accept either array of rows (your current front-end) or wrapper { rows:[...], ... }
  const isArrayOnly = Array.isArray(rows);
  const dataRows = isArrayOnly ? rows : (Array.isArray(rows?.rows) ? rows.rows : null);
  if (!Array.isArray(dataRows) || dataRows.length === 0) {
    return json({ ok: false, error: "empty_rows" }, 400);
  }

  // 2) Collect request meta (no extra headers added to response)
  const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "";
  const ua = request.headers.get("User-Agent") || "";

  // 3) Normalize & sanitize rows
  const IVA_RATE = 0.15;
  const norm = [];
  for (const r of dataRows) {
    // expected fields: timestamp, item, qty, subtotal, vat, total
    const timestamp = safeText(r.timestamp, 64);
    const item_name = safeText(r.item, 96);
    const qty = toInt(r.qty, 1, 9999);
    const subtotal_usd = toMoney(r.subtotal);
    const vat_usd = toMoney(r.vat);
    const total_usd = toMoney(r.total);
    if (!timestamp || !item_name || qty <= 0) {
      return json({ ok: false, error: "invalid_row", hint: { item_name, qty } }, 422);
    }
    norm.push({ timestamp, item_name, qty, subtotal_usd, vat_usd, total_usd, currency: "USD", iva_rate: IVA_RATE });
  }

  // Optional delivery/contact fields (supported if the client sends them)
  const wrapper = isArrayOnly ? null : rows;
  const payload = {
    rows: norm,
    source_ip: ip,
    user_agent: ua,
    delivery_address: safeText(getOpt(wrapper, "delivery_address"), 200),
    whatsapp: safeText(getOpt(wrapper, "whatsapp"), 50),
    email: safeText(getOpt(wrapper, "email"), 120),
    delivery_lat: safeText(getOpt(wrapper, "delivery_lat"), 32),
    delivery_lng: safeText(getOpt(wrapper, "delivery_lng"), 32),
    status: "pending"
  };

  // 4) Sign (OPS CySec: integrity + replay-guard field)
  const tsHeader = new Date().toISOString();
  const bodyString = JSON.stringify(payload);
  const bodyHash = await sha256base64(bodyString);
  const signature = await hmacSha256Base64(env.SIGNING_KEY, `${tsHeader}.${bodyHash}`);

  // 5) Relay to Apps Script (no CORS/CSP on our side)
  const res = await fetch(env.APP_SCRIPT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Asset-ID": env.ASSET_ID,
      "X-KID": env.KID,
      "X-Timestamp": tsHeader,
      "X-Body-Hash": bodyHash,
      "X-Signature": signature
    },
    body: bodyString
  });

  const text = await res.text().catch(() => "");
  if (res.ok && /success/i.test(text)) {
    return json({ ok: true, forwarded: true });
  }
  return json({ ok: false, forwarded: false, status: res.status, body: text.slice(0, 3000) }, 502);
}

/* ---------------- Utilities (sanitizers, limits, crypto) ---------------- */

async function readLimited(request, maxBytes) {
  // Read streaming body up to maxBytes
  const reader = request.body?.getReader?.();
  if (!reader) {
    const t = await request.text().catch(() => "");
    const buf = new TextEncoder().encode(t);
    return buf.byteLength > maxBytes ? null : buf;
  }
  let received = 0;
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) return null;
    chunks.push(value);
  }
  return concat(chunks);
}
function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

function safeText(v, max = 200) {
  if (typeof v !== "string") return "";
  const s = v.replace(/[<>]/g, "").replace(/[\u0000-\u001F]+/g, " ").trim();
  return s.length > max ? s.slice(0, max) : s;
}
function toInt(v, min = 0, max = 1e9) {
  const n = Number.parseInt(String(v), 10);
  if (!Number.isFinite(n)) return 0;
  return Math.min(Math.max(n, min), max);
}
function toMoney(v) {
  const n = Number.parseFloat(String(v));
  if (!Number.isFinite(n) || n < 0) return "0.00";
  return n.toFixed(2);
}
function getOpt(obj, key) {
  if (!obj || typeof obj !== "object") return undefined;
  return obj[key];
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" } // no CORS/CSP
  });
}

// Crypto helpers
async function sha256base64(str) {
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return b64(new Uint8Array(digest));
}
async function hmacSha256Base64(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64(new Uint8Array(sig));
}
function b64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
