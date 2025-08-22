// netlify/edge-functions/guarda.js
// Netlify Edge Runtime (Deno + Web Crypto)

const COOKIE_NAME = Deno.env.get("SESSION_COOKIE_NAME") || "quiz_sess";
const LINK_KEY = Deno.env.get("LINK_KEY");
const TTL_SECONDS = Number(Deno.env.get("SESSION_TTL_SECONDS") || 12 * 60 * 60);
const RENEW_WINDOW_SECONDS = Number(Deno.env.get("RENEW_WINDOW_SECONDS") || 2 * 60 * 60);
const COOKIE_PATH = Deno.env.get("SESSION_COOKIE_PATH") || "/quiz";

const enc = new TextEncoder();

function parseCookies(header) {
  const c = {};
  (header || "")
    .split(";")
    .map(s => s.trim())
    .forEach(kv => {
      const i = kv.indexOf("=");
      if (i > -1) c[kv.slice(0, i)] = kv.slice(i + 1);
    });
  return c;
}

function b64urlEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecodeToString(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  const b64p = pad ? b64 + "=".repeat(4 - pad) : b64;
  return atob(b64p);
}
async function hmacBase64Url(data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(LINK_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return b64urlEncode(new Uint8Array(sig));
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str || ""));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
function buildCookie(token) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    `Path=${COOKIE_PATH}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${TTL_SECONDS}`
  ];
  return parts.join("; ");
}

export default async (request, context) => {
  if (!LINK_KEY) {
    return new Response("Configuração ausente (LINK_KEY).", {
      status: 500,
      headers: { "Cache-Control": "no-store", "X-Guard": "deny" }
    });
  }

  const url = new URL(request.url);

  // (0) Normalizações de URL numa tacada só (menos rediretos)
  const before = url.toString();
  if (url.searchParams.has("token")) url.searchParams.delete("token");
  if (url.pathname === "/quiz") url.pathname = "/quiz/"; // força barra final
  if (url.toString() !== before) {
    return new Response(null, {
      status: 302,
      headers: { Location: url.toString(), "Cache-Control": "no-store", "X-Guard": "sanitize" }
    });
  }

  // (1) Ler cookie
  const cookies = parseCookies(request.headers.get("cookie") || request.headers.get("Cookie") || "");
  const raw = cookies[COOKIE_NAME];
  if (!raw) {
    const body = `<meta charset="utf-8"><p>Acesso restrito. Abra o quiz pelo botão do Nutror.</p>`;
    return new Response(body, {
      status: 401,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "X-Guard": "deny"
      }
    });
  }

  // (2) body.sig
  const dot = raw.lastIndexOf(".");
  if (dot <= 0) {
    return new Response("Sessão inválida.", {
      status: 401,
      headers: { "cache-control": "no-store", "X-Guard": "deny" }
    });
  }
  const body64 = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);

  // (3) Assinatura
  const expected = await hmacBase64Url(body64);
  if (expected !== sig) {
    return new Response("Sessão inválida (assinatura).", {
      status: 401,
      headers: { "cache-control": "no-store", "X-Guard": "deny" }
    });
  }

  // (4) Payload
  let payload;
  try {
    const json = b64urlDecodeToString(body64);
    payload = JSON.parse(json);
  } catch {
    return new Response("Sessão inválida (payload).", {
      status: 401,
      headers: { "cache-control": "no-store", "X-Guard": "deny" }
    });
  }

  // (5) Expiração
  const nowSec = Math.floor(Date.now() / 1000);
  if (!payload.exp || nowSec >= payload.exp) {
    const body = `<meta charset="utf-8"><p>Sessão expirada. Volte ao Nutror e clique no botão do quiz.</p>`;
    return new Response(body, {
      status: 401,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "X-Guard": "deny"
      }
    });
  }

  // (6) Amarra leve ao user-agent
  const ua = request.headers.get("user-agent") || "";
  const uaHash = await sha256Hex(ua);
  if (payload.ua !== uaHash) {
    return new Response("Sessão inválida (contexto diferente).", {
      status: 401,
      headers: { "cache-control": "no-store", "X-Guard": "deny" }
    });
  }

  // (7) Renovação silenciosa
  let setCookieHeader = null;
  if ((payload.exp - nowSec) <= RENEW_WINDOW_SECONDS) {
    const newPayload = { v: 1, ua: uaHash, iat: nowSec, exp: nowSec + TTL_SECONDS };
    const newBody = b64urlEncode(enc.encode(JSON.stringify(newPayload)));
    const newSig = await hmacBase64Url(newBody);
    const newToken = `${newBody}.${newSig}`;
    setCookieHeader = buildCookie(newToken);
  }

  // (8) Segue para o conteúdo
  const response = await context.next();

  // (9) Cabeçalhos finais
  response.headers.set("Cache-Control", "private, max-age=0, no-store");
  response.headers.set("X-Guard", "hit");
  if (setCookieHeader) response.headers.append("Set-Cookie", setCookieHeader);

  return response;
};
