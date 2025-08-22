// netlify/functions/entrar.js
// Node 18+ (Netlify Functions - CommonJS)

const crypto = require("crypto");

const COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "quiz_sess";
const LINK_KEY = process.env.LINK_KEY; // já configurada
const TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 12 * 60 * 60); // 12h
const RENEW_WINDOW_SECONDS = Number(process.env.RENEW_WINDOW_SECONDS || 2 * 60 * 60); // 2h (usado pelo guarda)
const COOKIE_PATH = process.env.SESSION_COOKIE_PATH || "/quiz";
const ALLOWED_REFERRERS = (process.env.ALLOWED_REFERRERS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean); // ex.: "nutror.com,app.nutror.com.br"

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}
function sign(data) {
  return crypto.createHmac("sha256", LINK_KEY).update(data).digest("base64url");
}
function hashUA(ua) {
  return crypto.createHash("sha256").update(ua || "").digest("hex").slice(0, 16);
}
function buildToken({ uaHash, iatSec, expSec }) {
  const payload = { v: 1, ua: uaHash, iat: iatSec, exp: expSec };
  const body = b64url(JSON.stringify(payload));
  const sig = sign(body);
  return `${body}.${sig}`;
}
function buildCookie(token) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    `Path=${COOKIE_PATH}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${TTL_SECONDS}`,
  ];
  return parts.join("; ");
}
function isAllowedReferrer(referer) {
  if (!ALLOWED_REFERRERS.length) return true; // sem política -> permite
  try {
    const host = new URL(referer).hostname.toLowerCase();
    return ALLOWED_REFERRERS.some(allowed => {
      const a = allowed.toLowerCase();
      return host === a || host.endsWith(`.${a}`);
    });
  } catch {
    // Referer ausente/inválido -> se você quiser travar em produção, troque para `return false`
    return false;
  }
}

exports.handler = async (event) => {
  if (!LINK_KEY) {
    return { statusCode: 500, body: "LINK_KEY não configurada." };
  }

  const qs = event.queryStringParameters || {};
  const tokenFromLink = qs.token || "";
  const redirect = qs.redirect || "/quiz/";

  // 1) valida token do link
  if (!tokenFromLink || tokenFromLink !== LINK_KEY) {
    return { statusCode: 401, body: "Acesso negado (token inválido)." };
  }

  // 2) reforço opcional: referer Nutror
  const referer = event.headers?.referer || event.headers?.Referer || "";
  if (!isAllowedReferrer(referer)) {
    return { statusCode: 401, body: "Acesso negado (origem não autorizada)." };
  }

  // 3) gera sessão HMAC (12h) vinculada ao UA
  const nowSec = Math.floor(Date.now() / 1000);
  const uaHash = hashUA(event.headers["user-agent"] || event.headers["User-Agent"]);
  const expSec = nowSec + TTL_SECONDS;
  const sessToken = buildToken({ uaHash, iatSec: nowSec, expSec });

  const cookie = buildCookie(sessToken);

  // Observação: para múltiplos cookies, use multiValueHeaders (ver comentário abaixo).
  return {
    statusCode: 302,
    headers: {
      "Cache-Control": "no-store",
      "Set-Cookie": cookie,
      Location: redirect,
    },
    // Se você PRECISAR setar mais de um cookie:
    // multiValueHeaders: { "Set-Cookie": [cookie, "outro=valor; Path=/; Secure; HttpOnly"] }
  };
};
