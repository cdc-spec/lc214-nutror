// netlify/functions/entrar.js
const crypto = require("crypto");

const COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "quiz_sess";
const LINK_KEY = process.env.LINK_KEY;
const TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 12 * 60 * 60);
const RENEW_WINDOW_SECONDS = Number(process.env.RENEW_WINDOW_SECONDS || 2 * 60 * 60);
const COOKIE_PATH = process.env.SESSION_COOKIE_PATH || "/quiz";
const ALLOWED_REFERRERS = (process.env.ALLOWED_REFERRERS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);

function b64url(input) { return Buffer.from(input).toString("base64url"); }
function sign(data) { return crypto.createHmac("sha256", LINK_KEY).update(data).digest("base64url"); }
function hashUA(ua) { return crypto.createHash("sha256").update(ua || "").digest("hex").slice(0, 16); }

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
  if (!referer) return false; // *** obrigatório vir de link (não vale colar na barra) ***
  if (!ALLOWED_REFERRERS.length) return false; // *** exija configuração explícita ***
  try {
    const host = new URL(referer).hostname.toLowerCase();
    return ALLOWED_REFERRERS.some(a => host === a || host.endsWith(`.${a}`));
  } catch { return false; }
}

exports.handler = async (event) => {
  if (!LINK_KEY) return { statusCode: 500, body: "LINK_KEY não configurada." };

  const qs = event.queryStringParameters || {};
  const tokenFromLink = qs.token || "";
  // Força redirecionar SEM token na URL final
  const redirect = "/quiz/"; 

  if (!tokenFromLink || tokenFromLink !== LINK_KEY) {
    return { statusCode: 401, body: "Acesso negado (token inválido)." };
  }

  const referer = event.headers?.referer || event.headers?.Referer || "";
  if (!isAllowedReferrer(referer)) {
    return { statusCode: 401, body: "Acesso negado (origem não autorizada)." };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const uaHash = hashUA(event.headers["user-agent"] || event.headers["User-Agent"]);
  const expSec = nowSec + TTL_SECONDS;
  const sessToken = buildToken({ uaHash, iatSec: nowSec, expSec });

  const cookie = buildCookie(sessToken);

  return {
    statusCode: 302,
    headers: {
      "Cache-Control": "no-store",
      "Set-Cookie": cookie,
      Location: redirect,
    },
  };
};
