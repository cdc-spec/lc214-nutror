// netlify/functions/entrar.js
const crypto = require("crypto");

const COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "quiz_sess";
const LINK_KEY = process.env.LINK_KEY;
const TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 12 * 60 * 60);
const RENEW_WINDOW_SECONDS = Number(process.env.RENEW_WINDOW_SECONDS || 2 * 60 * 60);
const COOKIE_PATH = process.env.SESSION_COOKIE_PATH || "/quiz";

/**
 * IMPORTANTÍSSIMO:
 * - Coloque apenas HOSTs aqui (sem https:// e sem /caminhos), ex.: "app.nutror.com".
 * - Você pode listar mais de um, separados por vírgula.
 * - Se o Nutror manda no-referrer, use o fallback por Fetch Metadata (abaixo).
 */
const RAW_ALLOWED = (process.env.ALLOWED_REFERRERS || "");

/** Habilita fallback por Fetch Metadata (para o caso de no-referrer no Nutror) */
const ALLOW_FETCH_METADATA_FALLBACK = String(process.env.ALLOW_FETCH_METADATA_FALLBACK || "true").toLowerCase() === "true";

function normalizeAllowed(listStr) {
  return listStr
    .split(",")
    .map(s => s.trim())
    .map(s => {
      if (!s) return "";
      try { return new URL(s).hostname.toLowerCase(); } // se vier "https://host/...", extrai hostname
      catch { return s.replace(/^https?:\/\//, "").split("/")[0].toLowerCase(); }
    })
    .filter(Boolean);
}
const ALLOWED_REFERRERS = normalizeAllowed(RAW_ALLOWED);

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

function refererAllowed(referer) {
  if (!referer) return false;
  try {
    const host = new URL(referer).hostname.toLowerCase();
    return ALLOWED_REFERRERS.length > 0 && ALLOWED_REFERRERS.some(a => host === a || host.endsWith(`.${a}`));
  } catch { return false; }
}

/**
 * Fallback baseado em Fetch Metadata:
 * Permite navegações top-level iniciadas por clique, vindas de outro site,
 * mesmo sem Referer (cobre o caso do Nutror com no-referrer).
 * Bloqueia URL colada/digitada (sec-fetch-site === "none").
 */
function fetchMetadataAllows(headers) {
  if (!ALLOW_FETCH_METADATA_FALLBACK) return false;
  const sfSite = headers["sec-fetch-site"] || headers["Sec-Fetch-Site"] || "";
  const sfMode = headers["sec-fetch-mode"] || headers["Sec-Fetch-Mode"] || "";
  const sfUser = headers["sec-fetch-user"] || headers["Sec-Fetch-User"] || "";

  // Regras: clique do usuário, navegação top-level, e NÃO 'none' (ou seja, não foi colada/digitada).
  const isUserClick = sfUser === "?1";
  const isTopNav   = sfMode === "navigate";
  const notTyped   = sfSite && sfSite.toLowerCase() !== "none";

  // Se quiser ser mais estrito, troque notTyped por (sfSite.toLowerCase() === "cross-site")
  return isUserClick && isTopNav && notTyped;
}

exports.handler = async (event) => {
  if (!LINK_KEY) {
    return { statusCode: 500, body: "LINK_KEY não configurada." };
  }

  const qs = event.queryStringParameters || {};
  const tokenFromLink = qs.token || "";
  const redirect = "/quiz/"; // SEM token na URL final

  if (!tokenFromLink || tokenFromLink !== LINK_KEY) {
    return { statusCode: 401, body: "Acesso negado (token inválido)." };
  }

  const headers = event.headers || {};
  const referer = headers.referer || headers.Referer || "";

  const viaReferer = refererAllowed(referer);
  const viaFetchMD = !viaReferer && fetchMetadataAllows(headers);

  if (!viaReferer && !viaFetchMD) {
    // Resposta com debug leve para facilitar diagnóstico
    const dbg = {
      allowed: ALLOWED_REFERRERS,
      referer: referer || "(vazio)",
      "sec-fetch-site": headers["sec-fetch-site"] || headers["Sec-Fetch-Site"] || "(vazio)",
      "sec-fetch-mode": headers["sec-fetch-mode"] || headers["Sec-Fetch-Mode"] || "(vazio)",
      "sec-fetch-user": headers["sec-fetch-user"] || headers["Sec-Fetch-User"] || "(vazio)",
      fallback: ALLOW_FETCH_METADATA_FALLBACK ? "on" : "off",
    };
    return {
      statusCode: 401,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
      body: JSON.stringify({ error: "Acesso negado (origem não autorizada).", dbg }, null, 2),
    };
  }

  // Gera sessão
  const nowSec = Math.floor(Date.now() / 1000);
  const uaHash = hashUA(headers["user-agent"] || headers["User-Agent"]);
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
