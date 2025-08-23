// netlify/functions/questoes.js
const crypto = require("crypto");

// ⚠️ importa o banco agora FORA da área pública (bundler embute no pacote)
const QUESTIONS = require("../data/questoes.json");

const COOKIE_NAME = process.env.SESSION_COOKIE_NAME || "quiz_sess";
const LINK_KEY = process.env.LINK_KEY;

function parseCookies(h) {
  const c = {};
  (h || "").split(";").map(s => s.trim()).forEach(kv => {
    const i = kv.indexOf("="); if (i > -1) c[kv.slice(0, i)] = kv.slice(i + 1);
  });
  return c;
}
function b64urlToString(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  return Buffer.from(b64 + pad, "base64").toString("utf8");
}
function sign(body) {
  return crypto.createHmac("sha256", LINK_KEY).update(body).digest("base64url");
}
function hashUA(ua) {
  return crypto.createHash("sha256").update(ua || "").digest("hex").slice(0, 16);
}

exports.handler = async (event) => {
  try {
    if (!LINK_KEY) {
      return { statusCode: 500, body: "LINK_KEY não configurada." };
    }

    // 1) Lê cookie
    const cookies = parseCookies(event.headers.cookie || event.headers.Cookie || "");
    const raw = cookies[COOKIE_NAME];
    if (!raw) {
      return {
        statusCode: 401,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
        body: "Acesso restrito. Abra o quiz pelo botão do Nutror."
      };
    }

    // 2) Valida HMAC + expiração + amarração leve ao UA
    const dot = raw.lastIndexOf(".");
    if (dot <= 0) return deny("Sessão inválida.");

    const body64 = raw.slice(0, dot);
    const sig = raw.slice(dot + 1);

    const expected = sign(body64);
    if (expected !== sig) return deny("Sessão inválida (assinatura).");

    let payload;
    try {
      payload = JSON.parse(b64urlToString(body64));
    } catch {
      return deny("Sessão inválida (payload).");
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || nowSec >= payload.exp) return deny("Sessão expirada.");

    const ua = event.headers["user-agent"] || event.headers["User-Agent"] || "";
    if (payload.ua !== hashUA(ua)) return deny("Sessão inválida (contexto diferente).");

    // 3) OK → devolve as questões
    return {
      statusCode: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "private, no-store"
      },
      body: JSON.stringify(QUESTIONS)
    };
  } catch (e) {
    return { statusCode: 500, body: "Erro interno." };
  }
};

function deny(msg) {
  return {
    statusCode: 401,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    body: msg
  };
}
