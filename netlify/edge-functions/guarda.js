// netlify/edge-functions/guarda.js

const COOKIE_MAX_AGE = 60;  // 8h
const RENEW_IF_LT   = 15;      // renova se faltar < 15min

export default async (request, context) => {
  const url = new URL(request.url);
  const LINK_KEY = Deno.env.get("LINK_KEY") || "";
  const cookies = parseCookies(request.headers.get("cookie") || "");
  let token = cookies["quiz_auth"];

  // Plano B: se veio com ?token= (ou ?k=) e ainda não tem cookie, emite e limpa query
  if (!token) {
    const incoming = url.searchParams.get("token") || url.searchParams.get("k") || "";
    if (LINK_KEY && incoming && incoming === LINK_KEY) {
      const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
      const sig = await hmacSha256(LINK_KEY, String(exp));
      const newToken = `${exp}.${sig}`;
      const headers = new Headers({ Location: url.pathname });
      headers.append("Set-Cookie", buildCookie(newToken, COOKIE_MAX_AGE));
      return new Response("", { status: 302, headers });
    }
    return deny();
  }

  const [expStr, sig] = token.split(".");
  const exp = parseInt(expStr, 10);
  if (!exp || !sig) return deny();

  const now = Math.floor(Date.now() / 1000);
  if (now > exp) return deny("Seu acesso expirou. Clique novamente no botão da plataforma.");

  const expected = await hmacSha256(LINK_KEY, expStr);
  if (sig !== expected) return deny();

  // Ok, entrega o recurso
  const response = await context.next();

  // Renovação silenciosa
  const remaining = exp - now;
  if (remaining < RENEW_IF_LT) {
    const newExp = now + COOKIE_MAX_AGE;
    const newSig = await hmacSha256(LINK_KEY, String(newExp));
    const refreshed = `${newExp}.${newSig}`;
    response.headers.append("Set-Cookie", buildCookie(refreshed, COOKIE_MAX_AGE));
  }

  return response;
};

function parseCookies(str) {
  const out = {};
  str.split(";").forEach((p) => {
    const [k, v] = p.trim().split("=");
    if (k) out[k] = decodeURIComponent(v || "");
  });
  return out;
}

function buildCookie(value, maxAge) {
  return [
    `quiz_auth=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`,
  ].join("; ");
}

async function hmacSha256(secret, text) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function deny(msg = "Acesso negado. Abra o quiz pelo botão dentro da plataforma.") {
  return new Response(
    `<!doctype html><meta charset="utf-8"><h1>${msg}</h1>`,
    { status: 403, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}
