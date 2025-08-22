// netlify/edge-functions/guarda.js

export default async (request, context) => {
  const cookies = lerCookies(request.headers.get("cookie") || "");
  const token = cookies["quiz_auth"];
  if (!token) return negar();

  const [expStr, assinatura] = token.split(".");
  const exp = parseInt(expStr, 10);
  if (!exp || !assinatura) return negar();

  const agora = Math.floor(Date.now() / 1000);
  if (agora > exp) return negar("Seu acesso expirou. Volte pelo botão da plataforma.");

  // revalida a assinatura usando a mesma LINK_KEY
  const LINK_KEY = Deno.env.get("LINK_KEY") || "";
  const esperada = await hmacSha256(LINK_KEY, expStr);
  if (assinatura !== esperada) return negar();

  // liberado: entrega o arquivo solicitado (/quiz/...)
  return context.next();
};

function lerCookies(str) {
  const out = {};
  str.split(";").forEach((p) => {
    const [k, v] = p.trim().split("=");
    if (k) out[k] = decodeURIComponent(v || "");
  });
  return out;
}

async function hmacSha256(chave, texto) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(chave),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const assinatura = await crypto.subtle.sign("HMAC", key, enc.encode(texto));
  return Array.from(new Uint8Array(assinatura))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function negar(msg = "Acesso negado. Abra o quiz pelo botão dentro da plataforma.") {
  return new Response(
    `<!doctype html><meta charset="utf-8"><h1>${msg}</h1>`,
    { status: 403, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}
