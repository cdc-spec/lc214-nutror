// netlify/functions/entrar.js
const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || "";
const COOKIE_MAX_AGE = 60; // 8h de sessão

exports.handler = async (event) => {
  try {
    const k = (event.queryStringParameters && event.queryStringParameters.k) || "";
    if (!LINK_KEY || k !== LINK_KEY) {
      return {
        statusCode: 403,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: `<h1>Acesso negado</h1><p>Use o link da plataforma (Nutror) para entrar.</p>`,
      };
    }

    // Gera token assinado com expiração (epoch + HMAC)
    const expiraEm = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const payload = String(expiraEm);
    const assinatura = crypto.createHmac("sha256", LINK_KEY).update(payload).digest("hex");
    const token = `${expiraEm}.${assinatura}`;

    // Limpa eventual cookie antigo + seta cookie novo
    const cookieDeLimpeza = "quiz_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
    const cookieNovo = [
      `quiz_auth=${token}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${COOKIE_MAX_AGE}`,
    ].join("; ");

    return {
      statusCode: 302,
      headers: {
        // IMPORTANTE: inclua ?token= para seu index.html ficar “feliz”
        Location: `/quiz/?token=${encodeURIComponent(k)}`,
        "Cache-Control": "no-store",
      },
      multiValueHeaders: {
        "Set-Cookie": [cookieDeLimpeza, cookieNovo],
      },
      body: "",
    };
  } catch (err) {
    console.error("Erro na função 'entrar':", err);
    return {
      statusCode: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: "Erro interno do servidor.",
    };
  }
};
