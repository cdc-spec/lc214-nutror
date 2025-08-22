// Arquivo: netlify/functions/entrar.js (CÓDIGO COM A CORREÇÃO FINAL)
const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || "";
const COOKIE_MAX_AGE = 60; //  1 minuto de sessão

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

    // Gerar novo token assinado com expiração
    const expiraEm = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const payload = String(expiraEm);
    const assinatura = crypto.createHmac("sha256", LINK_KEY).update(payload).digest("hex");
    const token = `${expiraEm}.${assinatura}`;

    // Cookie para limpar o antigo. Definimos a validade como 0.
    const cookieDeLimpeza = "quiz_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

    // Cookie novo com o token válido
    const cookieNovo = [
      `quiz_auth=${token}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${COOKIE_MAX_AGE}`,
    ].join("; ");

    // CORREÇÃO FINAL: Usando multiValueHeaders para enviar múltiplos cookies
    return {
      statusCode: 302,
      headers: {
        Location: "/quiz/",
        "Cache-Control": "no-store",
      },
      multiValueHeaders: {
        "Set-Cookie": [cookieDeLimpeza, cookieNovo],
      },
      body: "",
    };
  } catch (err) {
    console.error("Erro na função 'entrar':", err); // Adicionado log de erro para depuração
    return {
      statusCode: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: "Erro interno do servidor.",
    };
  }
};
