// netlify/functions/entrar.js
const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || "";   // defina no Netlify (Site settings → Environment variables)
const COOKIE_MAX_AGE = 10 * 60;                // 10 minutos

exports.handler = async (event) => {
  try {
    // 1) validar a chave do link (?k=...)
    const k = (event.queryStringParameters && event.queryStringParameters.k) || "";
    if (!LINK_KEY || k !== LINK_KEY) {
      return {
        statusCode: 403,
        headers: { "content-type": "text/html; charset=utf-8" },
        body: `
          <h1>Acesso negado</h1>
          <p>Use o link da plataforma (Nutror) para entrar.</p>
        `,
      };
    }

    // 2) gerar token assinado com expiração (epoch em segundos)
    const expiraEm = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const payload = String(expiraEm);
    const assinatura = crypto.createHmac("sha256", LINK_KEY).update(payload).digest("hex");
    const token = `${expiraEm}.${assinatura}`;

    // 3) emitir cookie HttpOnly e redirecionar para /quiz/ (SEM ?k=...)
    const cookie = [
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
        "Set-Cookie": cookie,   // precisa ser string única (não array)
        Location: "/quiz/",
        "Cache-Control": "no-store",
      },
      body: "",
    };
  } catch (err) {
    // resposta simples em caso de erro inesperado
    return {
      statusCode: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
      body: "Erro interno.",
    };
  }
};
