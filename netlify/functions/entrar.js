// netlify/functions/entrar.js
const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || ""; // você vai configurar no Netlify
const COOKIE_MAX_AGE = 10 * 60; // 10 minutos

exports.handler = async (event) => {
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

  // 2) gerar um carimbo simples com expiração
  const expiraEm = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const dado = String(expiraEn);
  const assinatura = crypto.createHmac("sha256", LINK_KEY).update(dado).digest("hex");
  const token = `${expiraEm}.${assinatura}`;

  const cookie = [
    `quiz_auth=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${COOKIE_MAX_AGE}`,
  ].join("; ");

  // 3) redirecionar para /quiz (onde está seu index.html do quiz)
  return {
    statusCode: 302,
    headers: {
      "Set-Cookie": cookie,
      Location: "/quiz/",
    },
    body: "",
  };
};
