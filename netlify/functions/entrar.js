// netlify/functions/entrar.js
const crypto = require("crypto");

const LINK_KEY = process.env.LINK_KEY || ""; // defina no Netlify: superkeylc214
const COOKIE_MAX_AGE = 10 * 60; // 10 minutos

exports.handler = async (event) => {
  // 1) validar a chave do link (?k=...)
  const k = (event.queryStringParameters && event.queryStringParameters.k) || "";
  if (!LINK_KEY || k !== LINK_KEY) {
    return html403("Acesso negado. Use o botão dentro da plataforma (Nutror).");
  }

  // 2) gerar token com expiração (para o Edge validar via HMAC)
  const expiraEm = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const assinatura = crypto.createHmac("sha256", LINK_KEY).update(String(expiraEm)).digest("hex");
  const tokenAssinado = `${expiraEm}.${assinatura}`;

  // 3) montar cookies
  const cookieAuthParts = [
    `quiz_auth=${tokenAssinado}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${COOKIE_MAX_AGE}`,
  ];
  const cookieOkParts = [
    "quiz_ok=1",
    "Path=/",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${COOKIE_MAX_AGE}`,
  ];

  // 4) redirecionar para /quiz/ COM ?token=... (o seu index.html exige esse param)
  //    Observação: esse token NÃO é usado na segurança; é só para a UI validar no validar-token.js.
  const location = `/quiz/?token=${encodeURIComponent(k)}`;

  return {
    statusCode: 302,
    headers: {
      "Set-Cookie": [cookieAuthParts.join("; "), cookieOkParts.join("; ")],
      Location: location,
    },
    body: "",
  };
};

function html403(msg) {
  return {
    statusCode: 403,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><meta charset="utf-8"><h1>${msg}</h1>`,
  };
}
