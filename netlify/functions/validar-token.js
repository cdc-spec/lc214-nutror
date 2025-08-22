// netlify/functions/validar-token.js
exports.handler = async (event) => {
  const LINK_KEY = process.env.LINK_KEY || "";
  const token = (event.queryStringParameters && event.queryStringParameters.token) || "";

  if (!LINK_KEY) {
    return json(500, { success: false, error: "LINK_KEY ausente no ambiente." });
  }

  // Aqui a regra é simples: o "token" precisa ser igual à LINK_KEY.
  // (A autorização real é feita no Edge pelo cookie HttpOnly assinado.)
  if (token && token === LINK_KEY) {
    return json(200, { success: true });
  }

  return json(403, { success: false, error: "Token inválido." });
};

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(obj),
  };
}
