const { getStore } = require("@netlify/blobs");

exports.handler = async (event, context) => {
  // Os parâmetros da URL são obtidos do evento
  const token = event.queryStringParameters.token;

  if (!token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ success: false, error: "Token ausente" }),
    };
  }

  const store = getStore("tokens_de_acesso");
  
  // Pega e deleta o token para garantir uso único
  const tokenData = await store.get(token, { type: "json" });
  await store.delete(token);

  if (!tokenData) {
    return {
      statusCode: 403,
      body: JSON.stringify({ success: false, error: "Token inválido" }),
    };
  }

  if (tokenData.expires < Date.now()) {
    return {
      statusCode: 403,
      body: JSON.stringify({ success: false, error: "Token expirado" }),
    };
  }

  // Se tudo estiver OK, retorna sucesso
  return {
    statusCode: 200,
    body: JSON.stringify({ success: true }),
  };
};
