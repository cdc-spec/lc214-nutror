const { getStore } = require("@netlify/blobs");

exports.handler = async (event, context) => {
  const token = event.queryStringParameters.token;

  if (!token) {
    return {
      statusCode: 400,
      body: JSON.stringify({ success: false, error: "Token ausente" }),
    };
  }
  
  // Passando as credenciais manualmente, como sugerido pelo erro
  const store = getStore({
    name: "tokens_de_acesso",
    siteID: process.env.SITE_ID,
    token: process.env.NETLIFY_API_TOKEN,
  });

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
  return {
    statusCode: 200,
    body: JSON.stringify({ success: true }),
  };
};

