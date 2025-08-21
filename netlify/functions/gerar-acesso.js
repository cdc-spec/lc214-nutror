const { getStore } = require("@netlify/blobs");
const { randomUUID } = require("crypto");

exports.handler = async (event, context) => {
  // A URL base do site é obtida a partir do cabeçalho do evento
  const siteURL = new URL(event.rawUrl).origin;
  
  const store = getStore("tokens_de_acesso");
  const token = randomUUID();
  const expiration = Date.now() + 2 * 60 * 1000; // 2 minutos em milissegundos
  
  await store.setJSON(token, { expires: expiration });
  
  const redirectURL = `${siteURL}/?token=${token}`;
  
  // Retorna uma resposta de redirecionamento
  return {
    statusCode: 302,
    headers: {
      Location: redirectURL,
    },
  };
};
