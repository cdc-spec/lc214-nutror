const { getStore } = require("@netlify/blobs");
const { randomUUID } = require("crypto");

exports.handler = async (event, context) => {
  const siteURL = new URL(event.rawUrl).origin;
  
  // Passando as credenciais manualmente, como sugerido pelo erro
  const store = getStore({
    name: "tokens_de_acesso",
    siteID: process.env.SITE_ID,
    token: process.env.NETLIFY_API_TOKEN,
  });
  
  const token = randomUUID();
  const expiration = Date.now() + 2 * 60 * 1000;
  await store.setJSON(token, { expires: expiration });
  
  const redirectURL = `${siteURL}/?token=${token}`;
  
  return {
    statusCode: 302,
    headers: {
      Location: redirectURL,
    },
  };
};
