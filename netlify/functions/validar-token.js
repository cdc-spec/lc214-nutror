import { getStore } from "@netlify/blobs";

export default async (req, context) => {
  // Pega o token que foi enviado na URL (ex: ...?token=xyz)
  const urlParams = new URL(req.url).searchParams;
  const token = urlParams.get("token");

  // Se não enviaram um token, acesso negado.
  if (!token) {
    return new Response(JSON.stringify({ success: false, error: "Token ausente" }), { status: 400 });
  }

  const store = getStore("tokens_de_acesso");

  // Pega as informações do token E JÁ O DELETA do banco de dados.
  // Isso garante que ele só possa ser usado UMA VEZ.
  const tokenData = await store.get(token, { type: "json" });
  await store.delete(token);

  // Se o token não foi encontrado no banco (já foi usado ou nunca existiu)
  if (!tokenData) {
    return new Response(JSON.stringify({ success: false, error: "Token inválido" }), { status: 403 });
  }

  // Se o token expirou (a data de expiração é menor que a data atual)
  if (tokenData.expires < Date.now()) {
    return new Response(JSON.stringify({ success: false, error: "Token expirado" }), { status: 403 });
  }

  // Se passou em todas as verificações, sucesso!
  return new Response(JSON.stringify({ success: true }), { status: 200 });
};

export const config = {
  path: "/.netlify/functions/validar-token",
};