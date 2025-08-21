import { getStore } from "@netlify/blobs";
import { randomUUID } from "crypto";

export default async (req, context) => {
  // Pega a URL base do seu site (ex: https://delicate-ganache-etc.netlify.app)
  const siteURL = new URL(req.url).origin;

  // Pega o acesso ao nosso "banco de dados" de tokens
  const store = getStore("tokens_de_acesso");

  // Gera um token único e seguro
  const token = randomUUID();

  // Define a validade do token para 2 minutos a partir de agora
  const expiration = Date.now() + 2 * 60 * 1000; // 2 minutos em milissegundos

  // Salva o token no banco de dados com sua data de expiração
  await store.setJSON(token, { expires: expiration });

  // Monta a URL final para o aluno, com o token
  const redirectURL = `${siteURL}/?token=${token}`;

  // Redireciona o navegador do aluno para a URL final
  return new Response(null, {
    status: 302, // 302 é o código para redirecionamento temporário
    headers: {
      Location: redirectURL,
    },
  });
};

export const config = {
  path: "/.netlify/functions/gerar-acesso",
};