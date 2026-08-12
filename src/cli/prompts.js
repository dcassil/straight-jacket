export async function readPromptLines(stdin) {
  const chunks = [];
  for await (const chunk of stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks).toString("utf8").split(/\r?\n/);
}

export async function readPassword(stdin) {
  const [password] = await readPromptLines(stdin);
  return password ?? "";
}

export async function readPasswordConfirmation(stdin) {
  const [password, confirmation] = await readPromptLines(stdin);
  return {
    password: password ?? "",
    confirmation: confirmation ?? ""
  };
}
