/** Parse JSON and refuse duplicate object members before policy evaluation. */
export function parseUniqueJSON(text) {
  const value = JSON.parse(text);
  const stack = [];
  const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^{}\[\]:,\s]+/gu) ?? [];
  for (const token of tokens) inspectToken(token, stack);
  return value;
}

function inspectToken(token, stack) {
  if (token === '{' || token === '[') {
    stack.push({ object: token === '{', expectsKey: true, keys: new Set() });
    return;
  }
  if (token === '}' || token === ']') { stack.pop(); return; }
  const current = stack.at(-1);
  if (token === ',') { if (current) current.expectsKey = true; return; }
  inspectMember(token, current);
}

function inspectMember(token, current) {
  if (!current?.object || !current.expectsKey || !token.startsWith('"')) return;
  const key = JSON.parse(token);
  if (current.keys.has(key)) throw new Error(`duplicate JSON member: ${key}`);
  current.keys.add(key);
  current.expectsKey = false;
}
