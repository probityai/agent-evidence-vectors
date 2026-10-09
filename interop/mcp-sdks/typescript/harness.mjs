// Decode and re-encode each JSON-RPC line with the stdio codec of the
// TypeScript SDK (deserializeMessage: JSON.parse + zod JSONRPCMessageSchema;
// serializeMessage: JSON.stringify + "\n").
import { createInterface } from "node:readline";
import { deserializeMessage, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  try {
    const wire = serializeMessage(deserializeMessage(line)).replace(/\n$/, "");
    process.stdout.write(`OK ${Buffer.from(wire, "utf8").toString("base64")}\n`);
  } catch (err) {
    process.stdout.write(`ERR ${String(err.message ?? err).split("\n")[0]}\n`);
  }
}
