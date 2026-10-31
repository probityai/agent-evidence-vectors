import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';

const calls = [];
const schema = { type: 'object', properties: { count: { type: 'number' } }, required: ['count'], additionalProperties: false };
const tools = [
    { name: 'pick', inputSchema: { type: 'object' }, outputSchema: schema },
    { name: 'unused', inputSchema: { type: 'object' }, outputSchema: { type: 'object', $ref: 'https://example.invalid/unresolved.json' } }
];
for await (const line of createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    if (request.id === undefined) continue;
    let result;
    if (request.method === 'initialize') {
        result = {
            protocolVersion: request.params.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: 'independent-called-tool', version: '1' }
        };
    } else if (request.method === 'tools/list') {
        result = { tools, ttlMs: 0 };
    } else if (request.method === 'tools/call') {
        calls.push(request.params.name);
        writeFileSync(process.env.CALLED_TOOL_REPORT, JSON.stringify(calls));
        result = { content: [], structuredContent: { count: process.env.CALLED_TOOL_INVALID === '1' ? 'invalid' : 1 } };
    } else {
        throw new Error(`Unexpected fixture method: ${request.method}`);
    }
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: request.id, result })}\n`);
}
