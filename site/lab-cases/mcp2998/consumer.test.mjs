import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/client';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/client/validators/ajv';

assert.ok(['base', 'head'].includes(process.env.CALLED_TOOL_REVISION), 'CALLED_TOOL_REVISION must be base or head');
const expectedFirst = process.env.CALLED_TOOL_REVISION === 'base' ? 2 : 1;
async function fixture(invalid, run) {
    const directory = mkdtempSync(join(tmpdir(), 'called-tool-'));
    const report = join(directory, 'calls.json');
    writeFileSync(report, '[]');
    const compiled = [];
    const ajv = new AjvJsonSchemaValidator();
    const validator = {
        getValidator(schema) {
            compiled.push(schema.$ref ?? 'pick');
            return ajv.getValidator(schema);
        }
    };
    const client = new Client({ name: 'independent-consumer', version: '1' }, { capabilities: {}, jsonSchemaValidator: validator });
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: [fileURLToPath(new URL('./server.mjs', import.meta.url))],
        env: {
            ...getDefaultEnvironment(),
            CALLED_TOOL_REPORT: report,
            CALLED_TOOL_INVALID: invalid ? '1' : '0',
            ...(process.env.NODE_V8_COVERAGE && { NODE_V8_COVERAGE: process.env.NODE_V8_COVERAGE })
        },
        stderr: 'pipe'
    });
    try {
        await client.connect(transport);
        await run(client, compiled, () => JSON.parse(readFileSync(report, 'utf8')));
    } finally {
        await client.close();
        await transport.close();
        rmSync(directory, { recursive: true });
    }
}

test('complete catalog plus unusable uncalled schema: valid call and reuse', async () => {
    await fixture(false, async (client, compiled, calls) => {
        const listed = await client.listTools();
        assert.deepEqual(
            listed.tools.map(tool => tool.name),
            ['pick', 'unused']
        );
        assert.equal(compiled.length, 0);
        assert.deepEqual((await client.callTool({ name: 'pick', arguments: {} })).structuredContent, { count: 1 });
        assert.equal(compiled.length, expectedFirst);
        await client.callTool({ name: 'pick', arguments: {} });
        assert.equal(compiled.length, expectedFirst);
        assert.deepEqual(calls(), ['pick', 'pick']);
        console.log(
            JSON.stringify({
                revision: process.env.CALLED_TOOL_REVISION,
                listed: ['pick', 'unused'],
                providerValidatorRequests: compiled,
                serverCalls: calls()
            })
        );
    });
});

test('uncompilable called schema refuses before any server call', async () => {
    await fixture(false, async (client, compiled, calls) => {
        await client.listTools();
        await assert.rejects(client.callTool({ name: 'unused', arguments: {} }), /invalid outputSchema/);
        assert.deepEqual(calls(), []);
        assert.equal(compiled.length, expectedFirst);
    });
});

test('invalid called output refuses after one actual server call', async () => {
    await fixture(true, async (client, compiled, calls) => {
        await client.listTools();
        await assert.rejects(client.callTool({ name: 'pick', arguments: {} }), /does not match the tool's output schema/);
        assert.deepEqual(calls(), ['pick']);
        assert.equal(compiled.length, expectedFirst);
    });
});

test('explicit public toolDefinition validates without discovering the catalog', async () => {
    await fixture(false, async (client, compiled, calls) => {
        const toolDefinition = {
            name: 'pick',
            inputSchema: { type: 'object' },
            outputSchema: { type: 'object', properties: { count: { type: 'number' } }, required: ['count'] }
        };
        assert.deepEqual((await client.callTool({ name: 'pick', arguments: {} }, { toolDefinition })).structuredContent, { count: 1 });
        assert.deepEqual(compiled, ['pick']);
        assert.deepEqual(calls(), ['pick']);
    });
});

test('a cold cache supplies no output schema: this is not universal validation', async () => {
    await fixture(true, async (client, compiled, calls) => {
        assert.deepEqual((await client.callTool({ name: 'pick', arguments: {} })).structuredContent, { count: 'invalid' });
        assert.deepEqual(compiled, []);
        assert.deepEqual(calls(), ['pick']);
    });
});

test('unknown revision names refuse instead of silently selecting the head', () => {
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
        env: { ...process.env, CALLED_TOOL_REVISION: 'typo' },
        encoding: 'utf8'
    });
    assert.equal(child.status, 1);
    assert.match(child.stderr, /CALLED_TOOL_REVISION must be base or head/);
});
