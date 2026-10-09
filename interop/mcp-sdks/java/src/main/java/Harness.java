import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapperSupplier;
import io.modelcontextprotocol.spec.McpSchema;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Decodes each JSON-RPC line with McpSchema.deserializeJsonRpcMessage and the
 * SDK's default Jackson 2 mapper (JacksonMcpJsonMapperSupplier: a plain
 * ObjectMapper), then re-encodes it with the same mapper's writeValueAsString.
 */
public final class Harness {
    public static void main(String[] args) throws IOException {
        McpJsonMapper mapper = new JacksonMcpJsonMapperSupplier().get();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, false, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            try {
                McpSchema.JSONRPCMessage msg = McpSchema.deserializeJsonRpcMessage(mapper, line);
                String wire = mapper.writeValueAsString(msg);
                out.print("OK " + Base64.getEncoder().encodeToString(wire.getBytes(StandardCharsets.UTF_8)) + "\n");
            } catch (IOException | IllegalArgumentException e) {
                out.print("ERR " + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()).split("\n")[0] + "\n");
            }
        }
        out.flush();
    }
}
