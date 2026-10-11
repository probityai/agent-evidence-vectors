// Decodes each JSON-RPC line the way the Kotlin SDK's ReadBuffer does,
// McpJson.decodeFromString<JSONRPCMessage>(line), and re-encodes it with the
// public serializeMessage (McpJson.encodeToString(message) + "\n").
import io.modelcontextprotocol.kotlin.sdk.shared.serializeMessage
import io.modelcontextprotocol.kotlin.sdk.types.JSONRPCMessage
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import kotlinx.serialization.SerializationException
import java.util.Base64

fun main() {
    val out = StringBuilder()
    generateSequence(::readLine).forEach { line ->
        try {
            val msg = McpJson.decodeFromString<JSONRPCMessage>(line)
            val wire = serializeMessage(msg).removeSuffix("\n")
            out.append("OK ").append(Base64.getEncoder().encodeToString(wire.toByteArray(Charsets.UTF_8))).append('\n')
        } catch (e: SerializationException) {
            out.append("ERR ").append(e::class.simpleName).append(": ")
                .append((e.message ?: "").lineSequence().first()).append('\n')
        } catch (e: IllegalArgumentException) {
            out.append("ERR ").append(e::class.simpleName).append(": ")
                .append((e.message ?: "").lineSequence().first()).append('\n')
        }
    }
    System.out.write(out.toString().toByteArray(Charsets.UTF_8))
    System.out.flush()
}
