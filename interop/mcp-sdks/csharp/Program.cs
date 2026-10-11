// Decodes each JSON-RPC line the way StreamClientSessionTransport does,
// JsonSerializer.Deserialize with McpJsonUtilities.DefaultOptions, and
// re-encodes it with JsonSerializer.SerializeToUtf8Bytes under the same options.
using System.Text;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

var stdout = Console.OpenStandardOutput();
var output = new StringBuilder();
string? line;
while ((line = Console.In.ReadLine()) is not null)
{
    try
    {
        var message = JsonSerializer.Deserialize<JsonRpcMessage>(line, McpJsonUtilities.DefaultOptions);
        if (message is null)
        {
            output.Append("ERR null message\n");
            continue;
        }
        var wire = JsonSerializer.SerializeToUtf8Bytes(message, McpJsonUtilities.DefaultOptions);
        output.Append("OK ").Append(Convert.ToBase64String(wire)).Append('\n');
    }
    catch (JsonException e)
    {
        output.Append("ERR JsonException: ").Append(e.Message.Split('\n')[0]).Append('\n');
    }
}
var bytes = new UTF8Encoding(false).GetBytes(output.ToString());
stdout.Write(bytes, 0, bytes.Length);
stdout.Flush();
