# Decode and re-encode each JSON-RPC line the way the Ruby SDK's stdio
# transport does: JSON.parse(line, symbolize_names: true), then JSON.generate.
require "base64"
require "json"
require "mcp"

$stdout.sync = false
$stdin.each_line do |line|
  begin
    message = JSON.parse(line.chomp, symbolize_names: true)
    wire = JSON.generate(message)
    $stdout.write("OK #{Base64.strict_encode64(wire.b)}\n")
  rescue JSON::ParserError, JSON::GeneratorError, EncodingError => e
    $stdout.write("ERR #{e.class}: #{e.message.lines.first.to_s.strip[0, 160]}\n")
  end
end
$stdout.flush
