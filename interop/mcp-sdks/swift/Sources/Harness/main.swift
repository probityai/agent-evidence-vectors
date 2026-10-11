// Decodes each JSON-RPC line as a Response whose result is the SDK's dynamic
// Value type, and re-encodes it with the encoder Server.send(_:) builds:
// JSONEncoder with outputFormatting [.sortedKeys, .withoutEscapingSlashes].
import Foundation
import MCP

enum Probe: MCP.Method {
    static let name = "probe"
    typealias Result = [String: Value]
}

let decoder = JSONDecoder()
let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]

var output = Data()
while let line = readLine(strippingNewline: true) {
    do {
        let response = try decoder.decode(Response<Probe>.self, from: Data(line.utf8))
        let wire = try encoder.encode(response)
        output.append(Data("OK \(wire.base64EncodedString())\n".utf8))
    } catch is DecodingError {
        output.append(Data("ERR DecodingError\n".utf8))
    } catch let error as EncodingError {
        output.append(Data("ERR EncodingError: \(String(describing: error).prefix(120))\n".utf8))
    }
}
FileHandle.standardOutput.write(output)
