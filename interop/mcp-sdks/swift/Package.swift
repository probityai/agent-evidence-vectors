// swift-tools-version:6.1
import PackageDescription

let package = Package(
    name: "Harness",
    platforms: [.macOS("13.0")],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", exact: "0.12.1"),
    ],
    targets: [
        .executableTarget(name: "Harness", dependencies: [.product(name: "MCP", package: "swift-sdk")]),
    ]
)
