// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "AppCore",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "AppCore", targets: ["AppCore"]),
        .executable(name: "fake-phone", targets: ["FakePhone"]),
    ],
    targets: [
        .target(name: "AppCore"),
        // Stands in for the iPhone so the Mac app can be tested end to end from a terminal.
        .executableTarget(name: "FakePhone", dependencies: ["AppCore"]),
        .testTarget(name: "AppCoreTests", dependencies: ["AppCore"]),
    ]
)
