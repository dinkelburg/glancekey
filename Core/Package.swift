// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FaceUnlockCore",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "FaceUnlockCore", targets: ["FaceUnlockCore"]),
        .executable(name: "fake-phone", targets: ["FakePhone"]),
    ],
    targets: [
        .target(name: "FaceUnlockCore"),
        // Stands in for the iPhone so the Mac app can be tested end to end from a terminal.
        .executableTarget(name: "FakePhone", dependencies: ["FaceUnlockCore"]),
        .testTarget(name: "FaceUnlockCoreTests", dependencies: ["FaceUnlockCore"]),
    ]
)
