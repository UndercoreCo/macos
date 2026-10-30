// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "UndercoreMacCore", platforms: [.macOS(.v14)],
    products: [.library(name: "UndercoreMacCore", targets: ["UndercoreMacCore"])],
    dependencies: [.package(path: "../.build-deps/AWGKit")],
    targets: [
        .target(name: "UndercoreMacCore", dependencies: [.product(name: "WireGuardConfiguration", package: "AWGKit")]),
        .testTarget(name: "UndercoreMacCoreTests", dependencies: ["UndercoreMacCore"])
    ])
