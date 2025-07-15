// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CertificateAuthority",
    platforms: [
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "CertificateAuthority",
            targets: ["CertificateAuthority"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tomieq/SwiftExtensions", branch: "master"),
        .package(url: "https://github.com/tomieq/SwiftyTLV", branch: "master"),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3")),
        .package(url: "https://github.com/tomieq/CryptoKeyUtils", branch: "master")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "CertificateAuthority",
        dependencies: [
            .product(name: "SwiftExtensions", package: "SwiftExtensions"),
            .product(name: "SwiftyTLV", package: "SwiftyTLV"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "CryptoKeyUtils", package: "CryptoKeyUtils")
        ]),
        .testTarget(
            name: "CertificateAuthorityTests",
            dependencies: ["CertificateAuthority"]
        ),
    ]
)
