# LibP2PNoise

[![](https://img.shields.io/badge/made%20by-Breth-blue.svg?style=flat-square)](https://breth.app)
[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](http://libp2p.io/)
[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-blue.svg?style=flat-square)](https://github.com/apple/swift-package-manager)
![Build & Test (macos and linux)](https://github.com/swift-libp2p/swift-libp2p-noise/actions/workflows/build+test.yml/badge.svg)

> A LibP2P Stream Security protocol

## Table of Contents

- [Overview](#overview)
- [Install](#install)
- [Usage](#usage)
  - [Example](#example)
  - [API](#api)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Overview
Noise is a connection security protocol. It provides a secure transport channel for swift-libp2p based on the Noise Protocol Framework. Following an initial plaintext handshake, all data exchanged between peers using swift-libp2p-noise is encrypted and protected from eavesdropping.

### ⚠️ Warning
This package has **NOT** been extensively tested in real world applications and **should NOT be used in production environments**. Although the actual cryptography is handled by swift-crypto, the handshake logic could, and probably does, contain a myriad of bugs. Please feel free to look over the code and submit improvements where you see fit.  

#### Note:
- For more information check out the [LibP2P Noise Spec](https://github.com/libp2p/specs/tree/master/noise) 
- For more information check out the [Noise Protocol Spec](https://noiseprotocol.org/noise.html)

## Install

Include the following dependency in your Package.swift file
``` swift
let package = Package(
    ...
    dependencies: [
        ...
        .package(name: "LibP2PNoise", url: "https://github.com/swift-libp2p/swift-libp2p-noise.git", .upToNextMajor(from: "0.1.0"))
    ],
    ...
        .target(
            ...
            dependencies: [
                ...
                .product(name: "LibP2PNoise", package: "swift-libp2p-noise"),
            ]),
    ...
)
```

## Usage

### Example 
``` swift
import LibP2PNoise

/// Tell libp2p that it can use noise to secure connections...
app.security.use( .noise )

```

### API
``` swift
Not Applicable
```

## Contributing

Contributions are welcomed! This code is very much a proof of concept. I can guarantee you there's a better / safer way to accomplish the same results. Any suggestions, improvements, or even just critiques, are welcome! 

Let's make this code better together! 🤝


## Credits

- [LibP2P Noise Spec](https://github.com/libp2p/specs/tree/master/noise) 

## License

[MIT](LICENSE) © 2022 Breth Inc.
