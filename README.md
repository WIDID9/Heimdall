# Heimdall

Heimdall integrates runtime smart-contract security inspection into an Ethereum PBS builder. This Rust workspace extends [Flashbots rbuilder](https://github.com/flashbots/rbuilder), using Reth and revm for transaction execution and builder integration.

## Source layout

- `crates/rbuilder-primitives/src/lightweight_filter.rs`: lightweight execution screening.
- `crates/rbuilder-primitives/src/security_inspector.rs`: runtime security inspection.
- `crates/rbuilder-primitives/src/evm_inspector.rs`: inspector integration.
- `crates/rbuilder/src/building/`: transaction simulation and block-building integration.
- Other workspace crates provide builder configuration, state access, relay interfaces, and supporting utilities inherited from rbuilder.

## Build

The toolchain is specified in `rust-toolchain.toml`. The dependency versions and pinned Reth revision are recorded in `Cargo.toml` and `Cargo.lock`. Building requires the native dependencies used by Reth/rbuilder, including a C/C++ build toolchain, Clang, and the Protocol Buffers compiler (`protoc`).

```sh
cargo build --locked --release --bin rbuilder
```

## Configuration

Use `examples/config/rbuilder/config-live-example.toml` as a configuration reference. A live builder requires an execution node, a consensus node, transaction or bundle input, and configured relay endpoints. Adapt paths and endpoints to the local environment. Supply signing credentials through the environment-variable settings in the configuration rather than committing them.

```sh
cargo run --release --bin rbuilder -- run PATH_TO_CONFIG_FILE
```

## Publication scope

This repository publishes the Rust system source and the files required by its workspace. Experiment datasets, measurement CSVs, historical-state caches, experiment scripts, and standalone benchmark targets are excluded from the current source tree. Cargo build scripts and Rust library utilities remain because they are part of the system workspace.

Unit-test source and the embedded contract fixture are retained. Tests that require the omitted external fixtures or an external node environment need those resources separately. This source distribution does not include the artifacts needed to reproduce the paper's experiments.

## Attribution and license

The builder implementation is derived from [Flashbots rbuilder](https://github.com/flashbots/rbuilder). It uses [Reth](https://github.com/paradigmxyz/reth) and [revm](https://github.com/bluealloy/revm). Existing upstream attribution is retained.

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), as specified by the workspace.
