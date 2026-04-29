# Heimdall-rbuilder: Real-Time Transaction Security Inspection for PBS Block Builders

> **A security-enhanced Ethereum MEV-Boost block builder with an integrated real-time malicious transaction detection engine.**

### Run (Live Mode)

To run `rbuilder` in a live environment, you need the following components:

- **Reth Execution Node**: Required for state access (`reth_datadir`). It must expose an IPC interface for mempool transaction subscription (`el_node_ipc_path`), and be configured to flush every block (`--engine.persistence-threshold "0" --engine.memory-block-buffer-target "0"`).
- **Consensus Layer (CL) Node**: Required to trigger new payload events. It must be configured to trigger a payload event every single time.
- **Bundle Source**: A source that sends `eth_sendBundle`, `mev_sendBundle`, and `eth_sendRawTransaction` via JSON-RPC calls (`jsonrpc_server_port`). By default, `rbuilder` will take raw transactions directly from the Reth node's mempool.
- **Relays**: Endpoints to submit the built blocks to (`relays`).

#### Sample Node Configurations

**Lighthouse (CL Node):**
```bash
./target/maxperf/lighthouse bn \
    --network mainnet \
    --execution-endpoint http://localhost:8551 \
    --execution-jwt /secrets/jwt.hex \
    --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
    --disable-deposit-contract-sync \
    --http \
    --http-port 3500 \
    --always-prepare-payload \
    --prepare-payload-lookahead 8000 \
    --suggested-fee-recipient 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
```

**Reth (Execution Node):**
```bash
/usr/local/bin/reth node \
    --datadir /mnt/md0/rethdata \
    --authrpc.jwtsecret /secrets/jwt.hex \
    --authrpc.addr 127.0.0.1 \
    --authrpc.port 8551 \
    --http \
    --ws \
    --ws.addr 127.0.0.1 \
    --ws.port 8545 \
    --rpc-max-connections 429496729 \
    --http.api trace,web3,eth,debug \
    --ws.api trace,web3,eth,debug \
    --engine.persistence-threshold "0" \
    --engine.memory-block-buffer-target "0"
```

#### Additional Configurations

You can also:
- Configure a block processor API as a sink for submitted blocks (`blocks_processor_url`).
- Set up **Prometheus/Grafana** for metrics (served on `telemetry_port` + `/debug/metrics/prometheus`).
- Record traces of all events happening inside the builder (`tracing_path`, controlled via `telemetry_port` + `/debug/tracing/{start,stop}`).

#### Running the Builder

1. Prepare your configuration file based on [`config-live-example.toml`](./examples/config/rbuilder/config-live-example.toml).
2. Execute the builder:
   ```bash
   cargo run --bin rbuilder run PATH_TO_CONFIG_FILE
   ```
> **Warning**: Before running a builder in a live production environment, ensure you understand the risks associated with [reorg losses](./docs/REORG_LOSSES.md). See [`CONFIG.md`](./docs/CONFIG.md) for detailed configuration fields.

### End-to-End Local Testing

You can use [builder-playground](https://github.com/flashbots/builder-playground) to deploy a fully functional local setup (Lighthouse proposer + validator, Reth execution client, and an MEV-Boost Relay) to test `rbuilder` locally.

1. **Start builder-playground:**

2. **Update the Playground Configuration:**
   Update `config-playground.toml` with fully-qualified paths by replacing `$HOME` with its actual absolute value:
   ```bash
   sed -i "s|\$HOME|$HOME|g" ./examples/config/rbuilder/config-playground.toml
   ```

3. **Run `rbuilder`:**
   Start the builder using the playground configuration:
   ```bash
   cargo run --bin rbuilder run ./examples/config/rbuilder/config-playground.toml
   ```

4. **Verify Block Proposals:**
   You can query the local relay to verify that blocks are being proposed successfully:
   ```bash
   curl http://localhost:5555/relay/v1/data/bidtraces/proposer_payload_delivered
   ```

### Benchmark and Security Validation (`bench/`)

The `bench` directory contains an independent, minimal test framework designed to validate the security engine's accuracy and measure its microsecond-level latency impact without the overhead of the full builder node.

#### Dataset (`dataset.json`)

The `bench/dataset.json` file provides a comprehensive collection of pre-indexed historical transactions and known attacks. This dataset acts as the ground truth for our benchmarks, ensuring that our validation scripts and latency measurements are reproducible, deterministic, and evaluated against real-world scenarios.
#### Validating Real-World Attacks

To prove that the lightweight filter (Phase 1) successfully intercepts historical exploits (such as The DAO, SpankChain, Orion Protocol reentrancy attacks, and BEC overflows) without false negatives, you can run the validation harness:

```bash
cd bench
cargo run --release --bin revm_bench
```
*(Note: This harness connects to a mainnet RPC to replay historical state. It may take a few moments to fetch the data.)*

#### Measuring Execution Latency

To collect raw execution latency data across 100 historical blocks (comparing the baseline EVM against the Heimdall EVM), run the benchmark tool. This replays thousands of transactions in memory and generates a comprehensive `heimdall_latency.csv` dataset:

```bash
cd bench
cargo run --release --bin bench
```

---

## Acknowledgements

- [Flashbots rbuilder](https://github.com/flashbots/rbuilder) — the base block builder implementation
- [Reth](https://github.com/paradigmxyz/reth) — the Ethereum execution client powering the EVM backend
- [revm](https://github.com/bluealloy/revm) — the Rust EVM implementation providing the Inspector framework

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

---

This project extends [Flashbots rbuilder](https://github.com/flashbots/rbuilder) — an open-source, high-performance Ethereum block builder written in Rust — by embedding a novel **bytecode-level security inspection engine** directly into the PBS (Proposer-Builder Separation) block construction pipeline. The system can detect and preemptively filter reentrancy attacks and integer overflow exploits **at the EVM opcode execution level**, without introducing any measurable latency to the critical block assembly path.