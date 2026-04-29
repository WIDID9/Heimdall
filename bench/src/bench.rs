//! Heimdall Latency Benchmark — CDF-quality raw per-transaction data.
//!
//! For each of 10 historical mainnet blocks, replays every transaction three times:
//!   **Mode A (Baseline)**: revm execution without any inspector.
//!   **Mode B (Heimdall Phase 1)**:  revm execution with `LightweightFlagFilter` attached.
//!   **Mode C (Heimdall Phase 2)**:  revm execution with `SecurityInspector` attached.
//!
//! ## Architecture
//!
//! 1. **Warm-up pass** — Replay all block txs on `State<CacheDB<AlloyDB>>`.
//!    `State` intercepts commits in its own cache, so the inner `CacheDB`
//!    retains only the *original* values fetched from RPC.  After this pass
//!    every account, storage slot, and contract touched by any tx in the block
//!    is already resident in `CacheDB` — zero RPC during measurement.
//!
//! 2. **Snapshot** — Clone the warm `CacheDB` data into three independent
//!    `CacheDB<EmptyDB>` instances (baseline + Phase 1 + Phase 2).
//!
//! 3. **Baseline measurement** — `build_mainnet()` + `transact_commit()`,
//!    timed with `Instant` per tx.
//!
//! 4. **Phase 1 measurement** — `build_mainnet_with_inspector(filter)` +
//!    `inspect_tx_commit()`, timed per tx, flag recorded.
//!
//! 5. **Phase 2 measurement** — `build_mainnet_with_inspector(SecurityInspector)` +
//!    `inspect_tx_commit()` + `finalize_detection()`, timed per tx.
//!
//! ## Output
//!
//! `heimdall_latency_raw.csv` with columns:
//! `block_number, tx_hash, baseline_us, phase1_us, phase2_us, triggered_deep_inspection`

mod inspector;
mod lightweight_filter;

use alloy_consensus::Transaction;
use alloy_eips::BlockNumberOrTag;
use alloy_provider::{network::primitives::BlockTransactions, Provider, ProviderBuilder};
use inspector::SecurityInspector;
use lightweight_filter::LightweightFlagFilter;
use revm::{
    context::TxEnv,
    database::{AlloyDB, CacheDB, EmptyDB, StateBuilder},
    database_interface::WrapDatabaseAsync,
    primitives::{TxKind, U256},
    Context, ExecuteCommitEvm, InspectCommitEvm, MainBuilder, MainContext,
};
use std::io::Write;
use std::time::Instant;

const RPC_URL: &str = "https://eth-mainnet.g.alchemy.com/v2/oxtTwbgn-ZEJjJ-H5N22h";
const CHAIN_ID: u64 = 1;

/// 100 representative mainnet blocks — 10 clusters of 10 consecutive blocks
/// around the original anchor points, spanning different eras and gas profiles.
const BLOCK_NUMBERS: &[u64] = &[
    // ── Cluster 1: The DAO era (2016) — anchor 1_718_497 ──
    1_718_493, 1_718_494, 1_718_495, 1_718_496, 1_718_497,
    1_718_498, 1_718_499, 1_718_500, 1_718_501, 1_718_502,
    // ── Cluster 2: early 2018 — anchor 5_009_828 ──
    5_009_824, 5_009_825, 5_009_826, 5_009_827, 5_009_828,
    5_009_829, 5_009_830, 5_009_831, 5_009_832, 5_009_833,
    // ── Cluster 3: late 2018 — anchor 6_467_248 ──
    6_467_244, 6_467_245, 6_467_246, 6_467_247, 6_467_248,
    6_467_249, 6_467_250, 6_467_251, 6_467_252, 6_467_253,
    // ── Cluster 4: early 2020 — anchor 9_899_738 ──
    9_899_734, 9_899_735, 9_899_736, 9_899_737, 9_899_738,
    9_899_739, 9_899_740, 9_899_741, 9_899_742, 9_899_743,
    // ── Cluster 5: late 2021 — anchor 13_499_798 ──
    13_499_794, 13_499_795, 13_499_796, 13_499_797, 13_499_798,
    13_499_799, 13_499_800, 13_499_801, 13_499_802, 13_499_803,
    // ── Cluster 6: mid 2022 — anchor 14_684_814 ──
    14_684_810, 14_684_811, 14_684_812, 14_684_813, 14_684_814,
    14_684_815, 14_684_816, 14_684_817, 14_684_818, 14_684_819,
    // ── Cluster 7: mid 2022 (post-merge prep) — anchor 15_114_361 ──
    15_114_357, 15_114_358, 15_114_359, 15_114_360, 15_114_361,
    15_114_362, 15_114_363, 15_114_364, 15_114_365, 15_114_366,
    // ── Cluster 8: early 2023 — anchor 16_542_148 ──
    16_542_144, 16_542_145, 16_542_146, 16_542_147, 16_542_148,
    16_542_149, 16_542_150, 16_542_151, 16_542_152, 16_542_153,
    // ── Cluster 9: mid 2023 — anchor 17_806_056 ──
    17_806_052, 17_806_053, 17_806_054, 17_806_055, 17_806_056,
    17_806_057, 17_806_058, 17_806_059, 17_806_060, 17_806_061,
    // ── Cluster 10: 2024 — anchor 20_671_892 ──
    20_671_888, 20_671_889, 20_671_890, 20_671_891, 20_671_892,
    20_671_893, 20_671_894, 20_671_895, 20_671_896, 20_671_897,
];

/// Build a `TxEnv` from an RPC transaction object.
fn build_tx_env(tx: &alloy_rpc_types::Transaction, chain_id: u64) -> TxEnv {
    TxEnv::builder()
        .caller(tx.inner.signer())
        .gas_limit(tx.gas_limit())
        .gas_price(tx.gas_price().unwrap_or(tx.inner.max_fee_per_gas()))
        .value(tx.value())
        .data(tx.input().to_owned())
        .gas_priority_fee(tx.max_priority_fee_per_gas())
        .chain_id(Some(chain_id))
        .nonce(tx.nonce())
        .access_list(tx.access_list().cloned().unwrap_or_default())
        .kind(match tx.to() {
            Some(to) => TxKind::Call(to),
            None => TxKind::Create,
        })
        .build()
        .unwrap()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Heimdall Latency Benchmark — CDF Raw Data Collection      ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let rpc_url = RPC_URL.parse()?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // ── CSV output ──────────────────────────────────────────────────────
    let csv_path = "heimdall_latency.csv";
    let mut csv = std::io::BufWriter::new(std::fs::File::create(csv_path)?);
    writeln!(
        csv,
        "block_number,tx_hash,baseline_us,phase1_us,phase2_us,triggered_deep_inspection"
    )?;

    let total_start = Instant::now();
    let mut total_txs: usize = 0;

    for (block_idx, &block_number) in BLOCK_NUMBERS.iter().enumerate() {
        println!(
            "━━━ Block [{}/{}] #{} ━━━",
            block_idx + 1,
            BLOCK_NUMBERS.len(),
            block_number
        );

        // ── 1. Fetch full block ─────────────────────────────────────────
        let block = match provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await
        {
            Ok(Some(b)) => b,
            Ok(None) => {
                println!("  ⚠  Block not found (archival node required?)");
                continue;
            }
            Err(e) => {
                println!("  ⚠  RPC error fetching block: {e}");
                continue;
            }
        };

        let BlockTransactions::Full(transactions) = block.transactions else {
            println!("  ⚠  Block returned without full transactions");
            continue;
        };

        let tx_count = transactions.len();
        if tx_count == 0 {
            println!("  Skipping empty block.\n");
            continue;
        }
        println!("  Transactions: {tx_count}");

        // Pre-build all TxEnvs and collect tx hashes (done once, reused 3×).
        let tx_envs: Vec<TxEnv> = transactions
            .iter()
            .map(|tx| build_tx_env(tx, CHAIN_ID))
            .collect();

        let tx_hashes: Vec<String> = transactions
            .iter()
            .map(|tx| format!("{}", tx.inner.tx_hash()))
            .collect();

        // Block-env values reused across all three passes.
        let blk_num = U256::from(block.header.number);
        let beneficiary = block.header.beneficiary;
        let timestamp = U256::from(block.header.timestamp);
        let difficulty = block.header.difficulty;
        let gas_limit = block.header.gas_limit;
        let basefee = block.header.base_fee_per_gas.unwrap_or_default();

        // ── 2. Warm-up pass ─────────────────────────────────────────────
        //    Replay every tx on State<CacheDB<AlloyDB>>.
        //    • State.commit() writes to State.cache (internal).
        //    • CacheDB retains *original* fetched values from RPC.
        //    After this loop the CacheDB holds all data any tx will need,
        //    so the measurement passes make zero network calls.
        println!("  Phase 0: Warm-up (caching state from RPC)...");
        let warmup_start = Instant::now();

        let prev_id: alloy_eips::BlockId = (block_number - 1).into();
        let alloy_db =
            WrapDatabaseAsync::new(AlloyDB::new(provider.clone(), prev_id)).unwrap();
        let cache_db = CacheDB::new(alloy_db);
        let state = StateBuilder::new_with_database(cache_db).build();

        let ctx = Context::mainnet()
            .with_db(state)
            .modify_block_chained(|b| {
                b.number = blk_num;
                b.beneficiary = beneficiary;
                b.timestamp = timestamp;
                b.difficulty = difficulty;
                b.gas_limit = gas_limit;
                b.basefee = basefee;
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                c.disable_nonce_check = true;
                c.tx_gas_limit_cap = Some(u64::MAX);
                c.tx_chain_id_check = false;
            });

        let mut warmup_evm = ctx.build_mainnet();

        for (j, tx_env) in tx_envs.iter().enumerate() {
            let _ = warmup_evm.transact_commit(tx_env.clone());
            if (j + 1) % 100 == 0 {
                println!("    warm-up {}/{}", j + 1, tx_count);
            }
        }
        println!(
            "  Warm-up done in {:.1}s",
            warmup_start.elapsed().as_secs_f64()
        );

        // ── 3. Snapshot warm CacheDB into two in-memory clones ──────────
        //    Path:  evm.ctx                          → Context
        //           evm.ctx.journaled_state          → Journal<State<CacheDB<…>>>
        //           evm.ctx.journaled_state.database → State<CacheDB<…>>
        //           …                    .database   → CacheDB<…>  (originals only)
        let warm = &warmup_evm.ctx.journaled_state.database.database;

        let mut baseline_db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::default());
        baseline_db.cache.accounts = warm.cache.accounts.clone();
        baseline_db.cache.contracts = warm.cache.contracts.clone();
        baseline_db.cache.block_hashes = warm.cache.block_hashes.clone();

        let mut heimdall_db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::default());
        heimdall_db.cache.accounts = warm.cache.accounts.clone();
        heimdall_db.cache.contracts = warm.cache.contracts.clone();
        heimdall_db.cache.block_hashes = warm.cache.block_hashes.clone();

        let mut phase2_db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::default());
        phase2_db.cache.accounts = warm.cache.accounts.clone();
        phase2_db.cache.contracts = warm.cache.contracts.clone();
        phase2_db.cache.block_hashes = warm.cache.block_hashes.clone();

        drop(warmup_evm); // free RPC-backed state

        // ── 4. Baseline measurement (Mode A — no inspector) ─────────────
        println!("  Phase A: Baseline measurement...");
        let phase_a_start = Instant::now();

        let baseline_state = StateBuilder::new_with_database(baseline_db).build();
        let ctx_a = Context::mainnet()
            .with_db(baseline_state)
            .modify_block_chained(|b| {
                b.number = blk_num;
                b.beneficiary = beneficiary;
                b.timestamp = timestamp;
                b.difficulty = difficulty;
                b.gas_limit = gas_limit;
                b.basefee = basefee;
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                c.disable_nonce_check = true;
                c.tx_gas_limit_cap = Some(u64::MAX);
                c.tx_chain_id_check = false;
            });

        let mut baseline_evm = ctx_a.build_mainnet();

        let mut baseline_us: Vec<u128> = Vec::with_capacity(tx_count);
        for tx_env in &tx_envs {
            let t = Instant::now();
            let _ = baseline_evm.transact_commit(tx_env.clone());
            baseline_us.push(t.elapsed().as_micros());
        }
        drop(baseline_evm);
        println!(
            "  Phase A done in {:.1}s",
            phase_a_start.elapsed().as_secs_f64()
        );

        // ── 5. Heimdall measurement (Mode B — with filter) ──────────────
        println!("  Phase B: Heimdall measurement...");
        let phase_b_start = Instant::now();

        let heimdall_state = StateBuilder::new_with_database(heimdall_db).build();
        let filter = LightweightFlagFilter::new();
        let ctx_b = Context::mainnet()
            .with_db(heimdall_state)
            .modify_block_chained(|b| {
                b.number = blk_num;
                b.beneficiary = beneficiary;
                b.timestamp = timestamp;
                b.difficulty = difficulty;
                b.gas_limit = gas_limit;
                b.basefee = basefee;
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                c.disable_nonce_check = true;
                c.tx_gas_limit_cap = Some(u64::MAX);
                c.tx_chain_id_check = false;
            });

        let mut heimdall_evm = ctx_b.build_mainnet_with_inspector(filter);

        let mut heimdall_us: Vec<u128> = Vec::with_capacity(tx_count);
        let mut flags: Vec<bool> = Vec::with_capacity(tx_count);

        for tx_env in &tx_envs {
            heimdall_evm.inspector.reset();
            let t = Instant::now();
            let _ = heimdall_evm.inspect_tx_commit(tx_env.clone());
            heimdall_us.push(t.elapsed().as_micros());
            flags.push(heimdall_evm.inspector.requires_deep_inspection());
        }
        drop(heimdall_evm);
        println!(
            "  Phase B done in {:.1}s",
            phase_b_start.elapsed().as_secs_f64()
        );

        // ── 6. Phase 2 measurement (Mode C — SecurityInspector) ─────────
        println!("  Phase C: SecurityInspector (Phase 2) measurement...");
        let phase_c_start = Instant::now();

        let phase2_state = StateBuilder::new_with_database(phase2_db).build();
        let sec_inspector = SecurityInspector::new(true, true, true);
        let ctx_c = Context::mainnet()
            .with_db(phase2_state)
            .modify_block_chained(|b| {
                b.number = blk_num;
                b.beneficiary = beneficiary;
                b.timestamp = timestamp;
                b.difficulty = difficulty;
                b.gas_limit = gas_limit;
                b.basefee = basefee;
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                c.disable_nonce_check = true;
                c.tx_gas_limit_cap = Some(u64::MAX);
                c.tx_chain_id_check = false;
            });

        let mut phase2_evm = ctx_c.build_mainnet_with_inspector(sec_inspector);

        let mut phase2_us: Vec<u128> = Vec::with_capacity(tx_count);

        for tx_env in &tx_envs {
            phase2_evm.inspector = SecurityInspector::new(true, true, true);
            let t = Instant::now();
            let _ = phase2_evm.inspect_tx_commit(tx_env.clone());
            phase2_evm.inspector.finalize_detection();
            phase2_us.push(t.elapsed().as_micros());
        }
        drop(phase2_evm);
        println!(
            "  Phase C done in {:.1}s",
            phase_c_start.elapsed().as_secs_f64()
        );

        // ── 7. Write CSV rows ───────────────────────────────────────────
        let flagged_count = flags.iter().filter(|&&f| f).count();
        for i in 0..tx_count {
            writeln!(
                csv,
                "{},{},{},{},{},{}",
                block_number, tx_hashes[i], baseline_us[i], heimdall_us[i], phase2_us[i], flags[i],
            )?;
        }
        csv.flush()?;
        total_txs += tx_count;

        println!(
            "  Block #{} complete — {} txs recorded, {} flagged for deep inspection.\n",
            block_number, tx_count, flagged_count
        );
    }

    csv.flush()?;
    let total_elapsed = total_start.elapsed();

    println!("════════════════════════════════════════════════════════════════");
    println!(
        "Done!  {} total transactions → {}",
        total_txs, csv_path
    );
    println!("Total wall-clock time: {:.1}s", total_elapsed.as_secs_f64());

    Ok(())
}
