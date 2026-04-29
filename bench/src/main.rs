//! Heimdall Phase 1 — LightweightFlagFilter validation test harness.
//!
//! Tests the filter against 9 real-world exploit transactions to verify
//! that it correctly flags each one for Phase 2 deep inspection.

mod inspector;
mod lightweight_filter;

use alloy_consensus::Transaction;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_provider::{network::primitives::BlockTransactions, Provider, ProviderBuilder};
use inspector::SecurityInspector;
use lightweight_filter::LightweightFlagFilter;
use revm::{
    context::TxEnv,
    context_interface::result::ExecutionResult,
    database::{AlloyDB, CacheDB, StateBuilder},
    database_interface::WrapDatabaseAsync,
    primitives::{TxKind, U256},
    Context, InspectCommitEvm, InspectEvm, MainBuilder, MainContext,
};
use std::time::Instant;

const RPC_URL: &str = "https://eth-mainnet.g.alchemy.com/v2/oxtTwbgn-ZEJjJ-H5N22h";
const CHAIN_ID: u64 = 1;

/// Build a TxEnv from an RPC transaction.
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

struct TestCase {
    name: &'static str,
    tx_hash: &'static str,
}

const TEST_CASES: &[TestCase] = &[
    // Reentrancy
    TestCase {
        name: "The DAO (reentrancy)",
        tx_hash: "0x0ec3f2488a93839524add10ea229e773f6bc891b4eb4794c3337d4495263790b",
    },
    TestCase {
        name: "SpankChain (reentrancy)",
        tx_hash: "0x21e9d20b57f6ae60dac23466c8395d47f42dc24628e5a31f224567a2b4effa88",
    },
    TestCase {
        name: "Lendf.me (reentrancy)",
        tx_hash: "0xae7d664bdfcc54220df4f18d339005c6faf6e62c9ca79c56387bc0389274363b",
    },
    TestCase {
        name: "Rari Capital Fei Protocol (reentrancy)",
        tx_hash: "0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530",
    },
    TestCase {
        name: "Omin (reentrancy)",
        tx_hash: "0x264e16f4862d182a6a0b74977df28a85747b6f237b5e229c9a5bbacdf499ccb4",
    },
    TestCase {
        name: "Cream Finance (reentrancy)",
        tx_hash: "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
    },
    TestCase {
        name: "Orion Protocol (reentrancy)",
        tx_hash: "0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa",
    },
    TestCase {
        name: "Penpiexyz (reentrancy)",
        tx_hash: "0x42b2ec27c732100dd9037c76da415e10329ea41598de453bb0c0c9ea7ce0d8e5",
    },
    TestCase {
        name: "Curve (reentrancy)",
        tx_hash: "0xa84aa065ce61dbb1eb50ab6ae67fc31a9da50dd2c74eefd561661bfce2f1620c",
    },
    // Overflow
    TestCase {
        name: "BEC (overflow)",
        tx_hash: "0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebe0d3a470aba4a660f",
    },
    TestCase {
        name: "SmartMesh (overflow)",
        tx_hash: "0x1abab4c8db9a30e703114528e31dee129a3a758f7f8abc3b6494aad3d304e43f",
    },
    TestCase {
        name: "PoWHC (overflow)",
        tx_hash: "0x233107922bed72a4ea7c75a83ecf58dae4b744384e2b3feacd28903a17b864e0",
    },
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Heimdall Phase 1 — LightweightFlagFilter Validation Test  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let rpc_url = RPC_URL.parse()?;
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    let mut results: Vec<(&str, bool, String, f64)> = Vec::new();
    let total_start = Instant::now();

    for (i, tc) in TEST_CASES.iter().enumerate() {
        println!(
            "━━━ [{}/{}] {} ━━━",
            i + 1,
            TEST_CASES.len(),
            tc.name
        );
        println!("  TX:    {}", tc.tx_hash);


        let case_start = Instant::now();

        // ── 1. Fetch receipt to get actual tx index ─────────────────────
        let tx_hash: revm::primitives::B256 = match tc.tx_hash.parse() {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("Invalid tx hash: {e}");
                println!("  ⚠️  {msg}");
                results.push((tc.name, false, msg, 0.0));
                continue;
            }
        };

        let receipt = match provider.get_transaction_receipt(tx_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                let msg = "Receipt not found (archival node required?)".to_string();
                println!("  ⚠️  {msg}");
                results.push((tc.name, false, msg, 0.0));
                continue;
            }
            Err(e) => {
                let msg = format!("RPC error: {e}");
                println!("  ⚠️  {msg}");
                results.push((tc.name, false, msg, 0.0));
                continue;
            }
        };

        let block_number = receipt.block_number.expect("Receipt missing block number");
        let tx_index = receipt.transaction_index.unwrap_or(0) as usize;
        println!("  Actual block: #{block_number}, tx index: #{tx_index}");

        // ── 2. Fetch full block ─────────────────────────────────────────
        let block = match provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await
        {
            Ok(Some(b)) => b,
            Ok(None) => {
                let msg = "Block not found (archival node required?)".to_string();
                println!("  ⚠️  {msg}");
                results.push((tc.name, false, msg, 0.0));
                continue;
            }
            Err(e) => {
                let msg = format!("RPC error: {e}");
                println!("  ⚠️  {msg}");
                results.push((tc.name, false, msg, 0.0));
                continue;
            }
        };

        let BlockTransactions::Full(transactions) = block.transactions else {
            let msg = "Block has no full transactions".to_string();
            println!("  ⚠️  {msg}");
            results.push((tc.name, false, msg, 0.0));
            continue;
        };

        if tx_index >= transactions.len() {
            let msg = format!(
                "TX index {} >= block tx count {}",
                tx_index,
                transactions.len()
            );
            println!("  ⚠️  {msg}");
            results.push((tc.name, false, msg, 0.0));
            continue;
        }

        // ── 2. Setup EVM state at block - 1 ─────────────────────────────
        let prev_block_id: BlockId = (block_number - 1).into();
        let state_db =
            WrapDatabaseAsync::new(AlloyDB::new(provider.clone(), prev_block_id)).unwrap();
        let cache_db = CacheDB::new(state_db);
        let state = StateBuilder::new_with_database(cache_db).build();

        // ── 3. Build inspector-enabled EVM ──────────────────────────────
        let filter = LightweightFlagFilter::new();

        let ctx = Context::mainnet()
            .with_db(state)
            .modify_block_chained(|b| {
                b.number = U256::from(block.header.number);
                b.beneficiary = block.header.beneficiary;
                b.timestamp = U256::from(block.header.timestamp);
                b.difficulty = block.header.difficulty;
                b.gas_limit = block.header.gas_limit;
                b.basefee = block.header.base_fee_per_gas.unwrap_or_default();
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                // Disable nonce/balance checks so tx executes even without
                // replaying preceding transactions (state at block-1).
                c.disable_nonce_check = true;
                // Disable EIP-7825 tx gas limit cap (default OSAKA spec sets 30M cap).
                c.tx_gas_limit_cap = Some(u64::MAX);
                // Disable chain ID check for pre-EIP-155 legacy txs (The DAO era).
                c.tx_chain_id_check = false;
            });

        let mut evm = ctx.build_mainnet_with_inspector(filter);

        // ── 4. Replay preceding transactions ────────────────────────────
        // This builds the correct pre-state for the target tx.
        // Each preceding tx is committed via inspect_tx_commit, which
        // also invokes the inspector, but we reset before the target tx.
        println!(
            "  Replaying {} preceding txs (with RPC state fetches)...",
            tx_index
        );
        let replay_start = Instant::now();
        for j in 0..tx_index {
            let tx = &transactions[j];
            let tx_env = build_tx_env(tx, CHAIN_ID);
            let _ = evm.inspect_tx_commit(tx_env);
            if (j + 1) % 50 == 0 {
                println!("    ... replayed {}/{}", j + 1, tx_index);
            }
        }
        let replay_elapsed = replay_start.elapsed();
        println!(
            "  Replay done in {:.1}s",
            replay_elapsed.as_secs_f64()
        );

        // ── 5. Phase 1: Reset filter, then execute target tx ─────────────
        evm.inspector.reset();

        let target_tx = &transactions[tx_index];
        let target_tx_env = build_tx_env(target_tx, CHAIN_ID);

        let exec_start = Instant::now();
        let exec_result = evm.inspect_one_tx(target_tx_env.clone());
        let exec_elapsed = exec_start.elapsed();

        let flagged = evm.inspector.requires_deep_inspection();
        let case_elapsed = case_start.elapsed();

        let status = match &exec_result {
            Ok(result) => match result {
                ExecutionResult::Success { .. } => "Success".to_string(),
                ExecutionResult::Revert { .. } => "Revert".to_string(),
                ExecutionResult::Halt { reason, .. } => format!("Halt({reason:?})"),
            },
            Err(e) => format!("Error: {e:?}"),
        };

        let symbol = if flagged { "✅" } else { "❌" };
        println!(
            "  Phase 1:  {} | EVM: {} | Exec: {:.3}ms | Total: {:.1}s",
            symbol,
            status,
            exec_elapsed.as_secs_f64() * 1000.0,
            case_elapsed.as_secs_f64(),
        );
        println!(
            "  Phase 2 needed: {}",
            if flagged {
                "YES — flagged for deep inspection"
            } else {
                "NO — would skip Phase 2"
            }
        );

        // ── 6. Phase 2: SecurityInspector deep inspection ────────────────
        println!("\n  ─── Phase 2: SecurityInspector ───");

        // Use a fresh RPC-backed state (same as Phase 1) so all accounts are available
        let prev_block_id2: BlockId = (block_number - 1).into();
        let state_db2 =
            WrapDatabaseAsync::new(AlloyDB::new(provider.clone(), prev_block_id2)).unwrap();
        let cache_db2 = CacheDB::new(state_db2);
        let phase2_state = StateBuilder::new_with_database(cache_db2).build();
        let ctx2 = Context::mainnet()
            .with_db(phase2_state)
            .modify_block_chained(|b| {
                b.number = U256::from(block.header.number);
                b.beneficiary = block.header.beneficiary;
                b.timestamp = U256::from(block.header.timestamp);
                b.difficulty = block.header.difficulty;
                b.gas_limit = block.header.gas_limit;
                b.basefee = block.header.base_fee_per_gas.unwrap_or_default();
            })
            .modify_cfg_chained(|c| {
                c.chain_id = CHAIN_ID;
                c.disable_nonce_check = true;
                c.tx_gas_limit_cap = Some(u64::MAX);
                c.tx_chain_id_check = false;
            });

        let sec_inspector = SecurityInspector::new(true, true, true);
        let mut phase2_evm = ctx2.build_mainnet_with_inspector(sec_inspector);

        println!("  Replaying {} preceding txs for Phase 2...", tx_index);
        for j in 0..tx_index {
            phase2_evm.inspector = SecurityInspector::new(true, true, true);
            let tx = &transactions[j];
            let tx_env = build_tx_env(tx, CHAIN_ID);
            let _ = phase2_evm.inspect_tx_commit(tx_env);
        }

        // Execute target tx with SecurityInspector
        phase2_evm.inspector = SecurityInspector::new(true, true, true);
        let p2_start = Instant::now();
        let p2_result = phase2_evm.inspect_tx_commit(target_tx_env);
        phase2_evm.inspector.finalize_detection();
        let p2_elapsed = p2_start.elapsed();

        let p2_status = match &p2_result {
            Ok(result) => match result {
                ExecutionResult::Success { .. } => "Success".to_string(),
                ExecutionResult::Revert { .. } => "Revert".to_string(),
                ExecutionResult::Halt { reason, .. } => format!("Halt({reason:?})"),
            },
            Err(e) => format!("Error: {e:?}"),
        };

        println!("  Phase 2 EVM: {} | Exec: {:.3}ms", p2_status, p2_elapsed.as_secs_f64() * 1000.0);
        println!("  Risk Score : {}", phase2_evm.inspector.risk_score);
        println!("  Severity   : {:?}", phase2_evm.inspector.max_severity);
        if phase2_evm.inspector.heuristics.is_empty() {
            println!("  Heuristics : (none)");
        } else {
            println!("  Heuristics :");
            for h in &phase2_evm.inspector.heuristics {
                println!("    • {}", h);
            }
        }
        println!();

        results.push((tc.name, flagged, status, exec_elapsed.as_secs_f64() * 1000.0));
    }

    // ── Summary ─────────────────────────────────────────────────────────
    let total_elapsed = total_start.elapsed();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    SUMMARY                                 ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  {:<36} {:>6}  {:>8}  {:>7} ║",
        "Attack", "Filter", "EVM", "Exec ms"
    );
    println!("╠══════════════════════════════════════════════════════════════╣");

    let mut pass_count = 0;
    let total = results.len();

    for (name, flagged, status, exec_ms) in &results {
        let mark = if *flagged {
            pass_count += 1;
            "✅ PASS"
        } else {
            "❌ MISS"
        };
        let short_status: String = status.chars().take(8).collect();
        println!(
            "║  {:<36} {:>6}  {:>8}  {:>7.3} ║",
            name, mark, short_status, exec_ms
        );
    }

    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Detection Rate: {}/{} ({:.0}%)  Total Time: {:.1}s           ║",
        pass_count,
        total,
        (pass_count as f64 / total as f64) * 100.0,
        total_elapsed.as_secs_f64()
    );
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}
