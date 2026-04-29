use revm::{
    bytecode::opcode,
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter, InstructionResult, CallInput},
    interpreter::interpreter_types::Jumps,
    primitives::{Address, Log, U256},
    Inspector,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TaintState {
    #[default]
    Clean,
    TaintedInput,      // Source: Calldata
    TaintedByOverflow, // Source: Arithmetic Overflow on Tainted Input
}

impl TaintState {
    pub fn is_tainted(&self) -> bool {
        *self != TaintState::Clean
    }
}

/// Alert severity levels for graduated reporting
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
#[allow(dead_code)]
pub enum AlertSeverity {
    #[default]
    None,
    Low,      // Lock-only trigger, no data dependency
    Medium,   // CEI on non-critical slot
    High,     // CEI on high-risk slot
    Critical, // Lock + CEI both triggered
}

impl AlertSeverity {
    pub fn risk_score(&self) -> u8 {
        match self {
            AlertSeverity::Critical => 100,
            AlertSeverity::High => 100,
            AlertSeverity::Medium => 75,
            AlertSeverity::Low => 50,
            AlertSeverity::None => 0,
        }
    }
}

/// Epoch tracking for a single storage slot
#[derive(Clone, Debug, Default)]
pub struct SlotEpoch {
    pub last_read_epoch: u64,
    pub last_write_epoch: u64,  // When subcall wrote to this slot
    pub write_origin_frame_id: u64, // Which frame wrote this (0 = no write yet)
}

/// CEI Candidate - generated in Phase 1, judged in Phase 2
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct CeiCandidate {
    pub contract: Address,           // Contract where CEI violation occurred
    pub slot: U256,                   // Affected slot
    pub read_epoch: u64,             // When parent frame read the slot
    pub write_epoch: u64,            // When subcall wrote the slot
    pub read_frame_id: u64,          // Parent frame ID
    pub write_frame_id: u64,         // Child frame that wrote
    pub write_depth: usize,          // Call depth of the write
    pub is_high_risk: bool,          // Was slot used in control flow?
    pub selector: Option<[u8; 4]>,   // Function selector of the parent frame
}

/// Track balance changes for Phase 2 Rule 2.1 (Asset Invariant)
#[derive(Clone, Debug, Default)]
pub struct BalanceTracker {
    /// ETH delta per address (positive = received, negative = sent)
    pub eth_delta: HashMap<Address, i128>,
    /// ERC20 delta: (token_contract, holder_address) -> delta
    pub erc20_delta: HashMap<(Address, Address), i128>,
    /// Contracts involved in CEI patterns
    pub cei_contracts: HashSet<Address>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OverflowContext {
    pub pc: usize,
    pub op: u8,
    pub contract: Address,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct FrameTaint {
    pub stack: Vec<TaintState>,
    /// Memory taint at BYTE level. Key is byte offset.
    pub memory: HashMap<usize, TaintState>,
    /// Accumulated overflows in this frame that hit a Sink.
    pub pending_overflows: Vec<OverflowContext>,
    /// Slots written by THIS frame (SSTORE).
    pub written_slots: HashSet<U256>,
    /// Slots read by THIS frame (SLOAD).
    pub read_slots: HashSet<U256>,
    /// The address of the contract executing in this frame
    pub contract: Address,
    /// Slots modified by sub-calls of this frame. Tracks (Contract Address, Slot Index).
    pub subcall_modified_slots: HashSet<(Address, U256)>,
    /// Unique identifier for this call frame (monotonically increasing)
    pub frame_id: u64,
    /// Epoch tracking for slots - key: slot, value: read/write epochs
    pub slot_epochs: HashMap<U256, SlotEpoch>,
    /// Slots that participated in control flow (JUMPI) or financial operations
    pub high_risk_slots: HashSet<U256>,
    /// Function selector of this frame (first 4 bytes of calldata)
    pub selector: Option<[u8; 4]>,
}

#[derive(Clone, Debug)]
pub struct SecurityInspector {
    pub risk_score: u8,
    pub heuristics: Vec<String>,
    pub max_severity: AlertSeverity,  // Track highest severity encountered
    
    // Configuration Flags
    pub check_reentrancy: bool,
    pub check_overflow: bool,
    /// Toggle for Enhanced Check 2 (Read-Call-Write / Stale Write Hazard)
    pub check_cei: bool,

    // --- Re-entrancy Logic Fields ---
    pub last_sload: Option<(U256, usize)>,
    pub current_context_reads: HashMap<Address, HashSet<U256>>,
    
    /// Globally LOCKED slots with Locking Frame ID.
    /// Key: (Contract Address, Slot Index) -> Value: frame_id that created the lock
    pub active_locks: HashMap<(Address, U256), u64>,
    
    pub lock_stack: Vec<Vec<(Address, U256)>>,

    // --- Epoch & Frame Tracking ---
    /// Current epoch - incremented on each CALL
    pub current_epoch: u64,
    /// Next frame ID to assign (monotonic)
    pub next_frame_id: u64,

    // --- Taint Propagation Fields ---
    pub frame_stack: Vec<FrameTaint>,
    
    // --- 3-Phase Detection Fields ---
    /// Phase 1: CEI candidates (not yet confirmed as attacks)
    pub cei_candidates: Vec<CeiCandidate>,
    /// Phase 2: Balance tracking for asset invariant check
    pub balance_tracker: BalanceTracker,
}

impl SecurityInspector {
    pub fn new(check_reentrancy: bool, check_overflow: bool, check_cei: bool) -> Self {
        Self {
            risk_score: 0,
            heuristics: Vec::new(),
            max_severity: AlertSeverity::None,
            check_reentrancy,
            check_overflow,
            check_cei,
            last_sload: None,
            current_context_reads: HashMap::new(),
            active_locks: HashMap::new(),
            lock_stack: Vec::new(),
            current_epoch: 0,
            next_frame_id: 1,  // Start at 1 so 0 can be "root frame"
            frame_stack: vec![FrameTaint::default()],
            cei_candidates: Vec::new(),
            balance_tracker: BalanceTracker::default(),
        }
    }
    
    fn add_heuristic(&mut self, message: String) {
        if !self.heuristics.contains(&message) {
            self.heuristics.push(message);
        }
    }

    /// Helper to get the current frame's taint state
    fn current_frame_mut(&mut self) -> &mut FrameTaint {
        self.frame_stack.last_mut().expect("No active frame")
    }
    
    /// Phase 2: Judge CEI candidates using attack semantic rules
    /// Call this after transaction execution to get final detection results
    pub fn finalize_detection(&mut self) {
        let candidates = std::mem::take(&mut self.cei_candidates);
        
        if candidates.is_empty() {
            return;
        }
        
        for candidate in &candidates {
            // For same-contract reentrancy: check stale-read pattern
            // read_epoch < write_epoch means parent read before subcall wrote
            let is_stale_read = candidate.read_epoch > 0 && candidate.write_epoch > 0 
                && candidate.read_epoch < candidate.write_epoch;
            
            // For cross-contract reentrancy: write_epoch might be 0 (subcall didn't write to our storage)
            // In this case, we rely on asset loss detection
            let is_cross_contract_pattern = candidate.read_epoch > 0 && candidate.write_epoch == 0;
            
            // Rule 2.1: Asset Invariant Violation
            // Check if CEI contract lost assets (ΔETH + ΣΔERC20 < 0)
            // For same-contract: require stale-read pattern
            // For cross-contract: require high-risk slot, asset loss, AND deep call stack (depth > 4)
            // The depth check helps filter out legitimate DeFi operations which usually have shallow call stacks
            let has_asset_loss = self.check_asset_invariant(candidate.contract);
            let rule_2_1 = (is_stale_read && has_asset_loss) || 
                (is_cross_contract_pattern && has_asset_loss && candidate.is_high_risk && candidate.write_depth > 4);
            
            // Rule 2.3: Accounting Slot Cross-Layer Write
            // Check if slot is a core accounting slot (balances, totalSupply, etc.)
            // AND write happened at depth > 1
            // CRITICAL: Must have stale-read pattern (read before subcall write)
            let mut rule_2_3 = self.is_accounting_slot(candidate.slot) && candidate.write_depth > 1 
                && is_stale_read;
            
            // Rule 2.4: Same-contract reentrancy with high-risk flag
            // If the candidate is marked as high-risk (same-contract reentrancy), 
            // and write_depth > 2 (indicating nested calls), flag it
            // CRITICAL: Must have stale-read pattern
            let rule_2_4 = candidate.is_high_risk && candidate.write_depth > 2 && is_stale_read;
            
            // Phase 3 Filter: Rule 3.2 (Legitimate Callbacks)
            // If Rule 2.3 triggered but function is transfer/transferFrom, suppress it (unless Rule 2.1 also triggers)
            // This handles false positives like FLOKI fee-on-transfer callbacks
            if rule_2_3 && !rule_2_1 {
                if let Some(sel) = candidate.selector {
                    // transfer: 0xa9059cbb, transferFrom: 0x23b872dd
                    // safeTransfer variants and common hooks
                    if sel == [0xa9, 0x05, 0x9c, 0xbb] || sel == [0x23, 0xb8, 0x72, 0xdd] ||
                       sel == [0x79, 0x1a, 0xc9, 0x47] || sel == [0x5c, 0x11, 0xd7, 0x95] ||
                       sel == [0x02, 0x2c, 0x0d, 0x9f] || sel == [0xc6, 0x51, 0x2c, 0xc1] {
                        rule_2_3 = false;
                    }
                }
            }
            
            // Only report if at least one Phase 2 rule is triggered
            if rule_2_1 || rule_2_3 || rule_2_4 {
                let severity = if candidate.is_high_risk {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                };
                
                let rule_info = if rule_2_1 { "AssetLoss" } 
                    else if rule_2_4 { "SameContractReentrancy" }
                    else { "AccountingSlot" };
                let msg = format!(
                    "{:?}: REENTRANCY ATTACK! [{}] Contract {:?} Slot {} (read@{}, write@{}, depth:{}, sel:{:?})",
                    severity, rule_info, candidate.contract, candidate.slot,
                    candidate.read_epoch, candidate.write_epoch, candidate.write_depth, candidate.selector
                );
                
                self.add_heuristic(msg.clone());
                let current_score = severity.risk_score();
                if current_score > self.risk_score {
                    self.risk_score = current_score;
                }
                if self.max_severity < severity {
                    self.max_severity = severity;
                }
                println!("🚨 [Attack-Reentrancy] {}", msg);
            }
        }
    }
    
    /// Rule 2.1: Check if contract lost assets (Pure Loss / Draining)
    fn check_asset_invariant(&self, contract: Address) -> bool {
        let mut has_gain = false;
        let mut has_significant_loss = false;
        
        // Check ERC20s
        for ((_, holder), delta) in &self.balance_tracker.erc20_delta {
            if *holder == contract {
                if *delta > 0 {
                    has_gain = true;
                } else if *delta < -1_000_000 {
                    has_significant_loss = true;
                }
            }
        }
        
        // Check ETH
        if let Some(&delta) = self.balance_tracker.eth_delta.get(&contract) {
             if delta > 0 {
                 has_gain = true;
             } else if delta < -1_000_000_000_000_000 { // 0.001 ETH
                 has_significant_loss = true;
             }
        }

        // Only report loss if there are NO gains (Pure Draining)
        // If there are gains, it's likely a swap or legitimate interaction
        has_significant_loss && !has_gain
    }
    
    /// Rule 2.3: Check if slot is a core accounting slot
    fn is_accounting_slot(&self, slot: U256) -> bool {
        // Heuristic: slots 0-20 are often used for:
        // - Core state variables (owner, supply, pausers, reentrancy guards)
        // - Mapping base slots
        slot <= U256::from(20)
    }
}

impl<CTX> Inspector<CTX> for SecurityInspector {
    fn call(
        &mut self,
        _context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // Increment epoch on each CALL
        self.current_epoch += 1;
        
        let mut frame = FrameTaint::default();
        frame.contract = inputs.target_address;
        // Extract selector if available
        if inputs.input.len() >= 4 {
            let mut sel = [0u8; 4];
            match &inputs.input {
                CallInput::Bytes(bytes) => {
                    sel.copy_from_slice(&bytes[0..4]);
                    frame.selector = Some(sel);
                }
                CallInput::SharedBuffer(_) => {
                    // SharedBuffer needs context to resolve; skip selector extraction
                }
            }
        }
        // Assign unique frame ID
        frame.frame_id = self.next_frame_id;
        self.next_frame_id += 1;
        
        let current_frame_id = frame.frame_id;
        self.frame_stack.push(frame);

        if !self.check_reentrancy {
            return None;
        }

        // Track ETH transfers for Phase 2 Rule 2.1
        let value = inputs.value.transfer().unwrap_or(U256::ZERO);
        if value > U256::ZERO {
            // Convert to i128 (saturating)
            let val_i128: i128 = value.saturating_to::<i128>();
            
            // Deduct from caller
            let caller_delta = self.balance_tracker.eth_delta.entry(inputs.caller).or_insert(0);
            *caller_delta = caller_delta.saturating_sub(val_i128);
            
            // Add to target
            let target_delta = self.balance_tracker.eth_delta.entry(inputs.target_address).or_insert(0);
            *target_delta = target_delta.saturating_add(val_i128);
        }

        let caller = inputs.caller;
        let mut new_locks = Vec::new();

        if let Some(critical_slots) = self.current_context_reads.get(&caller) {
            for &slot in critical_slots {
                let lock_key = (caller, slot);
                // Lock with frame_id instead of depth
                if !self.active_locks.contains_key(&lock_key) {
                    self.active_locks.insert(lock_key, current_frame_id);
                    new_locks.push(lock_key);
                }
            }
        }
        self.lock_stack.push(new_locks);
        None
    }

    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        if let Some(frame) = self.frame_stack.pop() {
             // Logic A: Panic Detection (Solidity 0.8+)
             let is_panic_overflow = if matches!(outcome.result.result, InstructionResult::Revert) {
                  let out = &outcome.result.output;
                  out.len() >= 36 
                      && out[0..4] == [0x4e, 0x48, 0x7b, 0x71] 
                      && out[35] == 0x11
             } else {
                 false
             };

             // Logic B: Confirm Vulnerability if Success
             // Check explicitly for success variants as is_ok() might not exist
             if !is_panic_overflow && matches!(outcome.result.result, InstructionResult::Return | InstructionResult::Stop) {
                  for overflow in frame.pending_overflows {
                      self.risk_score = 100;
                      self.add_heuristic(overflow.message.clone());
                      println!("🚨 [Attack-Overflow] {}", overflow.message);
                  }
             }



             // Logic C: Propagate "Modified Slots" and Write Epochs to Parent (for CEI/Lendf.Me detection)
             if self.check_reentrancy {
                 let current_epoch = self.current_epoch;
                 let child_frame_id = frame.frame_id;
                 
                 if let Some(parent) = self.frame_stack.last_mut() {
                     let child_contract = frame.contract;
                     let parent_contract = parent.contract;
                     
                     // 1. Propagate Direct Writes from Child
                     // Key insight: Use child_contract (the actual writer) for direct writes
                     for slot in &frame.written_slots {
                         parent.subcall_modified_slots.insert((child_contract, *slot));
                         // Track epoch if child wrote to PARENT's contract storage
                         // This happens in same-contract reentrancy (A -> B -> A)
                         if child_contract == parent_contract {
                             let epoch_entry = parent.slot_epochs.entry(*slot).or_default();
                             if epoch_entry.last_write_epoch < current_epoch {
                                 epoch_entry.last_write_epoch = current_epoch;
                                 epoch_entry.write_origin_frame_id = child_frame_id;
                             }
                         }
                     }
                     // 2. Propagate Deep Writes from Child's Subcalls
                     // Preserve original (contract, slot) pairs - don't overwrite with child_contract
                     for (addr, slot) in &frame.subcall_modified_slots {
                         parent.subcall_modified_slots.insert((*addr, *slot));
                         // Track epoch if deep subcall wrote to PARENT's contract storage
                         if *addr == parent_contract {
                             let epoch_entry = parent.slot_epochs.entry(*slot).or_default();
                             if epoch_entry.last_write_epoch < current_epoch {
                                 epoch_entry.last_write_epoch = current_epoch;
                                 epoch_entry.write_origin_frame_id = child_frame_id;
                             }
                         }
                     }
                     
                     // 3. Track the LATEST write epoch for ANY slot written to parent's contract
                     // This is used for stale-read detection when parent reads slot X but subcall wrote slot Y
                     // We need to know WHEN the subcall wrote to our contract (any slot)
                     let any_write_to_parent = frame.written_slots.iter()
                         .filter(|_| child_contract == parent_contract)
                         .chain(frame.subcall_modified_slots.iter()
                             .filter(|(addr, _)| *addr == parent_contract)
                             .map(|(_, slot)| slot));
                     
                     for slot in any_write_to_parent {
                         let epoch_entry = parent.slot_epochs.entry(*slot).or_default();
                         if epoch_entry.last_write_epoch < current_epoch {
                             epoch_entry.last_write_epoch = current_epoch;
                             epoch_entry.write_origin_frame_id = child_frame_id;
                         }
                     }
                 }
             }
        }

        if !self.check_reentrancy {
            return;
        }

        if let Some(locks_to_remove) = self.lock_stack.pop() {
            for lock_key in locks_to_remove {
                self.active_locks.remove(&lock_key);
            }
        }
    }

    // Track ERC20 Transfer events for Phase 2 balance analysis
    fn log(&mut self, _interp: &mut Interpreter, _context: &mut CTX, log: Log) {
        // ERC20 Transfer: topic0 = keccak256("Transfer(address,address,uint256)")
        const TRANSFER_TOPIC: [u8; 32] = [
            0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 
            0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
            0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 
            0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
        ];
        
        if log.data.topics().len() >= 3 {
            let topic0 = log.data.topics()[0].0;
            if topic0 == TRANSFER_TOPIC {
                let from = Address::from_slice(&log.data.topics()[1].0[12..32]);
                let to = Address::from_slice(&log.data.topics()[2].0[12..32]);
                
                if log.data.data.len() >= 32 {
                    let value_bytes: [u8; 32] = log.data.data[0..32].try_into().unwrap_or([0u8; 32]);
                    let value = U256::from_be_bytes(value_bytes);
                    let token = log.address;
                    let delta: i128 = value.saturating_to::<i128>();
                    
                    // From loses tokens, To gains tokens
                    *self.balance_tracker.erc20_delta.entry((token, from)).or_insert(0) -= delta;
                    *self.balance_tracker.erc20_delta.entry((token, to)).or_insert(0) += delta;
                }
            }
        }
    }
    fn create(&mut self, _: &mut CTX, _: &mut CreateInputs) -> Option<CreateOutcome> { None }
    fn create_end(&mut self, _: &mut CTX, _: &CreateInputs, _out: &mut CreateOutcome) {}
    
    fn step(&mut self, interpreter: &mut Interpreter, _context: &mut CTX) {
        let op = interpreter.bytecode.opcode();
        let pc = interpreter.bytecode.pc();
        let contract = interpreter.input.target_address;
        
        // Copy flags
        let check_reentrancy = self.check_reentrancy;
        let check_overflow = self.check_overflow;

        fn get_taint_val(s: &[TaintState], n: usize) -> TaintState {
            let l = s.len();
            if l > n { s[l - 1 - n] } else { TaintState::Clean }
        }

        let mut sstore_taint_detected: Option<(U256, U256)> = None;
        let mut call_taint_detected: Option<U256> = None;
        let mut bec_attack_detected = false;

        {
            let frame = self.current_frame_mut();
            
            // SYNC: Ensure frame.contract matches the actual storage context (Handles DelegateCall mismatch)
            if frame.contract != contract {
                 frame.contract = contract;
            }
            
            // Sync shadow stack length
            let actual_len = interpreter.stack.len();
            while frame.stack.len() > actual_len {
                frame.stack.pop();
            }
            while frame.stack.len() < actual_len {
                frame.stack.push(TaintState::Clean);
            }
            let stack_len = frame.stack.len();

            // -------------------------------------------------------------
            // 1. SINK CHECKING
            // -------------------------------------------------------------
            // JUMPI is intentionally NOT a sink anymore.
            // SafeMath patterns like `require(a + b >= a)` cause excessive false positives
            // when JUMPI is treated as a sink for TaintedByOverflow conditions.
            // Overflow detection now relies on:
            // 1. SSTORE: writing overflow value to storage
            // 2. CALL: using overflow value for transfers
            // 3. Inline checks during ADD/MUL for "wrapped to small value" patterns (BEC attack)
            
            if op == opcode::SSTORE {
                let val_taint = get_taint_val(&frame.stack, 1);
                if val_taint == TaintState::TaintedByOverflow {
                     if let (Ok(slot), Ok(val)) = (interpreter.stack.peek(0), interpreter.stack.peek(1)) {
                         sstore_taint_detected = Some((slot, val));
                     }
                }
            } 
            else if op == opcode::CALL || op == opcode::CALLCODE {
                let val_taint = get_taint_val(&frame.stack, 2);
                if val_taint == TaintState::TaintedByOverflow {
                    if let Ok(value) = interpreter.stack.peek(2) {
                        if value > U256::ZERO {
                            call_taint_detected = Some(value);
                        }
                    }
                }
            }

            // -------------------------------------------------------------
            // 2. TAINT PROPAGATION
            // -------------------------------------------------------------

            if op == opcode::CALLDATALOAD {
                frame.stack.pop();
                frame.stack.push(TaintState::TaintedInput);
            } 
            else if op == opcode::CALLDATACOPY {
                if let (Ok(dest_offset), Ok(length)) = (interpreter.stack.peek(0), interpreter.stack.peek(2)) {
                    let start: usize = dest_offset.saturating_to::<usize>();
                    let len: usize = length.saturating_to::<usize>();
                    // BYTE level taint
                    for i in 0..len {
                        frame.memory.insert(start + i, TaintState::TaintedInput);
                    }
                }
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
            }
            // --- Arithmetic Loophole Fix & Propagation ---
            else if op == opcode::ADD || op == opcode::MUL || op == opcode::SUB || op == opcode::EXP {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                // Aggressive Propagation: If any input is already overflow-tainted, the result remains so.
                // This ensures that "overflow -> sub -> sstore" chains are caught.
                let prev_overflow = t1 == TaintState::TaintedByOverflow || t2 == TaintState::TaintedByOverflow;
                let inputs_tainted = t1.is_tainted() || t2.is_tainted();
                
                // Check for overflow and get operand values
                let (overflow, is_bec_pattern, is_smt_pattern) = if let (Ok(a), Ok(b)) = (interpreter.stack.peek(0), interpreter.stack.peek(1)) {
                    let ov = match op {
                        opcode::ADD => U256::overflowing_add(a, b).1,
                        opcode::MUL => U256::overflowing_mul(a, b).1,
                        opcode::SUB => U256::overflowing_sub(a, b).1,
                        opcode::EXP => a.overflowing_pow(b).1,
                        _ => false,
                    };
                    
                    // BEC Attack Pattern Detection:
                    // MUL where ONE operand is array length (very small, usually < 1M),
                    // and the other is a maliciously crafted HUGE value that wraps to a small result.
                    // BEC: `count (small) * value (huge) = amount (small)`
                    // BOTH operands must be user-controlled (tainted)
                    let both_tainted = t1.is_tainted() && t2.is_tainted();
                    let threshold_small = U256::from(1_000_000_000_000_000_000u64); // 1e18
                    
                    let is_bec = if op == opcode::MUL && ov && both_tainted {
                        let threshold_array_len = U256::from(1_000_000u64); // Array length upper bound
                        let threshold_large = U256::from(1u64) << 240;      // Value must be huge to wrap 2**256 cleanly
                        let (result, _) = U256::overflowing_mul(a, b);
                        let a_is_len = a < threshold_array_len;
                        let b_is_len = b < threshold_array_len;
                        let a_is_huge = a > threshold_large;
                        let b_is_huge = b > threshold_large;
                        ((a_is_len && b_is_huge) || (b_is_len && a_is_huge)) && result < threshold_small
                    } else { false };

                    // SMT Attack Pattern Detection (ADD Wrap-around):
                    // Two tainted values added together to bypass require(balance >= a + b) by wrapping to ~0.
                    let is_smt = if op == opcode::ADD && ov {
                        let (result, _) = U256::overflowing_add(a, b);
                        // DEBUG: If it wraps to a small value, print it to see why it fails
                        if result < threshold_small {
                            println!("DEBUG ADD WRAP: a={}, b={}, result={}, t1={:?}, t2={:?}", a, b, result, t1, t2);
                        }
                        // Requires both inputs tainted to formally trigger the attack alarm
                        both_tainted && result < threshold_small
                    } else { false };
                    
                    (ov, is_bec, is_smt)
                } else {
                    (false, false, false)
                };
                
                // Attack Detection Alerts
                if is_bec_pattern || is_smt_pattern {
                    if let (Ok(a), Ok(b)) = (interpreter.stack.peek(0), interpreter.stack.peek(1)) {
                        let msg = if is_bec_pattern {
                            let (result, _) = U256::overflowing_mul(a, b);
                            format!("CRITICAL: BEC MUL OVERFLOW ATTACK! {} * {} = {} (wrapped). PC: {}", a, b, result, pc)
                        } else {
                            let (result, _) = U256::overflowing_add(a, b);
                            format!("CRITICAL: SMT ADD OVERFLOW ATTACK! {} + {} = {} (wrapped). PC: {}", a, b, result, pc)
                        };
                        frame.pending_overflows.push(OverflowContext {
                            pc, op, contract, message: msg
                        });
                        bec_attack_detected = true;
                    }
                }
                
                // Taint Logic
                let result_taint = if prev_overflow {
                    // Propagate previous overflow status forward
                     TaintState::TaintedByOverflow
                } else if inputs_tainted {
                     // New overflow?
                     if overflow {
                         TaintState::TaintedByOverflow
                     } else {
                         TaintState::TaintedInput
                     }
                } else {
                    TaintState::Clean
                };
                
                frame.stack.push(result_taint);
            }
            // --- KECCAK256 / SHA3 ---
            else if op == opcode::KECCAK256 {
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.push(TaintState::Clean);
            }
            // --- DIV, MOD, SDIV, SMOD ---
            else if op == opcode::DIV || op == opcode::MOD || op == opcode::SDIV || op == opcode::SMOD {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                
                // Propagate TaintedByOverflow even through division
                // e.g. (OverflowedValue / 2) is still derived from an overflow
                let result_taint = if t1 == TaintState::TaintedByOverflow || t2 == TaintState::TaintedByOverflow {
                    TaintState::TaintedByOverflow
                } else if t1.is_tainted() || t2.is_tainted() {
                    TaintState::TaintedInput
                } else {
                    TaintState::Clean
                };
                frame.stack.push(result_taint);
            }
            // --- ADDMOD, MULMOD ---
            else if op == opcode::ADDMOD || op == opcode::MULMOD {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t3 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let result_taint = if t1.is_tainted() || t2.is_tainted() || t3.is_tainted() {
                    TaintState::TaintedInput
                } else {
                    TaintState::Clean
                };
                frame.stack.push(result_taint);
            }
            // --- SIGNEXTEND ---
            else if op == opcode::SIGNEXTEND {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let result_taint = if t1.is_tainted() || t2.is_tainted() {
                    TaintState::TaintedInput
                } else {
                    TaintState::Clean
                };
                frame.stack.push(result_taint);
            }
            // --- NOT, ISZERO ---
            else if op == opcode::NOT || op == opcode::ISZERO {
                 let t = frame.stack.pop().unwrap_or(TaintState::Clean);
                 // Downgrade TaintedByOverflow -> TaintedInput
                 if t.is_tainted() {
                     frame.stack.push(TaintState::TaintedInput);
                 } else {
                     frame.stack.push(TaintState::Clean);
                 }
            }
            // --- Bitwise Sanitization ---
            // Explicitly list opcodes
            else if op == opcode::AND || op == opcode::OR || op == opcode::XOR || 
                    op == opcode::SHL || op == opcode::SHR || op == opcode::SAR || op == opcode::BYTE {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let any_tainted = t1.is_tainted() || t2.is_tainted();
                if any_tainted {
                    frame.stack.push(TaintState::TaintedInput);
                } else {
                    frame.stack.push(TaintState::Clean);
                }
            }
            // --- Comparator Sanitization ---
            else if (op >= opcode::LT && op <= opcode::SGT) || op == opcode::EQ {
                let t1 = frame.stack.pop().unwrap_or(TaintState::Clean);
                let t2 = frame.stack.pop().unwrap_or(TaintState::Clean);
                // Downgrade
                if t1.is_tainted() || t2.is_tainted() {
                    frame.stack.push(TaintState::TaintedInput);
                } else {
                    frame.stack.push(TaintState::Clean);
                }
            }
            else if op == opcode::MLOAD {
                let mut loaded_taint = TaintState::Clean;
                
                if let Ok(offset) = interpreter.stack.peek(0) {
                    let start: usize = offset.saturating_to::<usize>();
                    
                    let mut overflow_count = 0usize;
                    let mut tainted_count = 0usize;
                    
                    for i in 0..32 {
                        if let Some(t) = frame.memory.get(&(start + i)) {
                            match t {
                                TaintState::TaintedByOverflow => {
                                    overflow_count += 1;
                                    tainted_count += 1;
                                },
                                TaintState::TaintedInput => {
                                    tainted_count += 1;
                                },
                                _ => {}
                            }
                        }
                    }
                    
                    if overflow_count == 32 {
                        loaded_taint = TaintState::TaintedByOverflow;
                    } else if tainted_count > 0 {
                        loaded_taint = TaintState::TaintedInput;
                    }
                }
                frame.stack.pop();
                frame.stack.push(loaded_taint);
            }
            else if op == opcode::MSTORE {
                if let (Ok(offset), Ok(_)) = (interpreter.stack.peek(0), interpreter.stack.peek(1)) {
                    let start: usize = offset.saturating_to::<usize>();
                    let value_taint = get_taint_val(&frame.stack, 1);
                    for i in 0..32 {
                        if value_taint == TaintState::Clean {
                            frame.memory.remove(&(start + i));
                        } else {
                            frame.memory.insert(start + i, value_taint);
                        }
                    }
                }
                frame.stack.pop();
                frame.stack.pop();
            }
            else if op == opcode::MSTORE8 {
                if let (Ok(offset), Ok(_)) = (interpreter.stack.peek(0), interpreter.stack.peek(1)) {
                    let start: usize = offset.saturating_to::<usize>();
                    let value_taint = get_taint_val(&frame.stack, 1);
                    if value_taint == TaintState::Clean {
                        frame.memory.remove(&start);
                    } else {
                        frame.memory.insert(start, value_taint);
                    }
                }
                frame.stack.pop();
                frame.stack.pop();
            }
            // --- SLOAD ---
            else if op == opcode::SLOAD {
                frame.stack.pop(); 
                frame.stack.push(TaintState::Clean);
            }
            else if op >= opcode::DUP1 && op <= opcode::DUP16 {
                let n = (op - opcode::DUP1 + 1) as usize;
                let t = get_taint_val(&frame.stack, n - 1);
                frame.stack.push(t);
            }
            else if op >= opcode::SWAP1 && op <= opcode::SWAP16 {
                let n = (op - opcode::SWAP1 + 1) as usize;
                if stack_len > n {
                    frame.stack.swap(stack_len - n - 1, stack_len - 1);
                }
            }
            else if op == opcode::POP {
                frame.stack.pop();
            }
            // --- SSTORE ---
            else if op == opcode::SSTORE {
                frame.stack.pop(); // slot
                frame.stack.pop(); // value
            }
            // --- BALANCE, EXTCODESIZE, EXTCODEHASH, BLOCKHASH ---
            else if op == opcode::BALANCE || op == opcode::EXTCODESIZE || op == opcode::EXTCODEHASH || op == opcode::BLOCKHASH {
                frame.stack.pop(); 
                frame.stack.push(TaintState::Clean);
            }
            // --- CODECOPY, EXTCODECOPY, RETURNDATACOPY ---
            else if op == opcode::CODECOPY || op == opcode::RETURNDATACOPY {
                if let (Ok(dest_offset), Ok(length)) = (interpreter.stack.peek(0), interpreter.stack.peek(2)) {
                    let start: usize = dest_offset.saturating_to::<usize>();
                    let len: usize = length.saturating_to::<usize>();
                    for i in 0..len {
                        frame.memory.remove(&(start + i));
                    }
                }
                 // 3 pops
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
            }
            else if op == opcode::EXTCODECOPY {
                if let (Ok(dest_offset), Ok(length)) = (interpreter.stack.peek(1), interpreter.stack.peek(3)) {
                     let start: usize = dest_offset.saturating_to::<usize>();
                    let len: usize = length.saturating_to::<usize>();
                    for i in 0..len {
                        frame.memory.remove(&(start + i));
                    }
                }
                // 4 pops
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
            }
             // --- LOG0-LOG4 ---
            else if op >= opcode::LOG0 && op <= opcode::LOG4 {
                let topic_count = (op - opcode::LOG0) as usize;
                for _ in 0..(2 + topic_count) {
                    frame.stack.pop();
                }
            }
             // --- CREATE/CREATE2 ---
            else if op == opcode::CREATE {
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.push(TaintState::Clean);
            }
            else if op == opcode::CREATE2 {
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.pop();
                frame.stack.push(TaintState::Clean);
            }
             // --- CALL/DELEGATE/STATIC ---
            else if op == opcode::CALL || op == opcode::CALLCODE {
                for _ in 0..7 { frame.stack.pop(); }
                frame.stack.push(TaintState::Clean);
            }
            else if op == opcode::DELEGATECALL || op == opcode::STATICCALL {
                for _ in 0..6 { frame.stack.pop(); }
                frame.stack.push(TaintState::Clean);
            }
        }
        
        if bec_attack_detected {
            self.risk_score = 100;
        }
        
        // -------------------------------------------------------------
        // 4. RE-ENTRANCY 
        // -------------------------------------------------------------
        let mut reentrancy_detected: Option<(U256, Address)> = None;

        if op == opcode::SSTORE && check_reentrancy {
            if let Ok(slot) = interpreter.stack.peek(0) {
                // TRACK WRITES
                self.current_frame_mut().written_slots.insert(slot);

                // CHECK 1: Lock Violation (frame_id based)
                // If slot is locked by a different frame, it's a violation
                let current_frame_id = self.frame_stack.last().map(|f| f.frame_id).unwrap_or(0);
                if let Some(&lock_frame_id) = self.active_locks.get(&(contract, slot)) {
                     // Violating lock: writing from a different frame than the one that created the lock
                     if current_frame_id != lock_frame_id {
                          reentrancy_detected = Some((slot, contract));
                     }
                }
                
                // CHECK 2: CEI Violation (Phase 1 - Generate Candidates)
                // No longer alerts directly - generates CeiCandidate for Phase 2 judgment
                if self.check_cei {
                    let call_depth = self.frame_stack.len();
                    let frame = self.current_frame_mut();
                    
                    // Check if any subcall wrote to THIS contract's storage (any slot)
                    // Key insight: Reentrancy attacks involve callbacks that modify the victim's state
                    // The callback might write to a DIFFERENT slot than what we're writing now,
                    // but if it wrote to ANY slot in our contract, it's suspicious
                    let is_dirty_same_contract_any_slot = frame.subcall_modified_slots.iter()
                        .any(|(addr, _)| *addr == contract);
                    
                    // Also check if subcall wrote to the EXACT same (contract, slot)
                    let is_dirty_exact_slot = frame.subcall_modified_slots.contains(&(contract, slot));
                    
                    // Check if this slot was read by this frame
                    let was_read = frame.read_slots.contains(&slot);
                    let is_high_risk = frame.high_risk_slots.contains(&slot);
                    
                    // NEW: For cross-contract reentrancy detection
                    // If we read a slot, made external calls (subcall_modified_slots not empty means calls were made),
                    // and now we're writing to the same slot, this could be a cross-contract reentrancy
                    // The subcall might have modified external state that affects our contract
                    let has_external_calls = !frame.subcall_modified_slots.is_empty();
                    
                    // Flag if:
                    // 1. Subcall wrote to our contract's storage (same-contract reentrancy)
                    // 2. OR we read this slot AND made external calls (potential cross-contract reentrancy)
                    let should_flag = is_dirty_same_contract_any_slot || 
                        (was_read && has_external_calls && is_high_risk);
                    
                    if should_flag {
                        // Get epoch data for this slot
                        let epoch_data = frame.slot_epochs.get(&slot).cloned().unwrap_or_default();
                        let frame_id = frame.frame_id;
                        
                        // Phase 1: Generate CEI candidate (don't alert yet)
                        let candidate = CeiCandidate {
                            contract,
                            slot,
                            read_epoch: epoch_data.last_read_epoch,
                            write_epoch: epoch_data.last_write_epoch,
                            read_frame_id: frame_id,
                            write_frame_id: epoch_data.write_origin_frame_id,
                            write_depth: call_depth,
                            is_high_risk: is_high_risk || is_dirty_exact_slot,
                            selector: frame.selector,
                        };
                        
                        // Track this contract for balance analysis
                        self.balance_tracker.cei_contracts.insert(contract);
                        self.cei_candidates.push(candidate);
                    }
                }
            }
        }
        if op == opcode::SLOAD && check_reentrancy {
            if let Ok(slot) = interpreter.stack.peek(0) {
                let current_epoch = self.current_epoch;
                let frame = self.current_frame_mut();
                frame.read_slots.insert(slot);
                
                // Record read epoch for this slot (epoch-based staleness check)
                let epoch_entry = frame.slot_epochs.entry(slot).or_default();
                epoch_entry.last_read_epoch = current_epoch;
                
                self.last_sload = Some((slot, pc));
            }
        }
        if op == opcode::JUMPI && check_reentrancy {
            if let Some((slot, sload_pc)) = self.last_sload {
                if pc > sload_pc && pc - sload_pc < 10 {
                    self.current_context_reads.entry(contract).or_default().insert(slot);
                    // Mark slot as high-risk (participated in control flow)
                    self.current_frame_mut().high_risk_slots.insert(slot);
                }
            }
        }

        if check_overflow {
             if let Some((slot, value)) = sstore_taint_detected {
                  // Only flag overflow SSTORE if the value is suspiciously small (wrap-around attack)
                  // OR insanely huge (underflow to max_uint, e.g. PoWH attack).
                  // Normal DeFi large values are easily < 2**200. Anything > 2**240 is clearly an underflow exploit.
                  // Ignored if value == 0, as writing 0 is clearing a slot, not an overflow exploit,
                  // and frequently happens due to taint propagation of 0 balances.
                  let threshold_small = U256::from(1_000_000_000_000_000_000u64); // 1e18
                  let threshold_huge = U256::from(1u64) << 240;
                  if (value > U256::ZERO && value < threshold_small) || value > threshold_huge {
                      let msg = format!("CRITICAL: OVERFLOW writing to State (SSTORE)! Slot: {}, Value: {}", slot, value);
                      self.current_frame_mut().pending_overflows.push(OverflowContext {
                          pc, op, contract, message: msg
                      });
                  }
             }
             if let Some(value) = call_taint_detected {
                  let msg = format!("CRITICAL: OVERFLOW affecting value transfer (CALL)! Value: {}", value);
                  self.current_frame_mut().pending_overflows.push(OverflowContext {
                      pc, op, contract, message: msg
                  });
             }
        }

        if let Some((slot, victim)) = reentrancy_detected {
             let msg = format!("CRITICAL: RE-ENTRANCY DETECTED! Writing to Locked Slot. Contract: {:?}, Slot: {}", victim, slot);
             self.add_heuristic(msg);
             self.risk_score = 100;
             println!("🚨 [Attack-Reentrancy] PC:{} | Writing to locked slot {} of {:?}", pc, slot, victim);
        }
    }
}
