//! # Phase 1 — Lightweight Flag Filter (Heimdall Security Engine)
//!
//! A **zero-allocation**, **O(1)-per-opcode** [`Inspector`] that acts as an
//! optimistic fast-path gate before the heavy Phase 2 [`SecurityInspector`].
//!
//! ## Heuristics
//!
//! | # | Name | Signal |
//! |---|------|--------|
//! | 1 | **Reentrancy Proxy** | `SSTORE` inside a nested external call (depth > base) |
//! | 2 | **Overflow Proxy** | Arithmetic wrap-around (`ADD`/`SUB`/`MUL`) followed by a critical sink (`SSTORE` or value-carrying `CALL`) within the same valid execution context |
//!
//! ## Revert Safety
//!
//! Overflow state is tracked per call-depth via a fixed 1024-bit bitmap
//! (`[u64; 16]`). When a sub-call **reverts**, its overflow bit is cleared;
//! when it **succeeds**, its overflow propagates upward to the parent frame
//! (conservatively: the parent may use the overflowed return value in a sink).
//!
//! ## Memory Layout
//!
//! ```text
//! flagged:          bool   —  1 byte
//! current_depth:    u32    —  4 bytes
//! overflow_bitmap:  [u64; 16] — 128 bytes
//! ────────────────────────────────────
//! Total (+ padding):        ~136 bytes, entirely on the stack.
//! ```

use revm::{
    interpreter::{
        interpreter_types::Jumps, CallInputs, CallOutcome, CreateInputs, CreateOutcome,
        Interpreter,
    },
    Inspector,
};

// ─── EVM Opcode Constants ────────────────────────────────────────────────
// Defined inline to avoid fragile dependency on opcode module re-export paths
// across revm crate versions.
const OP_ADD: u8 = 0x01;
const OP_MUL: u8 = 0x02;
const OP_SUB: u8 = 0x03;
const OP_SSTORE: u8 = 0x55;
const OP_CALL: u8 = 0xF1;
const OP_CALLCODE: u8 = 0xF2;

// ─── Bitmap Geometry ─────────────────────────────────────────────────────
/// EVM hard-limits call depth to 1024.
const MAX_DEPTH: usize = 1024;
/// Number of `u64` words needed to cover [`MAX_DEPTH`] bits.
const BITMAP_U64S: usize = MAX_DEPTH / 64; // 16

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Phase 1 Lightweight Flag Filter.
///
/// Monitors every EVM opcode with strictly **O(1)** overhead and **zero heap
/// allocations**. Its sole output is a single boolean flag indicating whether
/// the transaction should be forwarded to the Phase 2
/// [`SecurityInspector`](super::inspector::SecurityInspector) for deep
/// taint-tracking and frame-depth analysis.
///
/// # Usage
///
/// ```rust,ignore
/// let mut filter = LightweightFlagFilter::new();
///
/// // ... run the transaction with `filter` as the inspector ...
///
/// if filter.requires_deep_inspection() {
///     // Re-run with the heavy SecurityInspector (Phase 2).
/// }
///
/// // Reuse for the next transaction:
/// filter.reset();
/// ```
pub struct LightweightFlagFilter {
    /// The single output flag: `true` ⇒ Phase 2 inspection required.
    flagged: bool,

    /// Current call-stack depth.
    ///
    /// - `0` = no frame entered yet (pre-transaction).
    /// - `1` = the initial transaction call frame.
    /// - `2+` = inside one or more nested `CALL` / `CREATE` frames.
    current_depth: u32,

    /// Per-depth overflow-tracking bitmap (1024 bits).
    ///
    /// Bit *i* is **set** when an arithmetic overflow (`ADD`/`SUB`/`MUL`
    /// wrapping around `U256`) is detected while executing at call depth *i*.
    ///
    /// | Event | Action |
    /// |-------|--------|
    /// | Overflow detected at depth *d* | Set bit *d* |
    /// | Sub-call at depth *d* **succeeds** | Propagate bit *d* → bit *(d − 1)*, then clear bit *d* |
    /// | Sub-call at depth *d* **reverts** | Clear bit *d* (overflow never happened from the parent's view) |
    overflow_bitmap: [u64; BITMAP_U64S],
}

impl LightweightFlagFilter {
    // ── Construction / Lifecycle ──────────────────────────────────────

    /// Creates a new filter with all state zeroed.
    #[inline]
    pub const fn new() -> Self {
        Self {
            flagged: false,
            current_depth: 0,
            overflow_bitmap: [0u64; BITMAP_U64S],
        }
    }

    /// Returns `true` if the transaction exhibited signals that warrant
    /// deep Phase 2 inspection.
    ///
    /// Call **after** Phase 1 simulation completes.
    #[inline]
    pub const fn requires_deep_inspection(&self) -> bool {
        self.flagged
    }

    /// Resets all internal state so the filter can be reused for the next
    /// transaction without reallocating.
    #[inline]
    pub fn reset(&mut self) {
        self.flagged = false;
        self.current_depth = 0;
        self.overflow_bitmap = [0u64; BITMAP_U64S];
    }

    // ── Bitmap Primitives (all O(1)) ─────────────────────────────────

    /// Sets the overflow bit at `depth`.
    #[inline(always)]
    fn set_overflow(&mut self, depth: u32) {
        let word = (depth as usize) / 64;
        let bit = depth % 64;
        if word < BITMAP_U64S {
            self.overflow_bitmap[word] |= 1u64 << bit;
        }
    }

    /// Tests whether the overflow bit at `depth` is set.
    #[inline(always)]
    fn test_overflow(&self, depth: u32) -> bool {
        let word = (depth as usize) / 64;
        let bit = depth % 64;
        word < BITMAP_U64S && (self.overflow_bitmap[word] & (1u64 << bit)) != 0
    }

    /// Clears the overflow bit at `depth`.
    #[inline(always)]
    fn clear_overflow(&mut self, depth: u32) {
        let word = (depth as usize) / 64;
        let bit = depth % 64;
        if word < BITMAP_U64S {
            self.overflow_bitmap[word] &= !(1u64 << bit);
        }
    }

    /// Returns `true` if **any** overflow bit is set at depths `0 ..= depth`.
    ///
    /// This is the core "execution context tainted by overflow" predicate:
    /// an overflow in any ancestor frame (or the current frame) means the
    /// current execution may be operating on a wrapped value.
    ///
    /// Runs in `O(BITMAP_U64S)` = `O(16)` — constant-bounded. In practice
    /// most transactions have depth < 64, reducing this to a single-word
    /// mask-and-compare.
    #[inline]
    fn has_overflow_at_or_below(&self, depth: u32) -> bool {
        let full_words = (depth as usize) / 64;
        let bit_in_last = depth % 64;

        // Check complete u64 words *below* the word that contains `depth`.
        // Loop bound is compile-time-known maximum (16), satisfying O(1).
        let check_words = if full_words < BITMAP_U64S {
            full_words
        } else {
            BITMAP_U64S
        };
        let mut i = 0;
        while i < check_words {
            if self.overflow_bitmap[i] != 0 {
                return true;
            }
            i += 1;
        }

        // Check bits 0 ..= bit_in_last within the word containing `depth`.
        if full_words < BITMAP_U64S {
            let mask = if bit_in_last == 63 {
                u64::MAX
            } else {
                (1u64 << (bit_in_last + 1)) - 1
            };
            if self.overflow_bitmap[full_words] & mask != 0 {
                return true;
            }
        }

        false
    }

    // ── Frame Lifecycle Helpers ──────────────────────────────────────

    /// Called when entering a new `CALL` / `CREATE` frame.
    #[inline(always)]
    fn enter_frame(&mut self) {
        self.current_depth = self.current_depth.saturating_add(1);
    }

    /// Called when leaving a `CALL` / `CREATE` frame.
    ///
    /// - On **success**: propagates the child's overflow bit to the parent
    ///   (conservative — the parent may use the overflowed return value).
    /// - On **revert/error**: clears the child's overflow bit (the overflow
    ///   never took effect from the parent's perspective).
    #[inline(always)]
    fn exit_frame(&mut self, success: bool) {
        let child_depth = self.current_depth;

        if self.test_overflow(child_depth) {
            if success && child_depth > 0 {
                // Propagate upward: parent inherits the taint.
                self.set_overflow(child_depth - 1);
            }
            // Clean up: the child frame is gone.
            self.clear_overflow(child_depth);
        }

        self.current_depth = self.current_depth.saturating_sub(1);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Inspector Implementation (revm v36, generic over any Context)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl<CTX> Inspector<CTX> for LightweightFlagFilter {
    // ── Per-Opcode Hook ──────────────────────────────────────────────

    #[inline]
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut CTX) {
        // Fast path: once flagged, skip all further work. The pipeline
        // only needs a boolean; the reason is determined by Phase 2.
        if self.flagged {
            return;
        }

        let op = interp.bytecode.opcode();

        // ┌─────────────────────────────────────────────────────────────┐
        // │  Heuristic 1 — Reentrancy Proxy                           │
        // │                                                             │
        // │  SSTORE inside a nested external call is the canonical     │
        // │  signal of a re-entrant state mutation.                    │
        // │                                                             │
        // │  Depth 1 = initial tx call ⇒ normal.                      │
        // │  Depth ≥ 2 = inside a sub-call ⇒ flag.                    │
        // └─────────────────────────────────────────────────────────────┘
        if op == OP_SSTORE && self.current_depth >= 2 {
            self.flagged = true;
            return;
        }

        // ┌─────────────────────────────────────────────────────────────┐
        // │  Heuristic 2 — Overflow Proxy                              │
        // └─────────────────────────────────────────────────────────────┘

        // 2a. Detect arithmetic wrap-around.
        //     Peek operands from the stack *before* the opcode executes
        //     and check whether the operation will overflow U256.
        //     Cost: two stack peeks + one widening check = O(1).
        if op == OP_ADD || op == OP_SUB || op == OP_MUL {
            if let (Ok(a), Ok(b)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let overflows = match op {
                    OP_ADD => {
                        let (_, ov) = a.overflowing_add(b);
                        ov
                    }
                    OP_SUB => {
                        let (_, ov) = a.overflowing_sub(b);
                        ov
                    }
                    OP_MUL => {
                        let (_, ov) = a.overflowing_mul(b);
                        ov
                    }
                    // SAFETY: outer `if` guarantees op ∈ {ADD, SUB, MUL}.
                    _ => unsafe { core::hint::unreachable_unchecked() },
                };
                if overflows {
                    self.set_overflow(self.current_depth);
                }
            }
            // Arithmetic opcodes are never sinks — skip sink checks.
            return;
        }

        // 2b. Detect critical sinks following an overflow in the current
        //     valid execution context (same frame or any ancestor).

        // Sink: SSTORE — overflowed value being persisted to storage.
        if op == OP_SSTORE {
            if self.has_overflow_at_or_below(self.current_depth) {
                self.flagged = true;
            }
            return;
        }

        // Sink: value-carrying CALL / CALLCODE — overflowed value used
        // to transfer ETH.
        // Stack layout for CALL/CALLCODE:
        //   peek(0)=gas  peek(1)=to  peek(2)=value  peek(3..6)=offsets
        if op == OP_CALL || op == OP_CALLCODE {
            if self.has_overflow_at_or_below(self.current_depth) {
                if let Ok(value) = interp.stack.peek(2) {
                    if !value.is_zero() {
                        self.flagged = true;
                    }
                }
            }
        }
    }

    // ── Call Frame Hooks ─────────────────────────────────────────────

    #[inline]
    fn call(&mut self, _ctx: &mut CTX, _inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.enter_frame();
        None // Never short-circuit execution.
    }

    #[inline]
    fn call_end(&mut self, _ctx: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.exit_frame(outcome.result.is_ok());
    }

    // ── Create Frame Hooks ───────────────────────────────────────────

    #[inline]
    fn create(&mut self, _ctx: &mut CTX, _inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.enter_frame();
        None
    }

    #[inline]
    fn create_end(
        &mut self,
        _ctx: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        self.exit_frame(outcome.result.is_ok());
    }
}

impl Default for LightweightFlagFilter {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Unit Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    // ── Bitmap Operations ────────────────────────────────────────────

    #[test]
    fn bitmap_set_test_clear() {
        let mut f = LightweightFlagFilter::new();

        // Bit 0
        assert!(!f.test_overflow(0));
        f.set_overflow(0);
        assert!(f.test_overflow(0));
        f.clear_overflow(0);
        assert!(!f.test_overflow(0));

        // Bit 63 (last bit of first word)
        f.set_overflow(63);
        assert!(f.test_overflow(63));
        assert!(!f.test_overflow(62));
        f.clear_overflow(63);
        assert!(!f.test_overflow(63));

        // Bit 64 (first bit of second word)
        f.set_overflow(64);
        assert!(f.test_overflow(64));
        assert!(!f.test_overflow(63));
        assert!(!f.test_overflow(65));

        // Bit 1023 (maximum tracked depth)
        f.clear_overflow(64);
        f.set_overflow(1023);
        assert!(f.test_overflow(1023));
        assert!(!f.test_overflow(1022));
    }

    #[test]
    fn bitmap_has_overflow_at_or_below() {
        let mut f = LightweightFlagFilter::new();

        // Empty bitmap: no overflow anywhere
        assert!(!f.has_overflow_at_or_below(0));
        assert!(!f.has_overflow_at_or_below(100));
        assert!(!f.has_overflow_at_or_below(1023));

        // Set overflow at depth 5
        f.set_overflow(5);
        assert!(!f.has_overflow_at_or_below(4)); // below → no
        assert!(f.has_overflow_at_or_below(5)); //  exact → yes
        assert!(f.has_overflow_at_or_below(6)); //  above → yes
        assert!(f.has_overflow_at_or_below(100)); // far above → yes

        // Set overflow at depth 200 (crosses word boundary)
        f.clear_overflow(5);
        f.set_overflow(200);
        assert!(!f.has_overflow_at_or_below(199));
        assert!(f.has_overflow_at_or_below(200));
        assert!(f.has_overflow_at_or_below(500));
    }

    // ── Frame Lifecycle ──────────────────────────────────────────────

    #[test]
    fn frame_enter_exit_depth_tracking() {
        let mut f = LightweightFlagFilter::new();
        assert_eq!(f.current_depth, 0);

        f.enter_frame();
        assert_eq!(f.current_depth, 1);

        f.enter_frame();
        assert_eq!(f.current_depth, 2);

        f.exit_frame(true); // success
        assert_eq!(f.current_depth, 1);

        f.exit_frame(true);
        assert_eq!(f.current_depth, 0);
    }

    #[test]
    fn overflow_propagates_on_success() {
        let mut f = LightweightFlagFilter::new();

        f.enter_frame(); // depth 1
        f.enter_frame(); // depth 2

        // Overflow detected at depth 2
        f.set_overflow(2);
        assert!(f.test_overflow(2));

        // Sub-call succeeds → overflow propagates to depth 1
        f.exit_frame(true);
        assert!(!f.test_overflow(2)); // child bit cleared
        assert!(f.test_overflow(1)); //  parent bit set
    }

    #[test]
    fn overflow_cleared_on_revert() {
        let mut f = LightweightFlagFilter::new();

        f.enter_frame(); // depth 1
        f.enter_frame(); // depth 2

        f.set_overflow(2);
        assert!(f.test_overflow(2));

        // Sub-call reverts → overflow at depth 2 is erased
        f.exit_frame(false);
        assert!(!f.test_overflow(2)); // child bit cleared
        assert!(!f.test_overflow(1)); // parent NOT tainted
    }

    #[test]
    fn reset_clears_everything() {
        let mut f = LightweightFlagFilter::new();
        f.flagged = true;
        f.current_depth = 5;
        f.set_overflow(3);

        f.reset();
        assert!(!f.flagged);
        assert_eq!(f.current_depth, 0);
        assert!(!f.test_overflow(3));
    }

    // ── API ──────────────────────────────────────────────────────────

    #[test]
    fn requires_deep_inspection_default_false() {
        let f = LightweightFlagFilter::new();
        assert!(!f.requires_deep_inspection());
    }

    #[test]
    fn default_impl_matches_new() {
        let a = LightweightFlagFilter::new();
        let b = LightweightFlagFilter::default();
        assert_eq!(a.flagged, b.flagged);
        assert_eq!(a.current_depth, b.current_depth);
        assert_eq!(a.overflow_bitmap, b.overflow_bitmap);
    }

    #[test]
    fn saturating_depth_bounds() {
        let mut f = LightweightFlagFilter::new();

        // Underflow protection
        f.exit_frame(true);
        assert_eq!(f.current_depth, 0); // saturating_sub prevents underflow

        // Overflow at max depth is handled gracefully
        f.current_depth = u32::MAX;
        f.enter_frame();
        assert_eq!(f.current_depth, u32::MAX); // saturating_add prevents overflow
    }
}
