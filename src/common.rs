#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use p8n_rreil_macro::rreil;
use p8n_types::{Guard, Result, Statement, Value, Variable};

/// Describes how control flow continues after an opcode. We only care about single functions, so a
/// return instructions stops execution.
#[derive(Clone, Debug)]
pub enum JumpSpec {
    /// Execution stops after this opcode. Examples `hlt`, `ret` and `reti`.
    DeadEnd,
    /// Execute the opcode that follows after the current one.
    FallThru,
    /// Execution forks and continues at the address defined by the `Value` instance iff the Guard
    /// instance is true, otherwise execution falls thru and continues with the opcode following
    /// the current one.
    Branch(Value, Guard),
    /// Execution continues at the address defined by the `Value` instance.
    Jump(Value),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OpcodeType {
    OneByte,
    TwoByte,
    ThreeByte_38,
    ThreeByte_3A,
    XOP8_Map,
    XOP9_Map,
    XOPA_Map,
    ThreeDNow_Map,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum InstructionContext {
    IC,       // says nothing about the instruction
    IC_64BIT, // says the instruction applies in
    // 64-bit mode but no more
    IC_OPSIZE, // requires an OPSIZE prefix, so
    // operands change width
    IC_ADSIZE, // requires an ADSIZE prefix, so
    // operands change width
    IC_OPSIZE_ADSIZE, // requires ADSIZE and OPSIZE prefixes
    IC_XD,            // may say something about the opcode
    // but not the operands
    IC_XS, // may say something about the opcode
    // but not the operands
    IC_XD_OPSIZE, // requires an OPSIZE prefix, so
    // operands change width
    IC_XS_OPSIZE, // requires an OPSIZE prefix, so
    // operands change width
    IC_XD_ADSIZE, // requires an ADSIZE prefix, so
    // operands change width
    IC_XS_ADSIZE, // requires an ADSIZE prefix, so
    // operands change width
    IC_64BIT_REXW, // requires a REX.W prefix, so operands
    // change width; overrides IC_OPSIZE
    IC_64BIT_REXW_ADSIZE, // requires a REX.W prefix and 0x67
    // prefix
    IC_64BIT_OPSIZE,        // Just as meaningful as IC_OPSIZE
    IC_64BIT_ADSIZE,        // Just as meaningful as IC_ADSIZE
    IC_64BIT_OPSIZE_ADSIZE, // Just as meaningful as IC_OPSIZE/
    // IC_ADSIZE
    IC_64BIT_XD, // XD instructions are SSE; REX.W is
    // secondary
    IC_64BIT_XS,        // Just as meaningful as IC_64BIT_XD
    IC_64BIT_XD_OPSIZE, // Just as meaningful as IC_XD_OPSIZE
    IC_64BIT_XS_OPSIZE, // Just as meaningful as IC_XS_OPSIZE
    IC_64BIT_XD_ADSIZE, // Just as meaningful as IC_XD_ADSIZE
    IC_64BIT_XS_ADSIZE, // Just as meaningful as IC_XS_ADSIZE
    IC_64BIT_REXW_XS,   // OPSIZE could mean a different
    // opcode
    IC_64BIT_REXW_XD, // Just as meaningful as
    // IC_64BIT_REXW_XS
    IC_64BIT_REXW_OPSIZE, // The Dynamic Duo!  Prefer over all
    // else because this changes most
    // operands' meaning
    IC_VEX,                   // requires a VEX prefix
    IC_VEX_XS,                // requires VEX and the XS prefix
    IC_VEX_XD,                // requires VEX and the XD prefix
    IC_VEX_OPSIZE,            // requires VEX and the OpSize prefix
    IC_VEX_W,                 // requires VEX and the W prefix
    IC_VEX_W_XS,              // requires VEX, W, and XS prefix
    IC_VEX_W_XD,              // requires VEX, W, and XD prefix
    IC_VEX_W_OPSIZE,          // requires VEX, W, and OpSize
    IC_VEX_L,                 // requires VEX and the L prefix
    IC_VEX_L_XS,              // requires VEX and the L and XS prefix
    IC_VEX_L_XD,              // requires VEX and the L and XD prefix
    IC_VEX_L_OPSIZE,          // requires VEX, L, and OpSize
    IC_VEX_L_W,               // requires VEX, L and W
    IC_VEX_L_W_XS,            // requires VEX, L, W and XS prefix
    IC_VEX_L_W_XD,            // requires VEX, L, W and XD prefix
    IC_VEX_L_W_OPSIZE,        // requires VEX, L, W and OpSize
    IC_EVEX,                  // requires an EVEX prefix
    IC_EVEX_XS,               // requires EVEX and the XS prefix
    IC_EVEX_XD,               // requires EVEX and the XD prefix
    IC_EVEX_OPSIZE,           // requires EVEX and the OpSize prefix
    IC_EVEX_W,                // requires EVEX and the W prefix
    IC_EVEX_W_XS,             // requires EVEX, W, and XS prefix
    IC_EVEX_W_XD,             // requires EVEX, W, and XD prefix
    IC_EVEX_W_OPSIZE,         // requires EVEX, W, and OpSize
    IC_EVEX_L,                // requires EVEX and the L prefix
    IC_EVEX_L_XS,             // requires EVEX and the L and XS prefix
    IC_EVEX_L_XD,             // requires EVEX and the L and XD prefix
    IC_EVEX_L_OPSIZE,         // requires EVEX, L, and OpSize
    IC_EVEX_L_W,              // requires EVEX, L and W
    IC_EVEX_L_W_XS,           // requires EVEX, L, W and XS prefix
    IC_EVEX_L_W_XD,           // requires EVEX, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE,       // requires EVEX, L, W and OpSize
    IC_EVEX_L2,               // requires EVEX and the L2 prefix
    IC_EVEX_L2_XS,            // requires EVEX and the L2 and XS prefix
    IC_EVEX_L2_XD,            // requires EVEX and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE,        // requires EVEX, L2, and OpSize
    IC_EVEX_L2_W,             // requires EVEX, L2 and W
    IC_EVEX_L2_W_XS,          // requires EVEX, L2, W and XS prefix
    IC_EVEX_L2_W_XD,          // requires EVEX, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE,      // requires EVEX, L2, W and OpSize
    IC_EVEX_K,                // requires an EVEX_K prefix
    IC_EVEX_XS_K,             // requires EVEX_K and the XS prefix
    IC_EVEX_XD_K,             // requires EVEX_K and the XD prefix
    IC_EVEX_OPSIZE_K,         // requires EVEX_K and the OpSize prefix
    IC_EVEX_W_K,              // requires EVEX_K and the W prefix
    IC_EVEX_W_XS_K,           // requires EVEX_K, W, and XS prefix
    IC_EVEX_W_XD_K,           // requires EVEX_K, W, and XD prefix
    IC_EVEX_W_OPSIZE_K,       // requires EVEX_K, W, and OpSize
    IC_EVEX_L_K,              // requires EVEX_K and the L prefix
    IC_EVEX_L_XS_K,           // requires EVEX_K and the L and XS prefix
    IC_EVEX_L_XD_K,           // requires EVEX_K and the L and XD prefix
    IC_EVEX_L_OPSIZE_K,       // requires EVEX_K, L, and OpSize
    IC_EVEX_L_W_K,            // requires EVEX_K, L and W
    IC_EVEX_L_W_XS_K,         // requires EVEX_K, L, W and XS prefix
    IC_EVEX_L_W_XD_K,         // requires EVEX_K, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE_K,     // requires EVEX_K, L, W and OpSize
    IC_EVEX_L2_K,             // requires EVEX_K and the L2 prefix
    IC_EVEX_L2_XS_K,          // requires EVEX_K and the L2 and XS prefix
    IC_EVEX_L2_XD_K,          // requires EVEX_K and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE_K,      // requires EVEX_K, L2, and OpSize
    IC_EVEX_L2_W_K,           // requires EVEX_K, L2 and W
    IC_EVEX_L2_W_XS_K,        // requires EVEX_K, L2, W and XS prefix
    IC_EVEX_L2_W_XD_K,        // requires EVEX_K, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE_K,    // requires EVEX_K, L2, W and OpSize
    IC_EVEX_B,                // requires an EVEX_B prefix
    IC_EVEX_XS_B,             // requires EVEX_B and the XS prefix
    IC_EVEX_XD_B,             // requires EVEX_B and the XD prefix
    IC_EVEX_OPSIZE_B,         // requires EVEX_B and the OpSize prefix
    IC_EVEX_W_B,              // requires EVEX_B and the W prefix
    IC_EVEX_W_XS_B,           // requires EVEX_B, W, and XS prefix
    IC_EVEX_W_XD_B,           // requires EVEX_B, W, and XD prefix
    IC_EVEX_W_OPSIZE_B,       // requires EVEX_B, W, and OpSize
    IC_EVEX_L_B,              // requires EVEX_B and the L prefix
    IC_EVEX_L_XS_B,           // requires EVEX_B and the L and XS prefix
    IC_EVEX_L_XD_B,           // requires EVEX_B and the L and XD prefix
    IC_EVEX_L_OPSIZE_B,       // requires EVEX_B, L, and OpSize
    IC_EVEX_L_W_B,            // requires EVEX_B, L and W
    IC_EVEX_L_W_XS_B,         // requires EVEX_B, L, W and XS prefix
    IC_EVEX_L_W_XD_B,         // requires EVEX_B, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE_B,     // requires EVEX_B, L, W and OpSize
    IC_EVEX_L2_B,             // requires EVEX_B and the L2 prefix
    IC_EVEX_L2_XS_B,          // requires EVEX_B and the L2 and XS prefix
    IC_EVEX_L2_XD_B,          // requires EVEX_B and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE_B,      // requires EVEX_B, L2, and OpSize
    IC_EVEX_L2_W_B,           // requires EVEX_B, L2 and W
    IC_EVEX_L2_W_XS_B,        // requires EVEX_B, L2, W and XS prefix
    IC_EVEX_L2_W_XD_B,        // requires EVEX_B, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE_B,    // requires EVEX_B, L2, W and OpSize
    IC_EVEX_K_B,              // requires EVEX_B and EVEX_K prefix
    IC_EVEX_XS_K_B,           // requires EVEX_B, EVEX_K and the XS prefix
    IC_EVEX_XD_K_B,           // requires EVEX_B, EVEX_K and the XD prefix
    IC_EVEX_OPSIZE_K_B,       // requires EVEX_B, EVEX_K and the OpSize prefix
    IC_EVEX_W_K_B,            // requires EVEX_B, EVEX_K and the W prefix
    IC_EVEX_W_XS_K_B,         // requires EVEX_B, EVEX_K, W, and XS prefix
    IC_EVEX_W_XD_K_B,         // requires EVEX_B, EVEX_K, W, and XD prefix
    IC_EVEX_W_OPSIZE_K_B,     // requires EVEX_B, EVEX_K, W, and OpSize
    IC_EVEX_L_K_B,            // requires EVEX_B, EVEX_K and the L prefix
    IC_EVEX_L_XS_K_B,         // requires EVEX_B, EVEX_K and the L and XS prefix
    IC_EVEX_L_XD_K_B,         // requires EVEX_B, EVEX_K and the L and XD prefix
    IC_EVEX_L_OPSIZE_K_B,     // requires EVEX_B, EVEX_K, L, and OpSize
    IC_EVEX_L_W_K_B,          // requires EVEX_B, EVEX_K, L and W
    IC_EVEX_L_W_XS_K_B,       // requires EVEX_B, EVEX_K, L, W and XS prefix
    IC_EVEX_L_W_XD_K_B,       // requires EVEX_B, EVEX_K, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE_K_B,   // requires EVEX_B, EVEX_K, L, W and OpSize
    IC_EVEX_L2_K_B,           // requires EVEX_B, EVEX_K and the L2 prefix
    IC_EVEX_L2_XS_K_B,        // requires EVEX_B, EVEX_K and the L2 and XS prefix
    IC_EVEX_L2_XD_K_B,        // requires EVEX_B, EVEX_K and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE_K_B,    // requires EVEX_B, EVEX_K, L2, and OpSize
    IC_EVEX_L2_W_K_B,         // requires EVEX_B, EVEX_K, L2 and W
    IC_EVEX_L2_W_XS_K_B,      // requires EVEX_B, EVEX_K, L2, W and XS prefix
    IC_EVEX_L2_W_XD_K_B,      // requires EVEX_B, EVEX_K, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE_K_B,  // requires EVEX_B, EVEX_K, L2, W and OpSize
    IC_EVEX_KZ_B,             // requires EVEX_B and EVEX_KZ prefix
    IC_EVEX_XS_KZ_B,          // requires EVEX_B, EVEX_KZ and the XS prefix
    IC_EVEX_XD_KZ_B,          // requires EVEX_B, EVEX_KZ and the XD prefix
    IC_EVEX_OPSIZE_KZ_B,      // requires EVEX_B, EVEX_KZ and the OpSize prefix
    IC_EVEX_W_KZ_B,           // requires EVEX_B, EVEX_KZ and the W prefix
    IC_EVEX_W_XS_KZ_B,        // requires EVEX_B, EVEX_KZ, W, and XS prefix
    IC_EVEX_W_XD_KZ_B,        // requires EVEX_B, EVEX_KZ, W, and XD prefix
    IC_EVEX_W_OPSIZE_KZ_B,    // requires EVEX_B, EVEX_KZ, W, and OpSize
    IC_EVEX_L_KZ_B,           // requires EVEX_B, EVEX_KZ and the L prefix
    IC_EVEX_L_XS_KZ_B,        // requires EVEX_B, EVEX_KZ and the L and XS prefix
    IC_EVEX_L_XD_KZ_B,        // requires EVEX_B, EVEX_KZ and the L and XD prefix
    IC_EVEX_L_OPSIZE_KZ_B,    // requires EVEX_B, EVEX_KZ, L, and OpSize
    IC_EVEX_L_W_KZ_B,         // requires EVEX_B, EVEX_KZ, L and W
    IC_EVEX_L_W_XS_KZ_B,      // requires EVEX_B, EVEX_KZ, L, W and XS prefix
    IC_EVEX_L_W_XD_KZ_B,      // requires EVEX_B, EVEX_KZ, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE_KZ_B,  // requires EVEX_B, EVEX_KZ, L, W and OpSize
    IC_EVEX_L2_KZ_B,          // requires EVEX_B, EVEX_KZ and the L2 prefix
    IC_EVEX_L2_XS_KZ_B,       // requires EVEX_B, EVEX_KZ and the L2 and XS prefix
    IC_EVEX_L2_XD_KZ_B,       // requires EVEX_B, EVEX_KZ and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE_KZ_B,   // requires EVEX_B, EVEX_KZ, L2, and OpSize
    IC_EVEX_L2_W_KZ_B,        // requires EVEX_B, EVEX_KZ, L2 and W
    IC_EVEX_L2_W_XS_KZ_B,     // requires EVEX_B, EVEX_KZ, L2, W and XS prefix
    IC_EVEX_L2_W_XD_KZ_B,     // requires EVEX_B, EVEX_KZ, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE_KZ_B, // requires EVEX_B, EVEX_KZ, L2, W and OpSize
    IC_EVEX_KZ,               // requires an EVEX_KZ prefix
    IC_EVEX_XS_KZ,            // requires EVEX_KZ and the XS prefix
    IC_EVEX_XD_KZ,            // requires EVEX_KZ and the XD prefix
    IC_EVEX_OPSIZE_KZ,        // requires EVEX_KZ and the OpSize prefix
    IC_EVEX_W_KZ,             // requires EVEX_KZ and the W prefix
    IC_EVEX_W_XS_KZ,          // requires EVEX_KZ, W, and XS prefix
    IC_EVEX_W_XD_KZ,          // requires EVEX_KZ, W, and XD prefix
    IC_EVEX_W_OPSIZE_KZ,      // requires EVEX_KZ, W, and OpSize
    IC_EVEX_L_KZ,             // requires EVEX_KZ and the L prefix
    IC_EVEX_L_XS_KZ,          // requires EVEX_KZ and the L and XS prefix
    IC_EVEX_L_XD_KZ,          // requires EVEX_KZ and the L and XD prefix
    IC_EVEX_L_OPSIZE_KZ,      // requires EVEX_KZ, L, and OpSize
    IC_EVEX_L_W_KZ,           // requires EVEX_KZ, L and W
    IC_EVEX_L_W_XS_KZ,        // requires EVEX_KZ, L, W and XS prefix
    IC_EVEX_L_W_XD_KZ,        // requires EVEX_KZ, L, W and XD prefix
    IC_EVEX_L_W_OPSIZE_KZ,    // requires EVEX_KZ, L, W and OpSize
    IC_EVEX_L2_KZ,            // requires EVEX_KZ and the L2 prefix
    IC_EVEX_L2_XS_KZ,         // requires EVEX_KZ and the L2 and XS prefix
    IC_EVEX_L2_XD_KZ,         // requires EVEX_KZ and the L2 and XD prefix
    IC_EVEX_L2_OPSIZE_KZ,     // requires EVEX_KZ, L2, and OpSize
    IC_EVEX_L2_W_KZ,          // requires EVEX_KZ, L2 and W
    IC_EVEX_L2_W_XS_KZ,       // requires EVEX_KZ, L2, W and XS prefix
    IC_EVEX_L2_W_XD_KZ,       // requires EVEX_KZ, L2, W and XD prefix
    IC_EVEX_L2_W_OPSIZE_KZ,   // requires EVEX_KZ, L2, W and OpSize
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OperandEncoding {
    NONE,      // Operand not present
    REG,       // Register operand in ModR/M byte.
    RM,        // R/M operand in ModR/M byte.
    RM_CD2,    // R/M operand with CDisp scaling of 2
    RM_CD4,    // R/M operand with CDisp scaling of 4
    RM_CD8,    // R/M operand with CDisp scaling of 8
    RM_CD16,   // R/M operand with CDisp scaling of 16
    RM_CD32,   // R/M operand with CDisp scaling of 32
    RM_CD64,   // R/M operand with CDisp scaling of 64
    VSIB,      // VSIB operand in ModR/M byte.
    VSIB_CD2,  // VSIB operand with CDisp scaling of 2
    VSIB_CD4,  // VSIB operand with CDisp scaling of 4
    VSIB_CD8,  // VSIB operand with CDisp scaling of 8
    VSIB_CD16, // VSIB operand with CDisp scaling of 16
    VSIB_CD32, // VSIB operand with CDisp scaling of 32
    VSIB_CD64, // VSIB operand with CDisp scaling of 64
    VVVV,      // Register operand in VEX.vvvv byte.
    WRITEMASK, // Register operand in EVEX.aaa byte.
    IB,        // 1-byte immediate
    IW,        // 2-byte
    ID,        // 4-byte
    IO,        // 8-byte
    RB,        // (AL..DIL, R8L..R15L) Register code added to the opcode byte
    RW,        // (AX..DI, R8W..R15W)
    RD,        // (EAX..EDI, R8D..R15D)
    RO,        // (RAX..RDI, R8..R15)
    FP,        // Position on floating-point stack in ModR/M byte.
    Iv,        // Immediate of operand size
    Ia,        // Immediate of address size
    IRC,       // Immediate for static rounding control
    Rv,        // Register code of operand size added to the opcode byte
    DUP,       // Duplicate of another operand; ID is encoded in type
    SI,        // Source index; encoded in OpSize/Adsize prefix
    DI,        // Destination index; encoded in prefixes
}

#[derive(FromPrimitive, Clone, Copy, Debug, PartialEq)]
pub enum OperandType {
    NONE = 0,       // No operand present
    REL,        // immediate address
    R8,         // 1-byte register operand
    R16,        // 2-byte
    R32,        // 4-byte
    R64,        // 8-byte
    IMM,        // immediate operand
    IMM3,       // 1-byte immediate operand between 0 and 7
    IMM5,       // 1-byte immediate operand between 0 and 31
    AVX512ICC,  // 1-byte immediate operand for AVX512 icmp
    UIMM8,      // 1-byte unsigned immediate operand
    M,          // Memory operand
    MVSIBX,     // Memory operand using XMM index
    MVSIBY,     // Memory operand using YMM index
    MVSIBZ,     // Memory operand using ZMM index
    SRCIDX,     // memory at source index
    DSTIDX,     // memory at destination index
    MOFFS,      // memory offset (relative to segment base)
    ST,         // Position on the floating-point stack
    MM64,       // 8-byte MMX register
    XMM,        // 16-byte
    YMM,        // 32-byte
    ZMM,        // 64-byte
    VK,         // mask register
    SEGMENTREG, // Segment register operand
    DEBUGREG,   // Debug register operand
    CONTROLREG, // Control register operand
    BNDR,       // MPX bounds register
    Rv,         // Register operand of operand size
    RELv,       // Immediate address of operand size
    DUP0,       // Duplicate of operand 0
    DUP1,       // operand 1
    DUP2,       // operand 2
    DUP3,       // operand 3
    DUP4,       // operand 4
}

#[derive(Clone, Debug)]
pub struct OperandSpecifier {
    pub encoding: OperandEncoding,
    pub typ: OperandType,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Mode {
    Real,
    Protected,
    Long,
}

#[derive(PartialOrd, PartialEq, FromPrimitive, Clone, Copy, Debug)]
/// All possible values of the base field for effective-address
/// computations, a.k.a. the Mod and R/M fields of the ModR/M byte.
/// We distinguish between bases (EA_BASE_*) and registers that just happen
/// to be referred to when Mod == 0b11 (EA_REG_*).
pub enum EABase {
    BaseNone = 0,

    BaseBX_SI,
    BaseBX_DI,
    BaseBP_SI,
    BaseBP_DI,
    BaseSI,
    BaseDI,
    BaseBP,
    BaseBX,
    BaseR8W,
    BaseR9W,
    BaseR10W,
    BaseR11W,
    BaseR12W,
    BaseR13W,
    BaseR14W,
    BaseR15W,

    BaseEAX,
    BaseECX,
    BaseEDX,
    BaseEBX,
    Basesib,
    BaseEBP,
    BaseESI,
    BaseEDI,
    BaseR8D,
    BaseR9D,
    BaseR10D,
    BaseR11D,
    BaseR12D,
    BaseR13D,
    BaseR14D,
    BaseR15D,

    BaseRAX,
    BaseRCX,
    BaseRDX,
    BaseRBX,
    Basesib64,
    BaseRBP,
    BaseRSI,
    BaseRDI,
    BaseR8,
    BaseR9,
    BaseR10,
    BaseR11,
    BaseR12,
    BaseR13,
    BaseR14,
    BaseR15,

    RegAL,
    RegCL,
    RegDL,
    RegBL,
    RegAH,
    RegCH,
    RegDH,
    RegBH,
    RegR8B,
    RegR9B,
    RegR10B,
    RegR11B,
    RegR12B,
    RegR13B,
    RegR14B,
    RegR15B,
    RegSPL,
    RegBPL,
    RegSIL,
    RegDIL,

    RegAX,
    RegCX,
    RegDX,
    RegBX,
    RegSP,
    RegBP,
    RegSI,
    RegDI,
    RegR8W,
    RegR9W,
    RegR10W,
    RegR11W,
    RegR12W,
    RegR13W,
    RegR14W,
    RegR15W,

    RegEAX,
    RegECX,
    RegEDX,
    RegEBX,
    RegESP,
    RegEBP,
    RegESI,
    RegEDI,
    RegR8D,
    RegR9D,
    RegR10D,
    RegR11D,
    RegR12D,
    RegR13D,
    RegR14D,
    RegR15D,

    RegRAX,
    RegRCX,
    RegRDX,
    RegRBX,
    RegRSP,
    RegRBP,
    RegRSI,
    RegRDI,
    RegR8,
    RegR9,
    RegR10,
    RegR11,
    RegR12,
    RegR13,
    RegR14,
    RegR15,

    RegMM0,
    RegMM1,
    RegMM2,
    RegMM3,
    RegMM4,
    RegMM5,
    RegMM6,
    RegMM7,

    RegXMM0,
    RegXMM1,
    RegXMM2,
    RegXMM3,
    RegXMM4,
    RegXMM5,
    RegXMM6,
    RegXMM7,
    RegXMM8,
    RegXMM9,
    RegXMM10,
    RegXMM11,
    RegXMM12,
    RegXMM13,
    RegXMM14,
    RegXMM15,
    RegXMM16,
    RegXMM17,
    RegXMM18,
    RegXMM19,
    RegXMM20,
    RegXMM21,
    RegXMM22,
    RegXMM23,
    RegXMM24,
    RegXMM25,
    RegXMM26,
    RegXMM27,
    RegXMM28,
    RegXMM29,
    RegXMM30,
    RegXMM31,

    RegYMM0,
    RegYMM1,
    RegYMM2,
    RegYMM3,
    RegYMM4,
    RegYMM5,
    RegYMM6,
    RegYMM7,
    RegYMM8,
    RegYMM9,
    RegYMM10,
    RegYMM11,
    RegYMM12,
    RegYMM13,
    RegYMM14,
    RegYMM15,
    RegYMM16,
    RegYMM17,
    RegYMM18,
    RegYMM19,
    RegYMM20,
    RegYMM21,
    RegYMM22,
    RegYMM23,
    RegYMM24,
    RegYMM25,
    RegYMM26,
    RegYMM27,
    RegYMM28,
    RegYMM29,
    RegYMM30,
    RegYMM31,

    RegZMM0,
    RegZMM1,
    RegZMM2,
    RegZMM3,
    RegZMM4,
    RegZMM5,
    RegZMM6,
    RegZMM7,
    RegZMM8,
    RegZMM9,
    RegZMM10,
    RegZMM11,
    RegZMM12,
    RegZMM13,
    RegZMM14,
    RegZMM15,
    RegZMM16,
    RegZMM17,
    RegZMM18,
    RegZMM19,
    RegZMM20,
    RegZMM21,
    RegZMM22,
    RegZMM23,
    RegZMM24,
    RegZMM25,
    RegZMM26,
    RegZMM27,
    RegZMM28,
    RegZMM29,
    RegZMM30,
    RegZMM31,

    RegK0,
    RegK1,
    RegK2,
    RegK3,
    RegK4,
    RegK5,
    RegK6,
    RegK7,

    RegES,
    RegCS,
    RegSS,
    RegDS,
    RegFS,
    RegGS,

    RegDR0,
    RegDR1,
    RegDR2,
    RegDR3,
    RegDR4,
    RegDR5,
    RegDR6,
    RegDR7,
    RegDR8,
    RegDR9,
    RegDR10,
    RegDR11,
    RegDR12,
    RegDR13,
    RegDR14,
    RegDR15,

    RegCR0,
    RegCR1,
    RegCR2,
    RegCR3,
    RegCR4,
    RegCR5,
    RegCR6,
    RegCR7,
    RegCR8,
    RegCR9,
    RegCR10,
    RegCR11,
    RegCR12,
    RegCR13,
    RegCR14,
    RegCR15,

    RegBND0,
    RegBND1,
    RegBND2,
    RegBND3,

    RegRIP,
}

impl EABase {
    pub fn as_var(&self) -> Option<Variable> {
        match self {
            EABase::RegAL => Variable::new2("AL", None, 8).ok(),
            EABase::RegCL => Variable::new2("CL", None, 8).ok(),
            EABase::RegDL => Variable::new2("DL", None, 8).ok(),
            EABase::RegBL => Variable::new2("BL", None, 8).ok(),
            EABase::RegAH => Variable::new2("AH", None, 8).ok(),
            EABase::RegCH => Variable::new2("CH", None, 8).ok(),
            EABase::RegDH => Variable::new2("DH", None, 8).ok(),
            EABase::RegBH => Variable::new2("BH", None, 8).ok(),
            EABase::RegR8B => Variable::new2("R8B", None, 8).ok(),
            EABase::RegR9B => Variable::new2("R9B", None, 8).ok(),
            EABase::RegR10B => Variable::new2("R10B", None, 8).ok(),
            EABase::RegR11B => Variable::new2("R11B", None, 8).ok(),
            EABase::RegR12B => Variable::new2("R12B", None, 8).ok(),
            EABase::RegR13B => Variable::new2("R13B", None, 8).ok(),
            EABase::RegR14B => Variable::new2("R14B", None, 8).ok(),
            EABase::RegR15B => Variable::new2("R15B", None, 8).ok(),
            EABase::RegSPL => Variable::new2("SPL", None, 8).ok(),
            EABase::RegBPL => Variable::new2("BPL", None, 8).ok(),
            EABase::RegSIL => Variable::new2("SIL", None, 8).ok(),
            EABase::RegDIL => Variable::new2("DIL", None, 8).ok(),

            EABase::RegAX => Variable::new2("AX", None, 16).ok(),
            EABase::RegCX => Variable::new2("CX", None, 16).ok(),
            EABase::RegDX => Variable::new2("DX", None, 16).ok(),
            EABase::RegBX => Variable::new2("BX", None, 16).ok(),
            EABase::RegSP => Variable::new2("SP", None, 16).ok(),
            EABase::RegBP => Variable::new2("BP", None, 16).ok(),
            EABase::RegSI => Variable::new2("SI", None, 16).ok(),
            EABase::RegDI => Variable::new2("DI", None, 16).ok(),
            EABase::RegR8W => Variable::new2("R8W", None, 16).ok(),
            EABase::RegR9W => Variable::new2("R9W", None, 16).ok(),
            EABase::RegR10W => Variable::new2("R10W", None, 16).ok(),
            EABase::RegR11W => Variable::new2("R11W", None, 16).ok(),
            EABase::RegR12W => Variable::new2("R12W", None, 16).ok(),
            EABase::RegR13W => Variable::new2("R13W", None, 16).ok(),
            EABase::RegR14W => Variable::new2("R14W", None, 16).ok(),
            EABase::RegR15W => Variable::new2("R15W", None, 16).ok(),

            EABase::RegEAX => Variable::new2("EAX", None, 32).ok(),
            EABase::RegECX => Variable::new2("ECX", None, 32).ok(),
            EABase::RegEDX => Variable::new2("EDX", None, 32).ok(),
            EABase::RegEBX => Variable::new2("EBX", None, 32).ok(),
            EABase::RegESP => Variable::new2("ESP", None, 32).ok(),
            EABase::RegEBP => Variable::new2("EBP", None, 32).ok(),
            EABase::RegESI => Variable::new2("ESI", None, 32).ok(),
            EABase::RegEDI => Variable::new2("EDI", None, 32).ok(),
            EABase::RegR8D => Variable::new2("R8D", None, 32).ok(),
            EABase::RegR9D => Variable::new2("R9D", None, 32).ok(),
            EABase::RegR10D => Variable::new2("R10D", None, 32).ok(),
            EABase::RegR11D => Variable::new2("R11D", None, 32).ok(),
            EABase::RegR12D => Variable::new2("R12D", None, 32).ok(),
            EABase::RegR13D => Variable::new2("R13D", None, 32).ok(),
            EABase::RegR14D => Variable::new2("R14D", None, 32).ok(),
            EABase::RegR15D => Variable::new2("R15D", None, 32).ok(),

            EABase::RegRAX => Variable::new2("RAX", None, 64).ok(),
            EABase::RegRCX => Variable::new2("RCX", None, 64).ok(),
            EABase::RegRDX => Variable::new2("RDX", None, 64).ok(),
            EABase::RegRBX => Variable::new2("RBX", None, 64).ok(),
            EABase::RegRSP => Variable::new2("RSP", None, 64).ok(),
            EABase::RegRBP => Variable::new2("RBP", None, 64).ok(),
            EABase::RegRSI => Variable::new2("RSI", None, 64).ok(),
            EABase::RegRDI => Variable::new2("RDI", None, 64).ok(),
            EABase::RegR8 => Variable::new2("R8", None, 64).ok(),
            EABase::RegR9 => Variable::new2("R9", None, 64).ok(),
            EABase::RegR10 => Variable::new2("R10", None, 64).ok(),
            EABase::RegR11 => Variable::new2("R11", None, 64).ok(),
            EABase::RegR12 => Variable::new2("R12", None, 64).ok(),
            EABase::RegR13 => Variable::new2("R13", None, 64).ok(),
            EABase::RegR14 => Variable::new2("R14", None, 64).ok(),
            EABase::RegR15 => Variable::new2("R15", None, 64).ok(),

            EABase::RegMM0 => Variable::new2("MM0", None, 64).ok(),
            EABase::RegMM1 => Variable::new2("MM1", None, 64).ok(),
            EABase::RegMM2 => Variable::new2("MM2", None, 64).ok(),
            EABase::RegMM3 => Variable::new2("MM3", None, 64).ok(),
            EABase::RegMM4 => Variable::new2("MM4", None, 64).ok(),
            EABase::RegMM5 => Variable::new2("MM5", None, 64).ok(),
            EABase::RegMM6 => Variable::new2("MM6", None, 64).ok(),
            EABase::RegMM7 => Variable::new2("MM7", None, 64).ok(),

            EABase::RegXMM0 => Variable::new2("XMM0", None, 128).ok(),
            EABase::RegXMM1 => Variable::new2("XMM1", None, 128).ok(),
            EABase::RegXMM2 => Variable::new2("XMM2", None, 128).ok(),
            EABase::RegXMM3 => Variable::new2("XMM3", None, 128).ok(),
            EABase::RegXMM4 => Variable::new2("XMM4", None, 128).ok(),
            EABase::RegXMM5 => Variable::new2("XMM5", None, 128).ok(),
            EABase::RegXMM6 => Variable::new2("XMM6", None, 128).ok(),
            EABase::RegXMM7 => Variable::new2("XMM7", None, 128).ok(),
            EABase::RegXMM8 => Variable::new2("XMM8", None, 128).ok(),
            EABase::RegXMM9 => Variable::new2("XMM9", None, 128).ok(),
            EABase::RegXMM10 => Variable::new2("XMM10", None, 128).ok(),
            EABase::RegXMM11 => Variable::new2("XMM11", None, 128).ok(),
            EABase::RegXMM12 => Variable::new2("XMM12", None, 128).ok(),
            EABase::RegXMM13 => Variable::new2("XMM13", None, 128).ok(),
            EABase::RegXMM14 => Variable::new2("XMM14", None, 128).ok(),
            EABase::RegXMM15 => Variable::new2("XMM15", None, 128).ok(),
            EABase::RegXMM16 => Variable::new2("XMM16", None, 128).ok(),
            EABase::RegXMM17 => Variable::new2("XMM17", None, 128).ok(),
            EABase::RegXMM18 => Variable::new2("XMM18", None, 128).ok(),
            EABase::RegXMM19 => Variable::new2("XMM19", None, 128).ok(),
            EABase::RegXMM20 => Variable::new2("XMM20", None, 128).ok(),
            EABase::RegXMM21 => Variable::new2("XMM21", None, 128).ok(),
            EABase::RegXMM22 => Variable::new2("XMM22", None, 128).ok(),
            EABase::RegXMM23 => Variable::new2("XMM23", None, 128).ok(),
            EABase::RegXMM24 => Variable::new2("XMM24", None, 128).ok(),
            EABase::RegXMM25 => Variable::new2("XMM25", None, 128).ok(),
            EABase::RegXMM26 => Variable::new2("XMM26", None, 128).ok(),
            EABase::RegXMM27 => Variable::new2("XMM27", None, 128).ok(),
            EABase::RegXMM28 => Variable::new2("XMM28", None, 128).ok(),
            EABase::RegXMM29 => Variable::new2("XMM29", None, 128).ok(),
            EABase::RegXMM30 => Variable::new2("XMM30", None, 128).ok(),
            EABase::RegXMM31 => Variable::new2("XMM31", None, 128).ok(),

            EABase::RegYMM0 => Variable::new2("YMM0", None, 256).ok(),
            EABase::RegYMM1 => Variable::new2("YMM1", None, 256).ok(),
            EABase::RegYMM2 => Variable::new2("YMM2", None, 256).ok(),
            EABase::RegYMM3 => Variable::new2("YMM3", None, 256).ok(),
            EABase::RegYMM4 => Variable::new2("YMM4", None, 256).ok(),
            EABase::RegYMM5 => Variable::new2("YMM5", None, 256).ok(),
            EABase::RegYMM6 => Variable::new2("YMM6", None, 256).ok(),
            EABase::RegYMM7 => Variable::new2("YMM7", None, 256).ok(),
            EABase::RegYMM8 => Variable::new2("YMM8", None, 256).ok(),
            EABase::RegYMM9 => Variable::new2("YMM9", None, 256).ok(),
            EABase::RegYMM10 => Variable::new2("YMM10", None, 256).ok(),
            EABase::RegYMM11 => Variable::new2("YMM11", None, 256).ok(),
            EABase::RegYMM12 => Variable::new2("YMM12", None, 256).ok(),
            EABase::RegYMM13 => Variable::new2("YMM13", None, 256).ok(),
            EABase::RegYMM14 => Variable::new2("YMM14", None, 256).ok(),
            EABase::RegYMM15 => Variable::new2("YMM15", None, 256).ok(),
            EABase::RegYMM16 => Variable::new2("YMM16", None, 256).ok(),
            EABase::RegYMM17 => Variable::new2("YMM17", None, 256).ok(),
            EABase::RegYMM18 => Variable::new2("YMM18", None, 256).ok(),
            EABase::RegYMM19 => Variable::new2("YMM19", None, 256).ok(),
            EABase::RegYMM20 => Variable::new2("YMM20", None, 256).ok(),
            EABase::RegYMM21 => Variable::new2("YMM21", None, 256).ok(),
            EABase::RegYMM22 => Variable::new2("YMM22", None, 256).ok(),
            EABase::RegYMM23 => Variable::new2("YMM23", None, 256).ok(),
            EABase::RegYMM24 => Variable::new2("YMM24", None, 256).ok(),
            EABase::RegYMM25 => Variable::new2("YMM25", None, 256).ok(),
            EABase::RegYMM26 => Variable::new2("YMM26", None, 256).ok(),
            EABase::RegYMM27 => Variable::new2("YMM27", None, 256).ok(),
            EABase::RegYMM28 => Variable::new2("YMM28", None, 256).ok(),
            EABase::RegYMM29 => Variable::new2("YMM29", None, 256).ok(),
            EABase::RegYMM30 => Variable::new2("YMM30", None, 256).ok(),
            EABase::RegYMM31 => Variable::new2("YMM31", None, 256).ok(),

            EABase::RegZMM0 => Variable::new2("ZMM0", None, 512).ok(),
            EABase::RegZMM1 => Variable::new2("ZMM1", None, 512).ok(),
            EABase::RegZMM2 => Variable::new2("ZMM2", None, 512).ok(),
            EABase::RegZMM3 => Variable::new2("ZMM3", None, 512).ok(),
            EABase::RegZMM4 => Variable::new2("ZMM4", None, 512).ok(),
            EABase::RegZMM5 => Variable::new2("ZMM5", None, 512).ok(),
            EABase::RegZMM6 => Variable::new2("ZMM6", None, 512).ok(),
            EABase::RegZMM7 => Variable::new2("ZMM7", None, 512).ok(),
            EABase::RegZMM8 => Variable::new2("ZMM8", None, 512).ok(),
            EABase::RegZMM9 => Variable::new2("ZMM9", None, 512).ok(),
            EABase::RegZMM10 => Variable::new2("ZMM10", None, 512).ok(),
            EABase::RegZMM11 => Variable::new2("ZMM11", None, 512).ok(),
            EABase::RegZMM12 => Variable::new2("ZMM12", None, 512).ok(),
            EABase::RegZMM13 => Variable::new2("ZMM13", None, 512).ok(),
            EABase::RegZMM14 => Variable::new2("ZMM14", None, 512).ok(),
            EABase::RegZMM15 => Variable::new2("ZMM15", None, 512).ok(),
            EABase::RegZMM16 => Variable::new2("ZMM16", None, 512).ok(),
            EABase::RegZMM17 => Variable::new2("ZMM17", None, 512).ok(),
            EABase::RegZMM18 => Variable::new2("ZMM18", None, 512).ok(),
            EABase::RegZMM19 => Variable::new2("ZMM19", None, 512).ok(),
            EABase::RegZMM20 => Variable::new2("ZMM20", None, 512).ok(),
            EABase::RegZMM21 => Variable::new2("ZMM21", None, 512).ok(),
            EABase::RegZMM22 => Variable::new2("ZMM22", None, 512).ok(),
            EABase::RegZMM23 => Variable::new2("ZMM23", None, 512).ok(),
            EABase::RegZMM24 => Variable::new2("ZMM24", None, 512).ok(),
            EABase::RegZMM25 => Variable::new2("ZMM25", None, 512).ok(),
            EABase::RegZMM26 => Variable::new2("ZMM26", None, 512).ok(),
            EABase::RegZMM27 => Variable::new2("ZMM27", None, 512).ok(),
            EABase::RegZMM28 => Variable::new2("ZMM28", None, 512).ok(),
            EABase::RegZMM29 => Variable::new2("ZMM29", None, 512).ok(),
            EABase::RegZMM30 => Variable::new2("ZMM30", None, 512).ok(),
            EABase::RegZMM31 => Variable::new2("ZMM31", None, 512).ok(),

            EABase::RegK0 => Variable::new2("K0", None, 64).ok(),
            EABase::RegK1 => Variable::new2("K1", None, 64).ok(),
            EABase::RegK2 => Variable::new2("K2", None, 64).ok(),
            EABase::RegK3 => Variable::new2("K3", None, 64).ok(),
            EABase::RegK4 => Variable::new2("K4", None, 64).ok(),
            EABase::RegK5 => Variable::new2("K5", None, 64).ok(),
            EABase::RegK6 => Variable::new2("K6", None, 64).ok(),
            EABase::RegK7 => Variable::new2("K7", None, 64).ok(),

            EABase::RegES => Variable::new2("ES", None, 16).ok(),
            EABase::RegCS => Variable::new2("CS", None, 16).ok(),
            EABase::RegSS => Variable::new2("SS", None, 16).ok(),
            EABase::RegDS => Variable::new2("DS", None, 16).ok(),
            EABase::RegFS => Variable::new2("FS", None, 16).ok(),
            EABase::RegGS => Variable::new2("GS", None, 16).ok(),

            EABase::RegDR0 => Variable::new2("DR0", None, 64).ok(),
            EABase::RegDR1 => Variable::new2("DR1", None, 64).ok(),
            EABase::RegDR2 => Variable::new2("DR2", None, 64).ok(),
            EABase::RegDR3 => Variable::new2("DR3", None, 64).ok(),
            EABase::RegDR4 => Variable::new2("DR4", None, 64).ok(),
            EABase::RegDR5 => Variable::new2("DR5", None, 64).ok(),
            EABase::RegDR6 => Variable::new2("DR6", None, 64).ok(),
            EABase::RegDR7 => Variable::new2("DR7", None, 64).ok(),
            EABase::RegDR8 => Variable::new2("DR8", None, 64).ok(),
            EABase::RegDR9 => Variable::new2("DR9", None, 64).ok(),
            EABase::RegDR10 => Variable::new2("DR10", None, 64).ok(),
            EABase::RegDR11 => Variable::new2("DR11", None, 64).ok(),
            EABase::RegDR12 => Variable::new2("DR12", None, 64).ok(),
            EABase::RegDR13 => Variable::new2("DR13", None, 64).ok(),
            EABase::RegDR14 => Variable::new2("DR14", None, 64).ok(),
            EABase::RegDR15 => Variable::new2("DR15", None, 64).ok(),

            EABase::RegCR0 => Variable::new2("CR0", None, 64).ok(),
            EABase::RegCR1 => Variable::new2("CR1", None, 64).ok(),
            EABase::RegCR2 => Variable::new2("CR2", None, 64).ok(),
            EABase::RegCR3 => Variable::new2("CR3", None, 64).ok(),
            EABase::RegCR4 => Variable::new2("CR4", None, 64).ok(),
            EABase::RegCR5 => Variable::new2("CR5", None, 64).ok(),
            EABase::RegCR6 => Variable::new2("CR6", None, 64).ok(),
            EABase::RegCR7 => Variable::new2("CR7", None, 64).ok(),
            EABase::RegCR8 => Variable::new2("CR8", None, 64).ok(),
            EABase::RegCR9 => Variable::new2("CR9", None, 64).ok(),
            EABase::RegCR10 => Variable::new2("CR10", None, 64).ok(),
            EABase::RegCR11 => Variable::new2("CR11", None, 64).ok(),
            EABase::RegCR12 => Variable::new2("CR12", None, 64).ok(),
            EABase::RegCR13 => Variable::new2("CR13", None, 64).ok(),
            EABase::RegCR14 => Variable::new2("CR14", None, 64).ok(),
            EABase::RegCR15 => Variable::new2("CR15", None, 64).ok(),

            EABase::RegBND0 => Variable::new2("BND0", None, 128).ok(),
            EABase::RegBND1 => Variable::new2("BND1", None, 128).ok(),
            EABase::RegBND2 => Variable::new2("BND2", None, 128).ok(),
            EABase::RegBND3 => Variable::new2("BND3", None, 128).ok(),

            EABase::RegRIP => Variable::new2("RIP", None, 64).ok(),

            _ => None,
        }
    }

    pub fn as_base_var(&self) -> Option<Variable> {
        match self {
            EABase::BaseNone => None,

            EABase::BaseBX_SI => None,
            EABase::BaseBX_DI => None,
            EABase::BaseBP_SI => None,
            EABase::BaseBP_DI => None,
            EABase::BaseSI => Variable::new2("SI", None, 16).ok(),
            EABase::BaseDI => Variable::new2("DI", None, 16).ok(),
            EABase::BaseBP => Variable::new2("BP", None, 16).ok(),
            EABase::BaseBX => Variable::new2("BX", None, 16).ok(),
            EABase::BaseR8W => Variable::new2("R8W", None, 16).ok(),
            EABase::BaseR9W => Variable::new2("R9W", None, 16).ok(),
            EABase::BaseR10W => Variable::new2("R116W", None, 16).ok(),
            EABase::BaseR11W => Variable::new2("R11W", None, 16).ok(),
            EABase::BaseR12W => Variable::new2("R12W", None, 16).ok(),
            EABase::BaseR13W => Variable::new2("R13W", None, 16).ok(),
            EABase::BaseR14W => Variable::new2("R14W", None, 16).ok(),
            EABase::BaseR15W => Variable::new2("R15W", None, 16).ok(),

            EABase::BaseEAX => Variable::new2("EAX", None, 32).ok(),
            EABase::BaseECX => Variable::new2("ECX", None, 32).ok(),
            EABase::BaseEDX => Variable::new2("EDX", None, 32).ok(),
            EABase::BaseEBX => Variable::new2("EBX", None, 32).ok(),
            EABase::Basesib => None,
            EABase::BaseEBP => Variable::new2("EBP", None, 32).ok(),
            EABase::BaseESI => Variable::new2("ESI", None, 32).ok(),
            EABase::BaseEDI => Variable::new2("EDI", None, 32).ok(),
            EABase::BaseR8D => Variable::new2("R8D", None, 32).ok(),
            EABase::BaseR9D => Variable::new2("R9D", None, 32).ok(),
            EABase::BaseR10D => Variable::new2("R10D", None, 32).ok(),
            EABase::BaseR11D => Variable::new2("R11D", None, 32).ok(),
            EABase::BaseR12D => Variable::new2("R12D", None, 32).ok(),
            EABase::BaseR13D => Variable::new2("R13D", None, 32).ok(),
            EABase::BaseR14D => Variable::new2("R14D", None, 32).ok(),
            EABase::BaseR15D => Variable::new2("R15D", None, 32).ok(),

            EABase::BaseRAX => Variable::new2("RAX", None, 64).ok(),
            EABase::BaseRCX => Variable::new2("RCX", None, 64).ok(),
            EABase::BaseRDX => Variable::new2("RDX", None, 64).ok(),
            EABase::BaseRBX => Variable::new2("RBX", None, 64).ok(),
            EABase::Basesib64 => None,
            EABase::BaseRBP => Variable::new2("RBP", None, 64).ok(),
            EABase::BaseRSI => Variable::new2("RSI", None, 64).ok(),
            EABase::BaseRDI => Variable::new2("RDI", None, 64).ok(),
            EABase::BaseR8 => Variable::new2("R8", None, 64).ok(),
            EABase::BaseR9 => Variable::new2("R9", None, 64).ok(),
            EABase::BaseR10 => Variable::new2("R10", None, 64).ok(),
            EABase::BaseR11 => Variable::new2("R11", None, 64).ok(),
            EABase::BaseR12 => Variable::new2("R12", None, 64).ok(),
            EABase::BaseR13 => Variable::new2("R13", None, 64).ok(),
            EABase::BaseR14 => Variable::new2("R14", None, 64).ok(),
            EABase::BaseR15 => Variable::new2("R15", None, 64).ok(),

            _ => None,
        }
    }
}

#[derive(FromPrimitive, Clone, Copy, Debug)]
/// All possible values of the reg field in the ModR/M byte.
pub enum Reg {
    AL,
    CL,
    DL,
    BL,
    AH,
    CH,
    DH,
    BH,
    R8B,
    R9B,
    R10B,
    R11B,
    R12B,
    R13B,
    R14B,
    R15B,
    SPL,
    BPL,
    SIL,
    DIL,
    AX,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    MM0,
    MM1,
    MM2,
    MM3,
    MM4,
    MM5,
    MM6,
    MM7,
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,
    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,
    ZMM0,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31,
    K0,
    K1,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7,
    ES,
    CS,
    SS,
    DS,
    FS,
    GS,
    DR0,
    DR1,
    DR2,
    DR3,
    DR4,
    DR5,
    DR6,
    DR7,
    DR8,
    DR9,
    DR10,
    DR11,
    DR12,
    DR13,
    DR14,
    DR15,
    CR0,
    CR1,
    CR2,
    CR3,
    CR4,
    CR5,
    CR6,
    CR7,
    CR8,
    CR9,
    CR10,
    CR11,
    CR12,
    CR13,
    CR14,
    CR15,
    BND0,
    BND1,
    BND2,
    BND3,
    RIP,
}

impl Reg {
    pub fn as_var(&self) -> Option<Variable> {
        match self {
            Reg::AL => Variable::new2("AL", None, 8).ok(),
            Reg::CL => Variable::new2("CL", None, 8).ok(),
            Reg::DL => Variable::new2("DL", None, 8).ok(),
            Reg::BL => Variable::new2("BL", None, 8).ok(),
            Reg::AH => Variable::new2("AH", None, 8).ok(),
            Reg::CH => Variable::new2("CH", None, 8).ok(),
            Reg::DH => Variable::new2("DH", None, 8).ok(),
            Reg::BH => Variable::new2("BH", None, 8).ok(),
            Reg::R8B => Variable::new2("R8B", None, 8).ok(),
            Reg::R9B => Variable::new2("R9B", None, 8).ok(),
            Reg::R10B => Variable::new2("R10B", None, 8).ok(),
            Reg::R11B => Variable::new2("R11B", None, 8).ok(),
            Reg::R12B => Variable::new2("R12B", None, 8).ok(),
            Reg::R13B => Variable::new2("R13B", None, 8).ok(),
            Reg::R14B => Variable::new2("R14B", None, 8).ok(),
            Reg::R15B => Variable::new2("R15B", None, 8).ok(),
            Reg::SPL => Variable::new2("SPL", None, 8).ok(),
            Reg::BPL => Variable::new2("BPL", None, 8).ok(),
            Reg::SIL => Variable::new2("SIL", None, 8).ok(),
            Reg::DIL => Variable::new2("DIL", None, 8).ok(),

            Reg::AX => Variable::new2("AX", None, 16).ok(),
            Reg::CX => Variable::new2("CX", None, 16).ok(),
            Reg::DX => Variable::new2("DX", None, 16).ok(),
            Reg::BX => Variable::new2("BX", None, 16).ok(),
            Reg::SP => Variable::new2("SP", None, 16).ok(),
            Reg::BP => Variable::new2("BP", None, 16).ok(),
            Reg::SI => Variable::new2("SI", None, 16).ok(),
            Reg::DI => Variable::new2("DI", None, 16).ok(),
            Reg::R8W => Variable::new2("R8W", None, 16).ok(),
            Reg::R9W => Variable::new2("R9W", None, 16).ok(),
            Reg::R10W => Variable::new2("R10W", None, 16).ok(),
            Reg::R11W => Variable::new2("R11W", None, 16).ok(),
            Reg::R12W => Variable::new2("R12W", None, 16).ok(),
            Reg::R13W => Variable::new2("R13W", None, 16).ok(),
            Reg::R14W => Variable::new2("R14W", None, 16).ok(),
            Reg::R15W => Variable::new2("R15W", None, 16).ok(),

            Reg::EAX => Variable::new2("EAX", None, 32).ok(),
            Reg::ECX => Variable::new2("ECX", None, 32).ok(),
            Reg::EDX => Variable::new2("EDX", None, 32).ok(),
            Reg::EBX => Variable::new2("EBX", None, 32).ok(),
            Reg::ESP => Variable::new2("ESP", None, 32).ok(),
            Reg::EBP => Variable::new2("EBP", None, 32).ok(),
            Reg::ESI => Variable::new2("ESI", None, 32).ok(),
            Reg::EDI => Variable::new2("EDI", None, 32).ok(),
            Reg::R8D => Variable::new2("R8D", None, 32).ok(),
            Reg::R9D => Variable::new2("R9D", None, 32).ok(),
            Reg::R10D => Variable::new2("R10D", None, 32).ok(),
            Reg::R11D => Variable::new2("R11D", None, 32).ok(),
            Reg::R12D => Variable::new2("R12D", None, 32).ok(),
            Reg::R13D => Variable::new2("R13D", None, 32).ok(),
            Reg::R14D => Variable::new2("R14D", None, 32).ok(),
            Reg::R15D => Variable::new2("R15D", None, 32).ok(),

            Reg::RAX => Variable::new2("RAX", None, 64).ok(),
            Reg::RCX => Variable::new2("RCX", None, 64).ok(),
            Reg::RDX => Variable::new2("RDX", None, 64).ok(),
            Reg::RBX => Variable::new2("RBX", None, 64).ok(),
            Reg::RSP => Variable::new2("RSP", None, 64).ok(),
            Reg::RBP => Variable::new2("RBP", None, 64).ok(),
            Reg::RSI => Variable::new2("RSI", None, 64).ok(),
            Reg::RDI => Variable::new2("RDI", None, 64).ok(),
            Reg::R8 => Variable::new2("R8", None, 64).ok(),
            Reg::R9 => Variable::new2("R9", None, 64).ok(),
            Reg::R10 => Variable::new2("R10", None, 64).ok(),
            Reg::R11 => Variable::new2("R11", None, 64).ok(),
            Reg::R12 => Variable::new2("R12", None, 64).ok(),
            Reg::R13 => Variable::new2("R13", None, 64).ok(),
            Reg::R14 => Variable::new2("R14", None, 64).ok(),
            Reg::R15 => Variable::new2("R15", None, 64).ok(),

            Reg::MM0 => Variable::new2("MM0", None, 64).ok(),
            Reg::MM1 => Variable::new2("MM1", None, 64).ok(),
            Reg::MM2 => Variable::new2("MM2", None, 64).ok(),
            Reg::MM3 => Variable::new2("MM3", None, 64).ok(),
            Reg::MM4 => Variable::new2("MM4", None, 64).ok(),
            Reg::MM5 => Variable::new2("MM5", None, 64).ok(),
            Reg::MM6 => Variable::new2("MM6", None, 64).ok(),
            Reg::MM7 => Variable::new2("MM7", None, 64).ok(),

            Reg::XMM0 => Variable::new2("XMM0", None, 128).ok(),
            Reg::XMM1 => Variable::new2("XMM1", None, 128).ok(),
            Reg::XMM2 => Variable::new2("XMM2", None, 128).ok(),
            Reg::XMM3 => Variable::new2("XMM3", None, 128).ok(),
            Reg::XMM4 => Variable::new2("XMM4", None, 128).ok(),
            Reg::XMM5 => Variable::new2("XMM5", None, 128).ok(),
            Reg::XMM6 => Variable::new2("XMM6", None, 128).ok(),
            Reg::XMM7 => Variable::new2("XMM7", None, 128).ok(),
            Reg::XMM8 => Variable::new2("XMM8", None, 128).ok(),
            Reg::XMM9 => Variable::new2("XMM9", None, 128).ok(),
            Reg::XMM10 => Variable::new2("XMM10", None, 128).ok(),
            Reg::XMM11 => Variable::new2("XMM11", None, 128).ok(),
            Reg::XMM12 => Variable::new2("XMM12", None, 128).ok(),
            Reg::XMM13 => Variable::new2("XMM13", None, 128).ok(),
            Reg::XMM14 => Variable::new2("XMM14", None, 128).ok(),
            Reg::XMM15 => Variable::new2("XMM15", None, 128).ok(),
            Reg::XMM16 => Variable::new2("XMM16", None, 128).ok(),
            Reg::XMM17 => Variable::new2("XMM17", None, 128).ok(),
            Reg::XMM18 => Variable::new2("XMM18", None, 128).ok(),
            Reg::XMM19 => Variable::new2("XMM19", None, 128).ok(),
            Reg::XMM20 => Variable::new2("XMM20", None, 128).ok(),
            Reg::XMM21 => Variable::new2("XMM21", None, 128).ok(),
            Reg::XMM22 => Variable::new2("XMM22", None, 128).ok(),
            Reg::XMM23 => Variable::new2("XMM23", None, 128).ok(),
            Reg::XMM24 => Variable::new2("XMM24", None, 128).ok(),
            Reg::XMM25 => Variable::new2("XMM25", None, 128).ok(),
            Reg::XMM26 => Variable::new2("XMM26", None, 128).ok(),
            Reg::XMM27 => Variable::new2("XMM27", None, 128).ok(),
            Reg::XMM28 => Variable::new2("XMM28", None, 128).ok(),
            Reg::XMM29 => Variable::new2("XMM29", None, 128).ok(),
            Reg::XMM30 => Variable::new2("XMM30", None, 128).ok(),
            Reg::XMM31 => Variable::new2("XMM31", None, 128).ok(),

            Reg::YMM0 => Variable::new2("YMM0", None, 256).ok(),
            Reg::YMM1 => Variable::new2("YMM1", None, 256).ok(),
            Reg::YMM2 => Variable::new2("YMM2", None, 256).ok(),
            Reg::YMM3 => Variable::new2("YMM3", None, 256).ok(),
            Reg::YMM4 => Variable::new2("YMM4", None, 256).ok(),
            Reg::YMM5 => Variable::new2("YMM5", None, 256).ok(),
            Reg::YMM6 => Variable::new2("YMM6", None, 256).ok(),
            Reg::YMM7 => Variable::new2("YMM7", None, 256).ok(),
            Reg::YMM8 => Variable::new2("YMM8", None, 256).ok(),
            Reg::YMM9 => Variable::new2("YMM9", None, 256).ok(),
            Reg::YMM10 => Variable::new2("YMM10", None, 256).ok(),
            Reg::YMM11 => Variable::new2("YMM11", None, 256).ok(),
            Reg::YMM12 => Variable::new2("YMM12", None, 256).ok(),
            Reg::YMM13 => Variable::new2("YMM13", None, 256).ok(),
            Reg::YMM14 => Variable::new2("YMM14", None, 256).ok(),
            Reg::YMM15 => Variable::new2("YMM15", None, 256).ok(),
            Reg::YMM16 => Variable::new2("YMM16", None, 256).ok(),
            Reg::YMM17 => Variable::new2("YMM17", None, 256).ok(),
            Reg::YMM18 => Variable::new2("YMM18", None, 256).ok(),
            Reg::YMM19 => Variable::new2("YMM19", None, 256).ok(),
            Reg::YMM20 => Variable::new2("YMM20", None, 256).ok(),
            Reg::YMM21 => Variable::new2("YMM21", None, 256).ok(),
            Reg::YMM22 => Variable::new2("YMM22", None, 256).ok(),
            Reg::YMM23 => Variable::new2("YMM23", None, 256).ok(),
            Reg::YMM24 => Variable::new2("YMM24", None, 256).ok(),
            Reg::YMM25 => Variable::new2("YMM25", None, 256).ok(),
            Reg::YMM26 => Variable::new2("YMM26", None, 256).ok(),
            Reg::YMM27 => Variable::new2("YMM27", None, 256).ok(),
            Reg::YMM28 => Variable::new2("YMM28", None, 256).ok(),
            Reg::YMM29 => Variable::new2("YMM29", None, 256).ok(),
            Reg::YMM30 => Variable::new2("YMM30", None, 256).ok(),
            Reg::YMM31 => Variable::new2("YMM31", None, 256).ok(),

            Reg::ZMM0 => Variable::new2("ZMM0", None, 512).ok(),
            Reg::ZMM1 => Variable::new2("ZMM1", None, 512).ok(),
            Reg::ZMM2 => Variable::new2("ZMM2", None, 512).ok(),
            Reg::ZMM3 => Variable::new2("ZMM3", None, 512).ok(),
            Reg::ZMM4 => Variable::new2("ZMM4", None, 512).ok(),
            Reg::ZMM5 => Variable::new2("ZMM5", None, 512).ok(),
            Reg::ZMM6 => Variable::new2("ZMM6", None, 512).ok(),
            Reg::ZMM7 => Variable::new2("ZMM7", None, 512).ok(),
            Reg::ZMM8 => Variable::new2("ZMM8", None, 512).ok(),
            Reg::ZMM9 => Variable::new2("ZMM9", None, 512).ok(),
            Reg::ZMM10 => Variable::new2("ZMM10", None, 512).ok(),
            Reg::ZMM11 => Variable::new2("ZMM11", None, 512).ok(),
            Reg::ZMM12 => Variable::new2("ZMM12", None, 512).ok(),
            Reg::ZMM13 => Variable::new2("ZMM13", None, 512).ok(),
            Reg::ZMM14 => Variable::new2("ZMM14", None, 512).ok(),
            Reg::ZMM15 => Variable::new2("ZMM15", None, 512).ok(),
            Reg::ZMM16 => Variable::new2("ZMM16", None, 512).ok(),
            Reg::ZMM17 => Variable::new2("ZMM17", None, 512).ok(),
            Reg::ZMM18 => Variable::new2("ZMM18", None, 512).ok(),
            Reg::ZMM19 => Variable::new2("ZMM19", None, 512).ok(),
            Reg::ZMM20 => Variable::new2("ZMM20", None, 512).ok(),
            Reg::ZMM21 => Variable::new2("ZMM21", None, 512).ok(),
            Reg::ZMM22 => Variable::new2("ZMM22", None, 512).ok(),
            Reg::ZMM23 => Variable::new2("ZMM23", None, 512).ok(),
            Reg::ZMM24 => Variable::new2("ZMM24", None, 512).ok(),
            Reg::ZMM25 => Variable::new2("ZMM25", None, 512).ok(),
            Reg::ZMM26 => Variable::new2("ZMM26", None, 512).ok(),
            Reg::ZMM27 => Variable::new2("ZMM27", None, 512).ok(),
            Reg::ZMM28 => Variable::new2("ZMM28", None, 512).ok(),
            Reg::ZMM29 => Variable::new2("ZMM29", None, 512).ok(),
            Reg::ZMM30 => Variable::new2("ZMM30", None, 512).ok(),
            Reg::ZMM31 => Variable::new2("ZMM31", None, 512).ok(),

            Reg::K0 => Variable::new2("K0", None, 64).ok(),
            Reg::K1 => Variable::new2("K1", None, 64).ok(),
            Reg::K2 => Variable::new2("K2", None, 64).ok(),
            Reg::K3 => Variable::new2("K3", None, 64).ok(),
            Reg::K4 => Variable::new2("K4", None, 64).ok(),
            Reg::K5 => Variable::new2("K5", None, 64).ok(),
            Reg::K6 => Variable::new2("K6", None, 64).ok(),
            Reg::K7 => Variable::new2("K7", None, 64).ok(),

            Reg::ES => Variable::new2("ES", None, 16).ok(),
            Reg::CS => Variable::new2("CS", None, 16).ok(),
            Reg::SS => Variable::new2("SS", None, 16).ok(),
            Reg::DS => Variable::new2("DS", None, 16).ok(),
            Reg::FS => Variable::new2("FS", None, 16).ok(),
            Reg::GS => Variable::new2("GS", None, 16).ok(),

            Reg::DR0 => Variable::new2("DR0", None, 64).ok(),
            Reg::DR1 => Variable::new2("DR1", None, 64).ok(),
            Reg::DR2 => Variable::new2("DR2", None, 64).ok(),
            Reg::DR3 => Variable::new2("DR3", None, 64).ok(),
            Reg::DR4 => Variable::new2("DR4", None, 64).ok(),
            Reg::DR5 => Variable::new2("DR5", None, 64).ok(),
            Reg::DR6 => Variable::new2("DR6", None, 64).ok(),
            Reg::DR7 => Variable::new2("DR7", None, 64).ok(),
            Reg::DR8 => Variable::new2("DR8", None, 64).ok(),
            Reg::DR9 => Variable::new2("DR9", None, 64).ok(),
            Reg::DR10 => Variable::new2("DR10", None, 64).ok(),
            Reg::DR11 => Variable::new2("DR11", None, 64).ok(),
            Reg::DR12 => Variable::new2("DR12", None, 64).ok(),
            Reg::DR13 => Variable::new2("DR13", None, 64).ok(),
            Reg::DR14 => Variable::new2("DR14", None, 64).ok(),
            Reg::DR15 => Variable::new2("DR15", None, 64).ok(),

            Reg::CR0 => Variable::new2("CR0", None, 64).ok(),
            Reg::CR1 => Variable::new2("CR1", None, 64).ok(),
            Reg::CR2 => Variable::new2("CR2", None, 64).ok(),
            Reg::CR3 => Variable::new2("CR3", None, 64).ok(),
            Reg::CR4 => Variable::new2("CR4", None, 64).ok(),
            Reg::CR5 => Variable::new2("CR5", None, 64).ok(),
            Reg::CR6 => Variable::new2("CR6", None, 64).ok(),
            Reg::CR7 => Variable::new2("CR7", None, 64).ok(),
            Reg::CR8 => Variable::new2("CR8", None, 64).ok(),
            Reg::CR9 => Variable::new2("CR9", None, 64).ok(),
            Reg::CR10 => Variable::new2("CR10", None, 64).ok(),
            Reg::CR11 => Variable::new2("CR11", None, 64).ok(),
            Reg::CR12 => Variable::new2("CR12", None, 64).ok(),
            Reg::CR13 => Variable::new2("CR13", None, 64).ok(),
            Reg::CR14 => Variable::new2("CR14", None, 64).ok(),
            Reg::CR15 => Variable::new2("CR15", None, 64).ok(),

            Reg::BND0 => Variable::new2("BND0", None, 128).ok(),
            Reg::BND1 => Variable::new2("BND1", None, 128).ok(),
            Reg::BND2 => Variable::new2("BND2", None, 128).ok(),
            Reg::BND3 => Variable::new2("BND3", None, 128).ok(),

            Reg::RIP => Variable::new2("RIP", None, 64).ok(),
        }
    }
}

#[derive(FromPrimitive, PartialEq, Clone, Copy)]
pub enum SIBBase {
    None,
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl SIBBase {
    pub fn as_var(&self) -> Option<Variable> {
        match self {
            SIBBase::None => None,

            SIBBase::EAX => Variable::new2("EAX", None, 32).ok(),
            SIBBase::ECX => Variable::new2("ECX", None, 32).ok(),
            SIBBase::EDX => Variable::new2("EDX", None, 32).ok(),
            SIBBase::EBX => Variable::new2("EBX", None, 32).ok(),
            SIBBase::ESP => Variable::new2("ESP", None, 32).ok(),
            SIBBase::EBP => Variable::new2("EBP", None, 32).ok(),
            SIBBase::ESI => Variable::new2("ESI", None, 32).ok(),
            SIBBase::EDI => Variable::new2("EDI", None, 32).ok(),
            SIBBase::R8D => Variable::new2("R8D", None, 32).ok(),
            SIBBase::R9D => Variable::new2("R9D", None, 32).ok(),
            SIBBase::R10D => Variable::new2("R10D", None, 32).ok(),
            SIBBase::R11D => Variable::new2("R11D", None, 32).ok(),
            SIBBase::R12D => Variable::new2("R12D", None, 32).ok(),
            SIBBase::R13D => Variable::new2("R13D", None, 32).ok(),
            SIBBase::R14D => Variable::new2("R14D", None, 32).ok(),
            SIBBase::R15D => Variable::new2("R15D", None, 32).ok(),

            SIBBase::RAX => Variable::new2("RAX", None, 64).ok(),
            SIBBase::RCX => Variable::new2("RCX", None, 64).ok(),
            SIBBase::RDX => Variable::new2("RDX", None, 64).ok(),
            SIBBase::RBX => Variable::new2("RBX", None, 64).ok(),
            SIBBase::RSP => Variable::new2("RSP", None, 64).ok(),
            SIBBase::RBP => Variable::new2("RBP", None, 64).ok(),
            SIBBase::RSI => Variable::new2("RSI", None, 64).ok(),
            SIBBase::RDI => Variable::new2("RDI", None, 64).ok(),
            SIBBase::R8 => Variable::new2("R8", None, 64).ok(),
            SIBBase::R9 => Variable::new2("R9", None, 64).ok(),
            SIBBase::R10 => Variable::new2("R10", None, 64).ok(),
            SIBBase::R11 => Variable::new2("R11", None, 64).ok(),
            SIBBase::R12 => Variable::new2("R12", None, 64).ok(),
            SIBBase::R13 => Variable::new2("R13", None, 64).ok(),
            SIBBase::R14 => Variable::new2("R14", None, 64).ok(),
            SIBBase::R15 => Variable::new2("R15", None, 64).ok(),
        }
    }
}


#[derive(FromPrimitive, PartialEq, Clone, Copy)]
/// All possible values of the SIB index field.
/// borrows entries from ALL_EA_BASES with the special case that
/// sib is synonymous with NONE.
/// Vector SIB: index can be XMM or YMM.
pub enum SIBIndex {
    None,
    BX_SI,
    BX_DI,
    BP_SI,
    BP_DI,
    SI,
    DI,
    BP,
    BX,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    EAX,
    ECX,
    EDX,
    EBX,
    sib,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    sib64,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    MM0,
    MM1,
    MM2,
    MM3,
    MM4,
    MM5,
    MM6,
    MM7,
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,
    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,
    ZMM0,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31,
}

impl SIBIndex {
    pub fn as_var(&self) -> Option<Variable> {
        match self {
            SIBIndex::None => None,
            SIBIndex::BP_DI => None,
            SIBIndex::BP_SI => None,
            SIBIndex::BX_DI => None,
            SIBIndex::BX_SI => None,
            SIBIndex::sib => None,
            SIBIndex::sib64 => None,

            SIBIndex::BX => Variable::new2("BX", None, 16).ok(),
            SIBIndex::BP => Variable::new2("BP", None, 16).ok(),
            SIBIndex::SI => Variable::new2("SI", None, 16).ok(),
            SIBIndex::DI => Variable::new2("DI", None, 16).ok(),
            SIBIndex::R8W => Variable::new2("R8W", None, 16).ok(),
            SIBIndex::R9W => Variable::new2("R9W", None, 16).ok(),
            SIBIndex::R10W => Variable::new2("R10W", None, 16).ok(),
            SIBIndex::R11W => Variable::new2("R11W", None, 16).ok(),
            SIBIndex::R12W => Variable::new2("R12W", None, 16).ok(),
            SIBIndex::R13W => Variable::new2("R13W", None, 16).ok(),
            SIBIndex::R14W => Variable::new2("R14W", None, 16).ok(),
            SIBIndex::R15W => Variable::new2("R15W", None, 16).ok(),

            SIBIndex::EAX => Variable::new2("EAX", None, 32).ok(),
            SIBIndex::ECX => Variable::new2("ECX", None, 32).ok(),
            SIBIndex::EDX => Variable::new2("EDX", None, 32).ok(),
            SIBIndex::EBX => Variable::new2("EBX", None, 32).ok(),
            SIBIndex::EBP => Variable::new2("EBP", None, 32).ok(),
            SIBIndex::ESI => Variable::new2("ESI", None, 32).ok(),
            SIBIndex::EDI => Variable::new2("EDI", None, 32).ok(),
            SIBIndex::R8D => Variable::new2("R8D", None, 32).ok(),
            SIBIndex::R9D => Variable::new2("R9D", None, 32).ok(),
            SIBIndex::R10D => Variable::new2("R10D", None, 32).ok(),
            SIBIndex::R11D => Variable::new2("R11D", None, 32).ok(),
            SIBIndex::R12D => Variable::new2("R12D", None, 32).ok(),
            SIBIndex::R13D => Variable::new2("R13D", None, 32).ok(),
            SIBIndex::R14D => Variable::new2("R14D", None, 32).ok(),
            SIBIndex::R15D => Variable::new2("R15D", None, 32).ok(),

            SIBIndex::RAX => Variable::new2("RAX", None, 64).ok(),
            SIBIndex::RCX => Variable::new2("RCX", None, 64).ok(),
            SIBIndex::RDX => Variable::new2("RDX", None, 64).ok(),
            SIBIndex::RBX => Variable::new2("RBX", None, 64).ok(),
            SIBIndex::RBP => Variable::new2("RBP", None, 64).ok(),
            SIBIndex::RSI => Variable::new2("RSI", None, 64).ok(),
            SIBIndex::RDI => Variable::new2("RDI", None, 64).ok(),
            SIBIndex::R8 => Variable::new2("R8", None, 64).ok(),
            SIBIndex::R9 => Variable::new2("R9", None, 64).ok(),
            SIBIndex::R10 => Variable::new2("R10", None, 64).ok(),
            SIBIndex::R11 => Variable::new2("R11", None, 64).ok(),
            SIBIndex::R12 => Variable::new2("R12", None, 64).ok(),
            SIBIndex::R13 => Variable::new2("R13", None, 64).ok(),
            SIBIndex::R14 => Variable::new2("R14", None, 64).ok(),
            SIBIndex::R15 => Variable::new2("R15", None, 64).ok(),

            SIBIndex::MM0 => Variable::new2("MM0", None, 64).ok(),
            SIBIndex::MM1 => Variable::new2("MM1", None, 64).ok(),
            SIBIndex::MM2 => Variable::new2("MM2", None, 64).ok(),
            SIBIndex::MM3 => Variable::new2("MM3", None, 64).ok(),
            SIBIndex::MM4 => Variable::new2("MM4", None, 64).ok(),
            SIBIndex::MM5 => Variable::new2("MM5", None, 64).ok(),
            SIBIndex::MM6 => Variable::new2("MM6", None, 64).ok(),
            SIBIndex::MM7 => Variable::new2("MM7", None, 64).ok(),

            SIBIndex::XMM0 => Variable::new2("XMM0", None, 128).ok(),
            SIBIndex::XMM1 => Variable::new2("XMM1", None, 128).ok(),
            SIBIndex::XMM2 => Variable::new2("XMM2", None, 128).ok(),
            SIBIndex::XMM3 => Variable::new2("XMM3", None, 128).ok(),
            SIBIndex::XMM4 => Variable::new2("XMM4", None, 128).ok(),
            SIBIndex::XMM5 => Variable::new2("XMM5", None, 128).ok(),
            SIBIndex::XMM6 => Variable::new2("XMM6", None, 128).ok(),
            SIBIndex::XMM7 => Variable::new2("XMM7", None, 128).ok(),
            SIBIndex::XMM8 => Variable::new2("XMM8", None, 128).ok(),
            SIBIndex::XMM9 => Variable::new2("XMM9", None, 128).ok(),
            SIBIndex::XMM10 => Variable::new2("XMM10", None, 128).ok(),
            SIBIndex::XMM11 => Variable::new2("XMM11", None, 128).ok(),
            SIBIndex::XMM12 => Variable::new2("XMM12", None, 128).ok(),
            SIBIndex::XMM13 => Variable::new2("XMM13", None, 128).ok(),
            SIBIndex::XMM14 => Variable::new2("XMM14", None, 128).ok(),
            SIBIndex::XMM15 => Variable::new2("XMM15", None, 128).ok(),
            SIBIndex::XMM16 => Variable::new2("XMM16", None, 128).ok(),
            SIBIndex::XMM17 => Variable::new2("XMM17", None, 128).ok(),
            SIBIndex::XMM18 => Variable::new2("XMM18", None, 128).ok(),
            SIBIndex::XMM19 => Variable::new2("XMM19", None, 128).ok(),
            SIBIndex::XMM20 => Variable::new2("XMM20", None, 128).ok(),
            SIBIndex::XMM21 => Variable::new2("XMM21", None, 128).ok(),
            SIBIndex::XMM22 => Variable::new2("XMM22", None, 128).ok(),
            SIBIndex::XMM23 => Variable::new2("XMM23", None, 128).ok(),
            SIBIndex::XMM24 => Variable::new2("XMM24", None, 128).ok(),
            SIBIndex::XMM25 => Variable::new2("XMM25", None, 128).ok(),
            SIBIndex::XMM26 => Variable::new2("XMM26", None, 128).ok(),
            SIBIndex::XMM27 => Variable::new2("XMM27", None, 128).ok(),
            SIBIndex::XMM28 => Variable::new2("XMM28", None, 128).ok(),
            SIBIndex::XMM29 => Variable::new2("XMM29", None, 128).ok(),
            SIBIndex::XMM30 => Variable::new2("XMM30", None, 128).ok(),
            SIBIndex::XMM31 => Variable::new2("XMM31", None, 128).ok(),

            SIBIndex::YMM0 => Variable::new2("YMM0", None, 256).ok(),
            SIBIndex::YMM1 => Variable::new2("YMM1", None, 256).ok(),
            SIBIndex::YMM2 => Variable::new2("YMM2", None, 256).ok(),
            SIBIndex::YMM3 => Variable::new2("YMM3", None, 256).ok(),
            SIBIndex::YMM4 => Variable::new2("YMM4", None, 256).ok(),
            SIBIndex::YMM5 => Variable::new2("YMM5", None, 256).ok(),
            SIBIndex::YMM6 => Variable::new2("YMM6", None, 256).ok(),
            SIBIndex::YMM7 => Variable::new2("YMM7", None, 256).ok(),
            SIBIndex::YMM8 => Variable::new2("YMM8", None, 256).ok(),
            SIBIndex::YMM9 => Variable::new2("YMM9", None, 256).ok(),
            SIBIndex::YMM10 => Variable::new2("YMM10", None, 256).ok(),
            SIBIndex::YMM11 => Variable::new2("YMM11", None, 256).ok(),
            SIBIndex::YMM12 => Variable::new2("YMM12", None, 256).ok(),
            SIBIndex::YMM13 => Variable::new2("YMM13", None, 256).ok(),
            SIBIndex::YMM14 => Variable::new2("YMM14", None, 256).ok(),
            SIBIndex::YMM15 => Variable::new2("YMM15", None, 256).ok(),
            SIBIndex::YMM16 => Variable::new2("YMM16", None, 256).ok(),
            SIBIndex::YMM17 => Variable::new2("YMM17", None, 256).ok(),
            SIBIndex::YMM18 => Variable::new2("YMM18", None, 256).ok(),
            SIBIndex::YMM19 => Variable::new2("YMM19", None, 256).ok(),
            SIBIndex::YMM20 => Variable::new2("YMM20", None, 256).ok(),
            SIBIndex::YMM21 => Variable::new2("YMM21", None, 256).ok(),
            SIBIndex::YMM22 => Variable::new2("YMM22", None, 256).ok(),
            SIBIndex::YMM23 => Variable::new2("YMM23", None, 256).ok(),
            SIBIndex::YMM24 => Variable::new2("YMM24", None, 256).ok(),
            SIBIndex::YMM25 => Variable::new2("YMM25", None, 256).ok(),
            SIBIndex::YMM26 => Variable::new2("YMM26", None, 256).ok(),
            SIBIndex::YMM27 => Variable::new2("YMM27", None, 256).ok(),
            SIBIndex::YMM28 => Variable::new2("YMM28", None, 256).ok(),
            SIBIndex::YMM29 => Variable::new2("YMM29", None, 256).ok(),
            SIBIndex::YMM30 => Variable::new2("YMM30", None, 256).ok(),
            SIBIndex::YMM31 => Variable::new2("YMM31", None, 256).ok(),

            SIBIndex::ZMM0 => Variable::new2("ZMM0", None, 512).ok(),
            SIBIndex::ZMM1 => Variable::new2("ZMM1", None, 512).ok(),
            SIBIndex::ZMM2 => Variable::new2("ZMM2", None, 512).ok(),
            SIBIndex::ZMM3 => Variable::new2("ZMM3", None, 512).ok(),
            SIBIndex::ZMM4 => Variable::new2("ZMM4", None, 512).ok(),
            SIBIndex::ZMM5 => Variable::new2("ZMM5", None, 512).ok(),
            SIBIndex::ZMM6 => Variable::new2("ZMM6", None, 512).ok(),
            SIBIndex::ZMM7 => Variable::new2("ZMM7", None, 512).ok(),
            SIBIndex::ZMM8 => Variable::new2("ZMM8", None, 512).ok(),
            SIBIndex::ZMM9 => Variable::new2("ZMM9", None, 512).ok(),
            SIBIndex::ZMM10 => Variable::new2("ZMM10", None, 512).ok(),
            SIBIndex::ZMM11 => Variable::new2("ZMM11", None, 512).ok(),
            SIBIndex::ZMM12 => Variable::new2("ZMM12", None, 512).ok(),
            SIBIndex::ZMM13 => Variable::new2("ZMM13", None, 512).ok(),
            SIBIndex::ZMM14 => Variable::new2("ZMM14", None, 512).ok(),
            SIBIndex::ZMM15 => Variable::new2("ZMM15", None, 512).ok(),
            SIBIndex::ZMM16 => Variable::new2("ZMM16", None, 512).ok(),
            SIBIndex::ZMM17 => Variable::new2("ZMM17", None, 512).ok(),
            SIBIndex::ZMM18 => Variable::new2("ZMM18", None, 512).ok(),
            SIBIndex::ZMM19 => Variable::new2("ZMM19", None, 512).ok(),
            SIBIndex::ZMM20 => Variable::new2("ZMM20", None, 512).ok(),
            SIBIndex::ZMM21 => Variable::new2("ZMM21", None, 512).ok(),
            SIBIndex::ZMM22 => Variable::new2("ZMM22", None, 512).ok(),
            SIBIndex::ZMM23 => Variable::new2("ZMM23", None, 512).ok(),
            SIBIndex::ZMM24 => Variable::new2("ZMM24", None, 512).ok(),
            SIBIndex::ZMM25 => Variable::new2("ZMM25", None, 512).ok(),
            SIBIndex::ZMM26 => Variable::new2("ZMM26", None, 512).ok(),
            SIBIndex::ZMM27 => Variable::new2("ZMM27", None, 512).ok(),
            SIBIndex::ZMM28 => Variable::new2("ZMM28", None, 512).ok(),
            SIBIndex::ZMM29 => Variable::new2("ZMM29", None, 512).ok(),
            SIBIndex::ZMM30 => Variable::new2("ZMM30", None, 512).ok(),
            SIBIndex::ZMM31 => Variable::new2("ZMM31", None, 512).ok(),
        }
    }
}


#[derive(PartialEq, Clone, Copy)]
/// Possible displacement types for effective-address computations.
pub enum EADisplacement {
    DispNone,
    Disp8,
    Disp16,
    Disp32,
}

#[derive(PartialEq)]
/// All possible segment overrides.
pub enum SegmentOverride {
    None,
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

#[derive(FromPrimitive, Clone, Copy)]
/// Possible values for the VEX.m-mmmm field
pub enum VEXLeadingOpcodeByte {
    Lob0F = 0x1,
    Lob0F38 = 0x2,
    Lob0F3A = 0x3,
}

#[derive(FromPrimitive, Clone, Copy)]
pub enum XOPMapSelect {
    Select8 = 0x8,
    Select9 = 0x9,
    SelectA = 0xA,
}

#[derive(FromPrimitive, Clone, Copy)]
/// Possible values for the VEX.pp/EVEX.pp field
pub enum VEXPrefixCode {
    PrefixNone = 0x0,
    Prefix66 = 0x1,
    PrefixF3 = 0x2,
    PrefixF2 = 0x3,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum VectorExtensionType {
    NoVEX_XOP = 0x0,
    VEX_2B = 0x1,
    VEX_3B = 0x2,
    EVEX = 0x3,
    XOP = 0x4,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ModRMDecisionType {
    OneEntry = 0x0,
    SplitRM = 0x1,
    SplitMisc = 0x2,
    SplitReg = 0x3,
    Full = 0x4,
}

pub struct ContextDecision {
    pub opcodeDecision: [ModRMDecision; 256],
}

#[derive(Debug)]
pub struct ModRMDecision {
    pub modrmType: ModRMDecisionType,
    pub instrUids: usize,
}

/// Sets the adjust flag AF after an addition. Assumes res := a + ?.
pub fn set_adj_flag(res: &Variable, a: &Value) -> Result<Vec<Statement>> {
    rreil! {
        mov nibble_res:4, (res)
        mov nibble_a:4, (a)
        cmpltu AF:1, nibble_res:4, nibble_a:4
    }
}

/// Sets the adjust flag AF after a subtraction. Assumes res := a - ?.
pub fn set_sub_adj_flag(res: &Variable, a: &Value) -> Result<Vec<Statement>> {
    rreil! {
        mov nibble_res:4, (res)
        mov nibble_a:4, (a)
        cmpltu AF:1, nibble_a:4, nibble_res:4
    }
}

/// Sets the parity flag PF.
pub fn set_parity_flag(res: Variable, il: &mut Vec<Statement>) -> Result<()> {
    il.extend(rreil! {
           mov pres:8, (res)
           mov half_res:8, res:8
           mov PF:1, half_res:1
           sel/1/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/2/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/3/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/4/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/5/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/6/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           sel/7/1 b:1, half_res:8
           xor PF:1, PF:1, b:1
           xor PF:1, PF:1, [1]:1
    }?);
    Ok(())
}

/// Sets the carry flag CF after an addition. Assumes res := a + ?.
pub fn set_carry_flag(
    res: Variable,
    a: Value,
    _: Value,
    _: usize,
    il: &mut Vec<Statement>,
) -> Result<()> {
    il.extend(rreil! {
           cmpeq cf1:1, (res), (a)
           cmpltu cf2:1, (res), (a)
           //and cf1:1, cf1:1, CF:1
           or CF:1, cf1:1, cf2:1
    }?);
    Ok(())
}

/// Sets the carry flag CF after a subtraction. Assumes res := a + ?.
pub fn set_sub_carry_flag(res: &Variable, a: &Value) -> Result<Vec<Statement>> {
    rreil! {
        cmpeq cf1:1, (res), (a)
        cmpltu cf2:1, (a), (res)
        //and cf1:1, cf1:1, CF:1
        or CF:1, cf1:1, cf2:1
    }
}

/// Sets the overflow flag OF. Assumes res := a ? b.
pub fn set_overflow_flag(
    res: Variable,
    a: Value,
    b: Value,
    sz: u16,
    il: &mut Vec<Statement>,
) -> Result<()> {
    /*
     * The rules for turning on the overflow flag in binary/integer math are two:
     *
     * 1. If the sum of two numbers with the sign bits off yields a result number
     *    with the sign bit on, the "overflow" flag is turned on.
     *
     *    0100 + 0100 = 1000 (overflow flag is turned on)
     *
     * 2. If the sum of two numbers with the sign bits on yields a result number
     *    with the sign bit off, the "overflow" flag is turned on.
     *
     *    1000 + 1000 = 0000 (overflow flag is turned on)
     *
     * Otherwise, the overflow flag is turned off.
     */
    let msb = sz - 1;

    il.extend(rreil! {
        xor of1:sz, (a), (b)
        xor of1:sz, of1:sz, [0xffffffffffffffff]:sz
        xor of2:sz, (a), (res)
        sel/msb/1 a1:1, of1:sz
        sel/msb/1 a2:1, of2:sz
        and OF:1, a1:1, a2:1
    }?);
    Ok(())
}

/// Assumes res := a ? b
pub fn set_sub_overflow_flag(
    res: Variable,
    a: Value,
    b: Value,
    sz: u16,
    il: &mut Vec<Statement>,
) -> Result<()> {
    /*
     * The rules for turning on the overflow flag in binary/integer math are two:
     *
     * 1. If the sum of two numbers with the sign bits off yields a result number
     *    with the sign bit on, the "overflow" flag is turned on.
     *
     *    0100 + 0100 = 1000 (overflow flag is turned on)
     *
     * 2. If the sum of two numbers with the sign bits on yields a result number
     *    with the sign bit off, the "overflow" flag is turned on.
     *
     *    1000 + 1000 = 0000 (overflow flag is turned on)
     *
     * Otherwise, the overflow flag is turned off.
     */
    let msb = sz - 1;

    il.extend(rreil! {
        xor of1:sz, (a), (b)
        xor of2:sz, (b), (res)
        xor of2:sz, of2:sz, [0xffffffffffffffff]:sz
        sel/msb/1 a1:1, of1:sz
        sel/msb/1 a2:1, of2:sz
        and OF:1, a1:1, a2:1
    }?);
    Ok(())
}
