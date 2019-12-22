//===-- X86DisassemblerDecoder.cpp - Disassembler decoder -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is part of the X86 Disassembler.
// It contains the implementation of the instruction decoder.
// Documentation for the disassembler can be found in X86Disassembler.h.
//
//===----------------------------------------------------------------------===//

#![allow(non_snake_case)]

use std::cmp;
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};
use num_traits::FromPrimitive;
use p8n_types::{Name, Result, Statement, Value, Variable, Constant};

use crate::common::{
    EABase, EADisplacement, InstructionContext, JumpSpec, ModRMDecisionType, Mode, OpcodeType,
    OperandEncoding, OperandSpecifier, OperandType, Reg, SIBBase, SIBIndex, SegmentOverride,
    VEXLeadingOpcodeByte, VEXPrefixCode, VectorExtensionType, XOPMapSelect,
};
use crate::semantics::SEMANTICS;
use crate::tables::{
    INSTRUCTION_CONTEXTS, INSTRUCTION_NAMES, INSTRUCTION_SPECIFIER, MODRM_TABLE, OPERAND_SETS,
    X86_DISASSEMBLER_3DNOW_OPCODES, X86_DISASSEMBLER_ONE_BYTE_OPCODES,
    X86_DISASSEMBLER_THREE_BYTE_38_OPCODES, X86_DISASSEMBLER_THREE_BYTE_3A_OPCODES,
    X86_DISASSEMBLER_TWO_BYTE_OPCODES, X86_DISASSEMBLER_XOP8_OPCODES,
    X86_DISASSEMBLER_XOP9_OPCODES, X86_DISASSEMBLER_XOPA_OPCODES,
};

pub const ATTR_NONE: usize = 0x00;
pub const ATTR_64BIT: usize = (0x1 << 0);
pub const ATTR_XS: usize = (0x1 << 1);
pub const ATTR_XD: usize = (0x1 << 2);
pub const ATTR_REXW: usize = (0x1 << 3);
pub const ATTR_OPSIZE: usize = (0x1 << 4);
pub const ATTR_ADSIZE: usize = (0x1 << 5);
pub const ATTR_VEX: usize = (0x1 << 6);
pub const ATTR_VEXL: usize = (0x1 << 7);
pub const ATTR_EVEX: usize = (0x1 << 8);
pub const ATTR_EVEXL: usize = (0x1 << 9);
pub const ATTR_EVEXL2: usize = (0x1 << 10);
pub const ATTR_EVEXK: usize = (0x1 << 11);
pub const ATTR_EVEXKZ: usize = (0x1 << 12);
pub const ATTR_EVEXB: usize = (0x1 << 13);

pub const SEGMENT_REGISTERS: &'static [Option<Reg>; 7] = &[
    None, // SEG_OVERRIDE_NONE
    Some(Reg::CS),
    Some(Reg::SS),
    Some(Reg::DS),
    Some(Reg::ES),
    Some(Reg::FS),
    Some(Reg::GS),
];

// Accessor functions for various fields of an Intel instruction
fn modFromModRM(modrm: u8) -> u8 {
    (((modrm) & 0xc0) >> 6)
}
fn regFromModRM(modrm: u8) -> u8 {
    (((modrm) & 0x38) >> 3)
}
fn rmFromModRM(modrm: u8) -> u8 {
    ((modrm) & 0x7)
}
fn scaleFromSIB(sib: u8) -> u8 {
    (((sib) & 0xc0) >> 6)
}
fn indexFromSIB(sib: u8) -> u8 {
    (((sib) & 0x38) >> 3)
}
fn baseFromSIB(sib: u8) -> u8 {
    ((sib) & 0x7)
}
fn wFromREX(rex: u8) -> u8 {
    (((rex) & 0x8) >> 3)
}
fn rFromREX(rex: u8) -> u8 {
    (((rex) & 0x4) >> 2)
}
fn xFromREX(rex: u8) -> u8 {
    (((rex) & 0x2) >> 1)
}
fn bFromREX(rex: u8) -> u8 {
    ((rex) & 0x1)
}

fn rFromEVEX2of4(evex: u8) -> u8 {
    (((!(evex)) & 0x80) >> 7)
}
fn xFromEVEX2of4(evex: u8) -> u8 {
    (((!(evex)) & 0x40) >> 6)
}
fn bFromEVEX2of4(evex: u8) -> u8 {
    (((!(evex)) & 0x20) >> 5)
}
fn r2FromEVEX2of4(evex: u8) -> u8 {
    (((!(evex)) & 0x10) >> 4)
}
fn mmFromEVEX2of4(evex: u8) -> u8 {
    ((evex) & 0x3)
}
fn wFromEVEX3of4(evex: u8) -> u8 {
    (((evex) & 0x80) >> 7)
}
fn vvvvFromEVEX3of4(evex: u8) -> u8 {
    (((!(evex)) & 0x78) >> 3)
}
fn ppFromEVEX3of4(evex: u8) -> u8 {
    ((evex) & 0x3)
}
fn zFromEVEX4of4(evex: u8) -> u8 {
    (((evex) & 0x80) >> 7)
}
fn l2FromEVEX4of4(evex: u8) -> u8 {
    (((evex) & 0x40) >> 6)
}
fn lFromEVEX4of4(evex: u8) -> u8 {
    (((evex) & 0x20) >> 5)
}
fn bFromEVEX4of4(evex: u8) -> u8 {
    (((evex) & 0x10) >> 4)
}
fn v2FromEVEX4of4(evex: u8) -> u8 {
    (((!evex) & 0x8) >> 3)
}
fn aaaFromEVEX4of4(evex: u8) -> u8 {
    ((evex) & 0x7)
}

fn rFromVEX2of3(vex: u8) -> u8 {
    (((!(vex)) & 0x80) >> 7)
}
fn xFromVEX2of3(vex: u8) -> u8 {
    (((!(vex)) & 0x40) >> 6)
}
fn bFromVEX2of3(vex: u8) -> u8 {
    (((!(vex)) & 0x20) >> 5)
}
fn mmmmmFromVEX2of3(vex: u8) -> u8 {
    ((vex) & 0x1f)
}
fn wFromVEX3of3(vex: u8) -> u8 {
    (((vex) & 0x80) >> 7)
}
fn vvvvFromVEX3of3(vex: u8) -> u8 {
    (((!(vex)) & 0x78) >> 3)
}
fn lFromVEX3of3(vex: u8) -> u8 {
    (((vex) & 0x4) >> 2)
}
fn ppFromVEX3of3(vex: u8) -> u8 {
    ((vex) & 0x3)
}

fn rFromVEX2of2(vex: u8) -> u8 {
    (((!(vex)) & 0x80) >> 7)
}
fn vvvvFromVEX2of2(vex: u8) -> u8 {
    (((!(vex)) & 0x78) >> 3)
}
fn lFromVEX2of2(vex: u8) -> u8 {
    (((vex) & 0x4) >> 2)
}
fn ppFromVEX2of2(vex: u8) -> u8 {
    ((vex) & 0x3)
}

fn rFromXOP2of3(xop: u8) -> u8 {
    (((!(xop)) & 0x80) >> 7)
}
fn xFromXOP2of3(xop: u8) -> u8 {
    (((!(xop)) & 0x40) >> 6)
}
fn bFromXOP2of3(xop: u8) -> u8 {
    (((!(xop)) & 0x20) >> 5)
}
fn mmmmmFromXOP2of3(xop: u8) -> u8 {
    ((xop) & 0x1f)
}
fn wFromXOP3of3(xop: u8) -> u8 {
    (((xop) & 0x80) >> 7)
}
fn vvvvFromXOP3of3(vex: u8) -> u8 {
    (((!(vex)) & 0x78) >> 3)
}
fn lFromXOP3of3(xop: u8) -> u8 {
    (((xop) & 0x4) >> 2)
}
fn ppFromXOP3of3(xop: u8) -> u8 {
    ((xop) & 0x3)
}

/// The x86 internal instruction, which is produced by the decoder.
pub struct Instruction<'a> {
    // General instruction information
    buffer: &'a [u8],
    pub cursor: usize,

    /// The mode to disassemble for (64-bit, protected, real)
    mode: Mode,

    // Prefix state
    /// The possible mandatory prefix
    mandatory_pfx: Option<u8>,
    /// The value of the vector extension prefix(EVEX/VEX/XOP), if present
    vec_ext_pfx: Option<[u8; 4]>,
    /// The type of the vector extension prefix
    vec_ext_ty: VectorExtensionType,
    /// The value of the REX prefix, if present
    rex_pfx: Option<u8>,
    /// The segment override type
    segmentOverride: SegmentOverride,
    /// 1 if the prefix byte, 0xf2 or 0xf3 is xacquire or xrelease
    xAcquireRelease: bool,

    /// Address-size override
    hasAdSize: bool,
    /// Operand-size override
    hasOpSize: bool,
    /// Lock prefix
    hasLockPrefix: bool,
    /// The repeat prefix if any
    repeatPrefix: Option<u8>,

    /// Sizes of various critical pieces of data, in bytes
    registerSize: usize,
    addressSize: u8,
    displacementSize: u8,
    immediateSize: u8,

    /// Offsets from the start of the instruction to the pieces of data, which is
    /// needed to find relocation entries for adding symbolic operands.
    displacementOffset: u8,
    immediateOffset: u8,

    // opcode state
    /// The last byte of the opcode, not counting any ModR/M extension
    opcode: u8,

    // decode state

    // The type of opcode, used for indexing into the array of decode tables
    opcodeType: OpcodeType,
    // The instruction ID, extracted from the decode table
    pub instructionID: usize,
    // The specifier for the instruction, from the instruction info table
    pub spec: usize,

    // state for additional bytes, consumed during operand decode.  Pattern:
    // consumed___ indicates that the byte was already consumed and does not
    // need to be consumed again.

    // The VEX.vvvv field, which contains a third register operand for some AVX
    // instructions.
    vvvv: Reg,

    // The writemask for AVX-512 instructions which is contained in EVEX.aaa
    writemask: Reg,

    // The ModR/M byte, which contains most register operands and some portion of
    // all memory operands.
    consumedModRM: bool,
    modrm: u8,

    // The SIB byte, used for more complex 32- or 64-bit memory operands
    consumedSIB: bool,
    sib: u8,

    // The displacement, used for memory operands
    consumedDisplacement: bool,
    displacement: u32,

    // Immediates.  There can be two in some cases
    numImmediatesConsumed: u8,
    numImmediatesTranslated: u8,
    immediates: [u64; 2],

    // A register or immediate operand encoded into the opcode
    opcodeRegister: Reg,

    // Portions of the ModR/M byte

    // These fields determine the allowable values for the ModR/M fields, which
    // depend on operand and address widths.
    ea_reg_base: EABase,
    reg_base: Reg,

    // The Mod and R/M fields can encode a base for an effective address, or a
    // register.  These are separated into two fields here.
    ea_base: EABase,
    ea_displ: EADisplacement,
    // The reg field always encodes a register
    reg: Reg,

    // SIB state
    sib_idx_base: SIBIndex,
    sib_index: SIBIndex,
    sib_scale: u8,
    sib_base: SIBBase,

    // Embedded rounding control.
    RC: u8,

    pub operands: Option<&'static [OperandSpecifier]>,

    pub semantics: Option<fn(&mut Instruction, &mut Vec<Statement>) -> Result<JumpSpec>>,
}

impl<'a> Instruction<'a> {
    pub fn new(mode: Mode, buf: &'a [u8]) -> Option<Self> {
        let mut ret = Instruction {
            buffer: buf,
            cursor: 0,
            mode: mode,
            mandatory_pfx: None,
            vec_ext_pfx: None,
            vec_ext_ty: VectorExtensionType::NoVEX_XOP,
            rex_pfx: None,
            segmentOverride: SegmentOverride::None,
            xAcquireRelease: false,
            hasAdSize: false,
            hasOpSize: false,
            hasLockPrefix: false,
            repeatPrefix: None,
            registerSize: 0,
            addressSize: 0,
            displacementSize: 0,
            immediateSize: 0,
            displacementOffset: 0,
            immediateOffset: 0,
            opcode: 0,
            opcodeType: OpcodeType::OneByte,
            instructionID: 0,
            spec: 0,
            vvvv: Reg::AL,
            writemask: Reg::AL,
            consumedModRM: false,
            modrm: 0,
            consumedSIB: false,
            sib: 0,
            consumedDisplacement: false,
            displacement: 0,
            numImmediatesConsumed: 0,
            numImmediatesTranslated: 0,
            immediates: [0, 0],
            opcodeRegister: Reg::AL,
            ea_reg_base: EABase::BaseNone,
            reg_base: Reg::AL,
            ea_base: EABase::BaseNone,
            ea_displ: EADisplacement::DispNone,
            reg: Reg::AL,
            sib_idx_base: SIBIndex::None,
            sib_index: SIBIndex::None,
            sib_scale: 0,
            sib_base: SIBBase::None,
            RC: 0,
            operands: None,
            semantics: None,
        };

        if ret.decode_instruction() {
            Some(ret)
        } else {
            None
        }
    }

    fn lookAtByte(&mut self, byte: &mut u8) -> bool {
        match self.buffer.get(self.cursor) {
            Some(&b) => {
                *byte = b;
                return true;
            }
            None => {
                return false;
            }
        }
    }

    /*
     * consume_byte - Uses the reader function provided by the user to consume one
     *   byte from the instruction's memory and advance the cursor.
     *
     * @param insn  - The instruction with the reader function to use.  The cursor
     *                for this instruction is advanced.
     * @param byte  - A pointer to a pre-allocated memory buffer to be populated
     *                with the data read.
     * @return      - 0 if the read was successful; nonzero otherwise.
     */
    fn consume_byte(&mut self, byte: &mut u8) -> bool {
        match self.buffer.get(self.cursor) {
            Some(&b) => {
                *byte = b;
                self.cursor += 1;
                true
            }
            None => false,
        }
    }

    fn unconsume_byte(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn is_rex(&self, prefix: u8) -> bool {
        self.mode == Mode::Long && prefix >= 0x40 && prefix <= 0x4f
    }

    /*
     * set_prefix_present - Marks that a particular prefix is present as mandatory
     *
     * @param insn      - The instruction to be marked as having the prefix.
     * @param prefix    - The prefix that is present.
     */
    fn set_prefix_present(&mut self, prefix: u8) {
        match prefix {
            0xf0 => {
                self.hasLockPrefix = true;
            }
            0xf2 | 0xf3 => {
                let mut next_byte = 0;
                if !self.lookAtByte(&mut next_byte) {
                    return;
                }
                // TODO:
                //  1. There could be several 0x66
                //  2. if (next_byte == 0x66) and nextNextByte != 0x0f then
                //      it's not mandatory prefix
                //  3. if (next_byte >= 0x40 && next_byte <= 0x4f) it's REX and we need
                //     0x0f exactly after it to be mandatory prefix
                if self.is_rex(next_byte) || next_byte == 0x0f || next_byte == 0x66 {
                    // The last of 0xf2 /0xf3 is mandatory prefix
                    self.mandatory_pfx = Some(prefix);
                }
                self.repeatPrefix = Some(prefix);
            }
            0x66 => {
                let mut next_byte = 0;
                if !self.lookAtByte(&mut next_byte) {
                    return;
                }
                // 0x66 can't overwrite existing mandatory prefix and should be ignored
                if self.mandatory_pfx.is_none() && (next_byte == 0x0f || self.is_rex(next_byte)) {
                    self.mandatory_pfx = Some(prefix);
                }
            }
            _ => {}
        }
    }

    /*
     * readPrefixes - Consumes all of an instruction's prefix bytes, and marks the
     *   instruction as having them.  Also sets the instruction's default operand,
     *   address, and other relevant data sizes to report operands correctly.
     *
     * @param insn  - The instruction whose prefixes are to be read.
     * @return      - 0 if the instruction could be read until the end of the prefix
     *                bytes, and no prefixes conflicted; nonzero otherwise.
     */
    fn read_prefixes(&mut self) -> bool {
        let mut isPrefix = true;
        let mut byte = 0;
        let mut next_byte = 0;

        eprintln!("read_prefixes()");

        while isPrefix {
            /* If we fail reading prefixes, just stop here and let the opcode reader deal with it */
            if !self.consume_byte(&mut byte) {
                break;
            }

            /*
             * If the byte is a LOCK/REP/REPNE prefix and not a part of the opcode, then
             * break and let it be disassembled as a normal "instruction".
             */
            if self.cursor == 1 && byte == 0xf0 {
                // LOCK
                break;
            }

            if (byte == 0xf2 || byte == 0xf3) && self.lookAtByte(&mut next_byte) {
                /*
                 * If the byte is 0xf2 or 0xf3, and any of the following conditions are
                 * met:
                 * - it is followed by a LOCK (0xf0) prefix
                 * - it is followed by an xchg instruction
                 * then it should be disassembled as a xacquire/xrelease not repne/rep.
                 */
                if next_byte == 0xf0 || ((next_byte & 0xfe) == 0x86 || (next_byte & 0xf8) == 0x90) {
                    self.xAcquireRelease = true;
                    if !(byte == 0xf3 && next_byte == 0x90) {
                        // PAUSE instruction support
                        break;
                    }
                }
                /*
                 * Also if the byte is 0xf3, and the following condition is met:
                 * - it is followed by a "mov mem, reg" (opcode 0x88/0x89) or
                 *                       "mov mem, imm" (opcode 0xc6/0xc7) instructions.
                 * then it should be disassembled as an xrelease not rep.
                 */
                if byte == 0xf3
                    && (next_byte == 0x88
                        || next_byte == 0x89
                        || next_byte == 0xc6
                        || next_byte == 0xc7)
                {
                    self.xAcquireRelease = true;
                    if next_byte != 0x90 {
                        // PAUSE instruction support
                        break;
                    }
                }
                if self.is_rex(next_byte) {
                    let mut nnext_byte = 0;
                    // Go to REX prefix after the current one
                    if !self.consume_byte(&mut nnext_byte) {
                        return false;
                    }
                    // We should be able to read next byte after REX prefix
                    if !self.lookAtByte(&mut nnext_byte) {
                        return false;
                    }
                    self.unconsume_byte();
                }
            }

            match byte {
                0xf0 |  /* LOCK */
                0xf2 |  /* REPNE/REPNZ */
                0xf3 => {  /* REP or REPE/REPZ */
                    self.set_prefix_present(byte);
                }
                0x2e |  /* CS segment override -OR- Branch not taken */
                0x36 |  /* SS segment override -OR- Branch taken */
                0x3e |  /* DS segment override */
                0x26 |  /* ES segment override */
                0x64 |  /* FS segment override */
                0x65 => { /* GS segment override */
                    match byte {
                        0x2e => {
                            self.segmentOverride = SegmentOverride::CS;
                        }
                        0x36 => {
                            self.segmentOverride = SegmentOverride::SS;
                        }
                        0x3e => {
                            self.segmentOverride = SegmentOverride::DS;
                        }
                        0x26 => {
                            self.segmentOverride = SegmentOverride::ES;
                        }
                        0x64 => {
                            self.segmentOverride = SegmentOverride::FS;
                        }
                        0x65 => {
                            self.segmentOverride = SegmentOverride::GS;
                        }
                        _ => {
                            eprintln!("Unhandled override");
                        }
                    }

                    self.set_prefix_present(byte);
                }
                0x66 => { /* Operand-size override */
                    self.hasOpSize = true;
                    self.set_prefix_present(byte);
                }
                0x67 => { /* Address-size override */
                    self.hasAdSize = true;
                    self.set_prefix_present(byte);
                }
                _ => {   /* Not a prefix byte */
                    isPrefix = false;
                }
            }

            if isPrefix {
                eprintln!("Found prefix {:#x}", byte);
            }
        }

        self.vec_ext_ty = VectorExtensionType::NoVEX_XOP;

        match byte {
            0x62 => {
                let mut byte1 = 0;
                let mut byte2 = 0;

                if !self.consume_byte(&mut byte1) {
                    eprintln!("Couldn't read second byte of EVEX prefix");
                    return false;
                }

                if !self.lookAtByte(&mut byte2) {
                    eprintln!("Couldn't read third byte of EVEX prefix");
                    return false;
                }

                if (self.mode == Mode::Long || (byte1 & 0xc0) == 0xc0)
                    && ((!byte1 & 0xc) == 0xc)
                    && ((byte2 & 0x4) == 0x4)
                {
                    self.vec_ext_ty = VectorExtensionType::EVEX;
                } else {
                    self.unconsume_byte(); /* unconsume byte1 */
                    self.unconsume_byte(); /* unconsume byte  */
                }

                if self.vec_ext_ty == VectorExtensionType::EVEX {
                    let mut nnext_byte = 0;
                    if !self.consume_byte(&mut nnext_byte) {
                        eprintln!("Couldn't read third byte of EVEX prefix");
                        return false;
                    }

                    let mut nnnext_byte = 0;
                    if !self.consume_byte(&mut nnnext_byte) {
                        eprintln!("Couldn't read fourth byte of EVEX prefix");
                        return false;
                    }

                    let vex_pfx = [byte, byte1, nnext_byte, nnnext_byte];
                    self.vec_ext_pfx = Some(vex_pfx.clone());

                    /* We simulate the REX prefix for simplicity's sake */
                    if self.mode == Mode::Long {
                        self.rex_pfx = Some(
                            0x40 | (wFromEVEX3of4(vex_pfx[2]) << 3)
                                | (rFromEVEX2of4(vex_pfx[1]) << 2)
                                | (xFromEVEX2of4(vex_pfx[1]) << 1)
                                | (bFromEVEX2of4(vex_pfx[1]) << 0),
                        );
                    }

                    eprintln!(
                        "Found EVEX prefix {:#x} {:#x} {:#x} {:#x}",
                        vex_pfx[0], vex_pfx[1], vex_pfx[2], vex_pfx[3]
                    );
                }
            }
            0xc4 => {
                let mut byte1 = 0;

                if !self.lookAtByte(&mut byte1) {
                    eprintln!("Couldn't read second byte of VEX");
                    return false;
                }

                if self.mode == Mode::Long || (byte1 & 0xc0) == 0xc0 {
                    self.vec_ext_ty = VectorExtensionType::VEX_3B;
                } else {
                    self.unconsume_byte();
                }

                if self.vec_ext_ty == VectorExtensionType::VEX_3B && self.vec_ext_pfx.is_none() {
                    let mut nnext_byte = 0;
                    let mut nnnext_byte = 0;

                    self.consume_byte(&mut nnext_byte);
                    self.consume_byte(&mut nnnext_byte);

                    let vex_pfx = [byte, nnext_byte, nnnext_byte, 0];
                    self.vec_ext_pfx = Some(vex_pfx);

                    /* We simulate the REX prefix for simplicity's sake */
                    if self.mode == Mode::Long {
                        self.rex_pfx = Some(
                            0x40 | (wFromVEX3of3(vex_pfx[2]) << 3)
                                | (rFromVEX2of3(vex_pfx[1]) << 2)
                                | (xFromVEX2of3(vex_pfx[1]) << 1)
                                | (bFromVEX2of3(vex_pfx[1]) << 0),
                        );
                    }

                    eprintln!(
                        "Found VEX prefix {:#x} {:#x} {:#x}",
                        vex_pfx[0], vex_pfx[1], vex_pfx[2]
                    );
                }
            }
            0xc5 => {
                let mut byte1 = 0;

                if !self.lookAtByte(&mut byte1) {
                    eprintln!("Couldn't read second byte of VEX");
                    return false;
                }

                if self.mode == Mode::Long || (byte1 & 0xc0) == 0xc0 {
                    self.vec_ext_ty = VectorExtensionType::VEX_2B;
                } else {
                    self.unconsume_byte();
                }

                if self.vec_ext_ty == VectorExtensionType::VEX_2B && self.vec_ext_pfx.is_none() {
                    let mut nnext_byte = 0;
                    self.consume_byte(&mut nnext_byte);
                    self.vec_ext_pfx = Some([byte, nnext_byte, 0, 0]);

                    if self.mode == Mode::Long {
                        self.rex_pfx = Some(0x40 | (rFromVEX2of2(nnext_byte) << 2));
                    }
                    if ppFromVEX2of2(nnext_byte) == VEXPrefixCode::Prefix66 as u8 {
                        self.hasOpSize = true;
                    }

                    let vex_pfx = self.vec_ext_pfx.clone().unwrap();
                    eprintln!("Found VEX prefix {:#x} {:#x}", vex_pfx[0], vex_pfx[1]);
                }
            }
            0x8f => {
                let mut byte1 = 0;

                if !self.lookAtByte(&mut byte1) {
                    eprintln!("Couldn't read second byte of XOP");
                    return false;
                }

                if (byte1 & 0x38) != 0x0 {
                    /* 0 in these 3 bits is a POP instruction. */
                    self.vec_ext_ty = VectorExtensionType::XOP;
                } else {
                    self.unconsume_byte();
                }

                if self.vec_ext_ty == VectorExtensionType::XOP && self.vec_ext_pfx.is_some() {
                    self.vec_ext_pfx.as_mut().unwrap()[0] = byte;

                    let mut nnext_byte = 0;
                    self.consume_byte(&mut nnext_byte);
                    self.vec_ext_pfx.as_mut().unwrap()[1] = nnext_byte;
                    self.consume_byte(&mut nnext_byte);
                    self.vec_ext_pfx.as_mut().unwrap()[2] = nnext_byte;

                    /* We simulate the REX prefix for simplicity's sake */
                    let vex_pfx = self.vec_ext_pfx.clone().unwrap();
                    if self.mode == Mode::Long {
                        self.rex_pfx = Some(
                            0x40 | (wFromXOP3of3(vex_pfx[2]) << 3)
                                | (rFromXOP2of3(vex_pfx[1]) << 2)
                                | (xFromXOP2of3(vex_pfx[1]) << 1)
                                | (bFromXOP2of3(vex_pfx[1]) << 0),
                        );
                    }

                    if ppFromXOP3of3(vex_pfx[2]) == VEXPrefixCode::Prefix66 as u8 {
                        self.hasOpSize = true;
                    }

                    eprintln!("Found XOP prefix {:?}", self.vec_ext_pfx);
                }
            }
            byte if self.is_rex(byte) => {
                if !self.lookAtByte(&mut next_byte) {
                    return false;
                }
                self.rex_pfx = Some(byte);
                eprintln!("Found REX prefix {:#x}", byte);
            }
            _ => {
                self.unconsume_byte();
            }
        }

        match self.mode {
            Mode::Real => {
                self.registerSize = if self.hasOpSize { 4 } else { 2 };
                self.addressSize = if self.hasAdSize { 4 } else { 2 };
                self.displacementSize = if self.hasAdSize { 4 } else { 2 };
                self.immediateSize = if self.hasOpSize { 4 } else { 2 };
            }
            Mode::Protected => {
                self.registerSize = if self.hasOpSize { 2 } else { 4 };
                self.addressSize = if self.hasAdSize { 2 } else { 4 };
                self.displacementSize = if self.hasAdSize { 2 } else { 4 };
                self.immediateSize = if self.hasOpSize { 2 } else { 4 };
            }
            Mode::Long => {
                if self.rex_pfx.is_some() && wFromREX(self.rex_pfx.unwrap()) != 0 {
                    self.registerSize = 8;
                    self.addressSize = if self.hasAdSize { 4 } else { 8 };
                    self.displacementSize = 4;
                    self.immediateSize = 4;
                } else {
                    self.registerSize = if self.hasOpSize { 2 } else { 4 };
                    self.addressSize = if self.hasAdSize { 4 } else { 8 };
                    self.displacementSize = if self.hasOpSize { 2 } else { 4 };
                    self.immediateSize = if self.hasOpSize { 2 } else { 4 };
                }
            }
        }

        true
    }

    /*
     * readOpcode - Reads the opcode (excepting the ModR/M byte in the case of
     *   extended or escape opcodes).
     */
    fn read_opcode(&mut self) -> bool {
        /* Determine the length of the primary opcode */

        eprintln!("read_opcode()");

        self.opcodeType = OpcodeType::OneByte;
        let mut opcode = 0;

        if self.vec_ext_ty == VectorExtensionType::EVEX && self.vec_ext_pfx.is_some() {
            let rc =
                match VEXLeadingOpcodeByte::from_u8(mmFromEVEX2of4(self.vec_ext_pfx.unwrap()[1])) {
                    Some(VEXLeadingOpcodeByte::Lob0F) => {
                        self.opcodeType = OpcodeType::TwoByte;
                        self.consume_byte(&mut opcode)
                    }
                    Some(VEXLeadingOpcodeByte::Lob0F38) => {
                        self.opcodeType = OpcodeType::ThreeByte_38;
                        self.consume_byte(&mut opcode)
                    }
                    Some(VEXLeadingOpcodeByte::Lob0F3A) => {
                        self.opcodeType = OpcodeType::ThreeByte_3A;
                        self.consume_byte(&mut opcode)
                    }
                    _ => {
                        eprintln!(
                            "Unhandled mm field for instruction ({:#x})",
                            mmFromEVEX2of4(self.vec_ext_pfx.unwrap()[1])
                        );
                        return false;
                    }
                };

            if rc {
                self.opcode = opcode;
            }
            return rc;
        } else if self.vec_ext_ty == VectorExtensionType::VEX_3B && self.vec_ext_pfx.is_some() {
            let rc =
                match VEXLeadingOpcodeByte::from_u8(mmmmmFromVEX2of3(self.vec_ext_pfx.unwrap()[1]))
                {
                    Some(VEXLeadingOpcodeByte::Lob0F) => {
                        self.opcodeType = OpcodeType::TwoByte;
                        self.consume_byte(&mut opcode)
                    }
                    Some(VEXLeadingOpcodeByte::Lob0F38) => {
                        self.opcodeType = OpcodeType::ThreeByte_38;
                        self.consume_byte(&mut opcode)
                    }
                    Some(VEXLeadingOpcodeByte::Lob0F3A) => {
                        self.opcodeType = OpcodeType::ThreeByte_3A;
                        self.consume_byte(&mut opcode)
                    }
                    _ => {
                        eprintln!(
                            "Unhandled m-mmmm field for instruction ({:#x})",
                            mmmmmFromVEX2of3(self.vec_ext_pfx.unwrap()[1])
                        );
                        return false;
                    }
                };

            if rc {
                self.opcode = opcode;
            }
            return rc;
        } else if self.vec_ext_ty == VectorExtensionType::VEX_2B && self.vec_ext_pfx.is_some() {
            self.opcodeType = OpcodeType::TwoByte;
            if self.consume_byte(&mut opcode) {
                self.opcode = opcode;
                return true;
            } else {
                return false;
            }
        } else if self.vec_ext_ty == VectorExtensionType::XOP && self.vec_ext_pfx.is_some() {
            let rc = match XOPMapSelect::from_u8(mmmmmFromXOP2of3(self.vec_ext_pfx.unwrap()[1])) {
                Some(XOPMapSelect::Select8) => {
                    self.opcodeType = OpcodeType::XOP8_Map;
                    self.consume_byte(&mut opcode)
                }
                Some(XOPMapSelect::Select9) => {
                    self.opcodeType = OpcodeType::XOP9_Map;
                    self.consume_byte(&mut opcode)
                }
                Some(XOPMapSelect::SelectA) => {
                    self.opcodeType = OpcodeType::XOPA_Map;
                    self.consume_byte(&mut opcode)
                }
                _ => {
                    eprintln!(
                        "Unhandled m-mmmm field for instruction ({:#x})",
                        mmmmmFromVEX2of3(self.vec_ext_pfx.unwrap()[1])
                    );
                    return false;
                }
            };

            if rc {
                self.opcode = opcode;
            }
            return rc;
        }

        let mut current = 0;

        if !self.consume_byte(&mut current) {
            return false;
        }

        if current == 0x0f {
            eprintln!("Found a two-byte escape prefix ({:x})", current);

            if !self.consume_byte(&mut current) {
                return false;
            }

            if current == 0x38 {
                eprintln!("Found a three-byte escape prefix ({:x})", current);

                if !self.consume_byte(&mut current) {
                    return false;
                }

                self.opcodeType = OpcodeType::ThreeByte_38;
            } else if current == 0x3a {
                eprintln!("Found a three-byte escape prefix ({:x})", current);

                if !self.consume_byte(&mut current) {
                    return false;
                }

                self.opcodeType = OpcodeType::ThreeByte_3A;
            } else if current == 0x0f {
                eprintln!("Found a 3dnow escape prefix ({:x})", current);

                // Consume operands before the opcode to comply with the 3DNow encoding
                if !self.read_modrm() {
                    return false;
                }

                if !self.consume_byte(&mut current) {
                    return false;
                }

                self.opcodeType = OpcodeType::ThreeDNow_Map;
            } else {
                eprintln!("Didn't find a three-byte escape prefix");

                self.opcodeType = OpcodeType::TwoByte;
            }
        } else if self.mandatory_pfx.is_some() {
            // The opcode with mandatory prefix must start with opcode escape.
            // If not it's legacy repeat prefix
            self.mandatory_pfx = None;
        }

        /*
         * At this point we have consumed the full opcode.
         * Anything we consume from here on must be unconsumed.
         */

        self.opcode = current;
        true
    }

    /*
     * read_operands - Consults the specifier for an instruction and consumes all
     *   operands for that instruction, interpreting them as it goes.
     *
     * @param insn  - The instruction whose operands are to be read and interpreted.
     * @return      - 0 if all operands could be read; nonzero otherwise.
     */
    fn read_operands(&mut self) -> bool {
        let mut sawRegImm = false;

        eprintln!("read_operands()");

        /* If non-zero vvvv specified, need to make sure one of the operands
        uses it. */
        let hasVVVV = self.read_vvvv();
        let mut needVVVV = hasVVVV && (self.vvvv as usize != 0);

        if let Some(ops) = OPERAND_SETS.get(self.spec) {
            for spec in ops {
                eprintln!("{:?}", spec.encoding);

                match spec.encoding {
                    OperandEncoding::NONE | OperandEncoding::SI | OperandEncoding::DI => {}

                    OperandEncoding::VSIB
                    | OperandEncoding::VSIB_CD2
                    | OperandEncoding::VSIB_CD4
                    | OperandEncoding::VSIB_CD8
                    | OperandEncoding::VSIB_CD16
                    | OperandEncoding::VSIB_CD32
                    | OperandEncoding::VSIB_CD64 => {
                        // VSIB can use the V2 bit so check only the other bits.
                        if needVVVV {
                            needVVVV = hasVVVV & ((self.vvvv as usize & 0xf) != 0);
                        }
                        if !self.read_modrm() {
                            return false;
                        }

                        // Reject if SIB wasn't used.
                        if self.ea_base != EABase::Basesib && self.ea_base != EABase::Basesib64 {
                            return false;
                        }

                        // If sib_index was set to SIB_INDEX_NONE, index offset is 4.
                        if self.sib_index == SIBIndex::None {
                            self.sib_index =
                                SIBIndex::from_u8(self.sib_idx_base as u8 + 4).unwrap();
                        }

                        // If EVEX.v2 is set this is one of the 16-31 registers.
                        if self.vec_ext_ty == VectorExtensionType::EVEX && self.mode == Mode::Long {
                            if let Some(vex_pfx) = self.vec_ext_pfx {
                                if v2FromEVEX4of4(vex_pfx[3]) != 0 {
                                    self.sib_index =
                                        SIBIndex::from_u8(self.sib_index as u8 + 16).unwrap();
                                }
                            }
                        }

                        // Adjust the index register to the correct size.
                        match spec.typ {
                            OperandType::MVSIBX => {
                                self.sib_index = SIBIndex::from_u8(
                                    SIBIndex::XMM0 as u8
                                        + (self.sib_index as u8 - self.sib_idx_base as u8),
                                )
                                .unwrap();
                            }
                            OperandType::MVSIBY => {
                                self.sib_index = SIBIndex::from_u8(
                                    SIBIndex::YMM0 as u8
                                        + (self.sib_index as u8 - self.sib_idx_base as u8),
                                )
                                .unwrap();
                            }
                            OperandType::MVSIBZ => {
                                self.sib_index = SIBIndex::from_u8(
                                    SIBIndex::ZMM0 as u8
                                        + (self.sib_index as u8 - self.sib_idx_base as u8),
                                )
                                .unwrap();
                            }
                            _ => {
                                eprintln!("Unhandled VSIB index type");
                                return false;
                            }
                        }

                        // Apply the AVX512 compressed displacement scaling factor.
                        if spec.encoding != OperandEncoding::REG
                            && self.ea_displ == EADisplacement::Disp8
                        {
                            self.displacement *=
                                1 << (spec.encoding as usize - OperandEncoding::VSIB as usize);
                        }
                    }

                    OperandEncoding::REG
                    | OperandEncoding::RM
                    | OperandEncoding::RM_CD2
                    | OperandEncoding::RM_CD4
                    | OperandEncoding::RM_CD8
                    | OperandEncoding::RM_CD16
                    | OperandEncoding::RM_CD32
                    | OperandEncoding::RM_CD64 => {
                        if !self.read_modrm() {
                            return false;
                        }
                        if !self.fixup_reg(&spec) {
                            return false;
                        }
                        // Apply the AVX512 compressed displacement scaling factor.
                        if spec.encoding != OperandEncoding::REG
                            && self.ea_displ == EADisplacement::Disp8
                        {
                            self.displacement *=
                                1 << (spec.encoding as usize - OperandEncoding::RM as usize);
                        }
                    }
                    OperandEncoding::IB => {
                        if sawRegImm {
                            /* Saw a register immediate so don't read again and instead split the
                            previous immediate.  FIXME: This is a hack. */
                            self.immediates[self.numImmediatesConsumed as usize] =
                                self.immediates[self.numImmediatesConsumed as usize - 1] & 0xf;
                            self.numImmediatesConsumed += 1;
                        } else {
                            if !self.read_immediate(1) {
                                return false;
                            }
                            if spec.typ == OperandType::XMM || spec.typ == OperandType::YMM {
                                sawRegImm = true;
                            }
                        }
                    }
                    OperandEncoding::IW => {
                        if !self.read_immediate(2) {
                            return false;
                        }
                    }
                    OperandEncoding::ID => {
                        if !self.read_immediate(4) {
                            return false;
                        }
                    }
                    OperandEncoding::IO => {
                        if !self.read_immediate(8) {
                            return false;
                        }
                    }
                    OperandEncoding::Iv => {
                        if !self.read_immediate(self.immediateSize) {
                            return false;
                        }
                    }
                    OperandEncoding::Ia => {
                        if !self.read_immediate(self.addressSize) {
                            return false;
                        }
                    }
                    OperandEncoding::IRC => {
                        if let Some(vex_pfx) = self.vec_ext_pfx {
                            self.RC = (l2FromEVEX4of4(vex_pfx[3]) << 1) | lFromEVEX4of4(vex_pfx[3]);
                        } else {
                            return false;
                        }
                    }
                    OperandEncoding::RB => {
                        if !self.read_opcode_register(1) {
                            return false;
                        }
                    }
                    OperandEncoding::RW => {
                        if !self.read_opcode_register(2) {
                            return false;
                        }
                    }
                    OperandEncoding::RD => {
                        if !self.read_opcode_register(4) {
                            return false;
                        }
                    }
                    OperandEncoding::RO => {
                        if !self.read_opcode_register(8) {
                            return false;
                        }
                    }
                    OperandEncoding::Rv => {
                        if !self.read_opcode_register(0) {
                            return false;
                        }
                    }
                    OperandEncoding::FP => {}
                    OperandEncoding::VVVV => {
                        needVVVV = false; /* Mark that we have found a VVVV operand. */
                        if !hasVVVV {
                            return false;
                        }
                        if self.mode != Mode::Long {
                            self.vvvv = Reg::from_u8(self.vvvv as u8 & 0x7).unwrap();
                        }
                        if !self.fixup_reg(&spec) {
                            return false;
                        }
                    }
                    OperandEncoding::WRITEMASK => {
                        if !self.read_mask_register() {
                            return false;
                        }
                    }
                    OperandEncoding::DUP => {}
                }
            }
        }

        /* If we didn't find ENCODING_VVVV operand, but non-zero vvvv present, fail */
        !needVVVV
    }

    /*
     * readModRM - Consumes all addressing information (ModR/M byte, SIB byte, and
     *   displacement) for an instruction and interprets it.
     */
    fn read_modrm(&mut self) -> bool {
        let mo;
        let mut rm;
        let mut reg;
        let mut evexrm;

        eprintln!("readModRM()");

        if self.consumedModRM {
            return true;
        }

        let mut modrm = 0;
        if !self.consume_byte(&mut modrm) {
            return false;
        }
        self.modrm = modrm;
        self.consumedModRM = true;

        mo = modFromModRM(self.modrm);
        rm = rmFromModRM(self.modrm);
        reg = regFromModRM(self.modrm);

        /*
         * This goes by insn->registerSize to pick the correct register, which messes
         * up if we're using (say) XMM or 8-bit register operands.  That gets fixed in
         * fixup_reg().
         */
        match self.registerSize {
            2 => {
                self.reg_base = Reg::AX;
                self.ea_reg_base = EABase::RegAX;
            }
            4 => {
                self.reg_base = Reg::EAX;
                self.ea_reg_base = EABase::RegEAX;
            }
            8 => {
                self.reg_base = Reg::RAX;
                self.ea_reg_base = EABase::RegRAX;
            }
            _ => unreachable!(),
        }

        reg |= rFromREX(self.rex_pfx.unwrap_or(0)) << 3;
        rm |= bFromREX(self.rex_pfx.unwrap_or(0)) << 3;

        evexrm = 0;
        if self.vec_ext_ty == VectorExtensionType::EVEX
            && self.mode == Mode::Long
            && self.vec_ext_pfx.is_some()
        {
            reg |= r2FromEVEX2of4(self.vec_ext_pfx.unwrap()[1]) << 4;
            evexrm = xFromEVEX2of4(self.vec_ext_pfx.unwrap()[1]) << 4;
        }

        self.reg = Reg::from_u8(self.reg_base as u8 + reg).unwrap();

        match self.addressSize {
            2 => {
                let ea_base_base = EABase::BaseBX_SI;

                match mo {
                    0x0 => {
                        if rm == 0x6 {
                            self.ea_base = EABase::BaseNone;
                            self.ea_displ = EADisplacement::Disp16;
                            if !self.read_displacement() {
                                return false;
                            }
                        } else {
                            self.ea_base = EABase::from_u8(ea_base_base as u8 + rm).unwrap();
                            self.ea_displ = EADisplacement::DispNone;
                        }
                    }
                    0x1 => {
                        self.ea_base = EABase::from_u8(ea_base_base as u8 + rm).unwrap();
                        self.ea_displ = EADisplacement::Disp8;
                        self.displacementSize = 1;
                        if !self.read_displacement() {
                            return false;
                        }
                    }
                    0x2 => {
                        self.ea_base = EABase::from_u8(ea_base_base as u8 + rm).unwrap();
                        self.ea_displ = EADisplacement::Disp16;
                        if !self.read_displacement() {
                            return false;
                        }
                    }
                    0x3 => {
                        self.ea_base = EABase::from_u8(self.ea_reg_base as u8 + rm).unwrap();
                        if !self.read_displacement() {
                            return false;
                        }
                    }
                    _ => unreachable!(),
                }
            }
            4 | 8 => {
                let ea_base_base = if self.addressSize == 4 {
                    EABase::BaseEAX
                } else {
                    EABase::BaseRAX
                };

                match mo {
                    0x0 => {
                        self.ea_displ = EADisplacement::DispNone; /* read_sib may override this */
                        // In determining whether RIP-relative mode is used (rm=5),
                        // or whether a SIB byte is present (rm=4),
                        // the extension bits (REX.b and EVEX.x) are ignored.
                        match rm & 7 {
                            0x4 => {
                                // SIB byte is present
                                self.ea_base = if self.addressSize == 4 {
                                    EABase::Basesib
                                } else {
                                    EABase::Basesib64
                                };
                                if !self.read_sib() || !self.read_displacement() {
                                    return false;
                                }
                            }
                            0x5 => {
                                // RIP-relative
                                self.ea_base = EABase::BaseNone;
                                self.ea_displ = EADisplacement::Disp32;
                                if !self.read_displacement() {
                                    return false;
                                }
                            }
                            _ => {
                                self.ea_base = EABase::from_u8(ea_base_base as u8 + rm).unwrap();
                            }
                        }
                    }
                    0x1 | 0x2 => {
                        if mo == 0x1 {
                            self.displacementSize = 1;
                        }

                        self.ea_displ = if mo == 0x1 {
                            EADisplacement::Disp8
                        } else {
                            EADisplacement::Disp32
                        };
                        match rm & 7 {
                            0x4 => {
                                // SIB byte is present
                                self.ea_base = EABase::Basesib;
                                if !self.read_sib() || !self.read_displacement() {
                                    return false;
                                }
                            }
                            _ => {
                                self.ea_base = EABase::from_u8(ea_base_base as u8 + rm).unwrap();
                                if !self.read_displacement() {
                                    return false;
                                }
                            }
                        }
                    }
                    0x3 => {
                        self.ea_displ = EADisplacement::DispNone;
                        self.ea_base = EABase::from_u8(self.ea_reg_base as u8 + evexrm).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }

        true
    }

    /*
     * read_displacement - Consumes the displacement of an instruction.
     *
     * @param insn  - The instruction whose displacement is to be read.
     * @return      - 0 if the displacement byte was successfully read; nonzero
     *                otherwise.
     */
    fn read_displacement(&mut self) -> bool {
        eprintln!("read_displacement()");

        if self.consumedDisplacement {
            return true;
        }

        self.consumedDisplacement = true;
        self.displacementOffset = self.cursor as u8;

        match self.ea_displ {
            EADisplacement::DispNone => {
                self.consumedDisplacement = false;
                true
            }
            EADisplacement::Disp8 => {
                if let Some(&b) = self.buffer.get(self.cursor) {
                    self.cursor += 1;
                    self.displacement = b as u32;
                    true
                } else {
                    false
                }
            }
            EADisplacement::Disp16 => {
                let mut cur = Cursor::new(&self.buffer[self.cursor..]);

                if let Ok(b) = cur.read_u16::<LittleEndian>() {
                    self.cursor += 2;
                    self.displacement = b as u32;
                    true
                } else {
                    false
                }
            }
            EADisplacement::Disp32 => {
                let mut cur = Cursor::new(&self.buffer[self.cursor..]);

                if let Ok(b) = cur.read_u32::<LittleEndian>() {
                    self.cursor += 4;
                    self.displacement = b as u32;
                    true
                } else {
                    false
                }
            }
        }
    }

    /*
     * read_sib - Consumes the SIB byte to determine addressing information for an
     *   instruction.
     *
     * @param insn  - The instruction whose SIB byte is to be read.
     * @return      - 0 if the SIB byte was successfully read; nonzero otherwise.
     */
    fn read_sib(&mut self) -> bool {
        let sib_base_base;

        eprintln!("read_sib()");

        if self.consumedSIB {
            return true;
        }

        self.consumedSIB = true;

        match self.addressSize {
            2 => {
                eprintln!("SIB-based addressing doesn't work in 16-bit mode");
                return false;
            }
            4 => {
                self.sib_idx_base = SIBIndex::EAX;
                sib_base_base = SIBBase::EAX;
            }
            8 => {
                self.sib_idx_base = SIBIndex::RAX;
                sib_base_base = SIBBase::RAX;
            }
            _ => unreachable!(),
        }

        let mut sib = 0;

        if !self.consume_byte(&mut sib) {
            return false;
        } else {
            self.sib = sib;
        }

        let index = indexFromSIB(self.sib) | (xFromREX(self.rex_pfx.unwrap_or(0)) << 3);

        if index == 0x4 {
            self.sib_index = SIBIndex::None;
        } else {
            self.sib_index = SIBIndex::from_u8(self.sib_idx_base as u8 + index).unwrap();
        }

        self.sib_scale = 1 << scaleFromSIB(self.sib);

        let base = baseFromSIB(self.sib) | (bFromREX(self.rex_pfx.unwrap_or(0)) << 3);

        match base {
            0x5 | 0xd => match modFromModRM(self.modrm) {
                0x0 => {
                    self.ea_displ = EADisplacement::Disp32;
                    self.sib_base = SIBBase::None;
                }
                0x1 => {
                    self.ea_displ = EADisplacement::Disp8;
                    self.sib_base = SIBBase::from_u8(sib_base_base as u8 + base).unwrap();
                }
                0x2 => {
                    self.ea_displ = EADisplacement::Disp32;
                    self.sib_base = SIBBase::from_u8(sib_base_base as u8 + base).unwrap();
                }
                0x3 => {
                    eprintln!("Cannot have Mod = 0b11 and a SIB byte");
                    return false;
                }
                _ => unreachable!(),
            },
            _ => {
                self.sib_base = SIBBase::from_u8(sib_base_base as u8 + base).unwrap();
            }
        }

        return true;
    }

    /*
     * getID - Determines the ID of an instruction, consuming the ModR/M byte as
     *   appropriate for extended and escape opcodes.  Determines the attributes and
     *   context for the instruction before doing so.
     *
     * @param insn  - The instruction whose ID is to be determined.
     * @return      - 0 if the ModR/M could be read when needed or was not needed;
     *                nonzero otherwise.
     */
    fn getID(&mut self) -> bool {
        let mut attrMask = ATTR_NONE;

        eprintln!("getID()");
        eprintln!("getID(): {:x?}", self.mandatory_pfx);

        if self.mode == Mode::Long {
            attrMask |= ATTR_64BIT;
        }

        if self.vec_ext_ty != VectorExtensionType::NoVEX_XOP {
            attrMask |= if self.vec_ext_ty == VectorExtensionType::EVEX {
                ATTR_EVEX
            } else {
                ATTR_VEX
            };

            if self.vec_ext_ty == VectorExtensionType::EVEX && self.vec_ext_pfx.is_some() {
                let vex_pfx = self.vec_ext_pfx.unwrap();

                match VEXPrefixCode::from_u8(ppFromEVEX3of4(vex_pfx[2])) {
                    Some(VEXPrefixCode::Prefix66) => {
                        attrMask |= ATTR_OPSIZE;
                    }
                    Some(VEXPrefixCode::PrefixF3) => {
                        attrMask |= ATTR_XS;
                    }
                    Some(VEXPrefixCode::PrefixF2) => {
                        attrMask |= ATTR_XD;
                    }
                    _ => {}
                }

                if zFromEVEX4of4(vex_pfx[3]) != 0 {
                    attrMask |= ATTR_EVEXKZ;
                }
                if bFromEVEX4of4(vex_pfx[3]) != 0 {
                    attrMask |= ATTR_EVEXB;
                }
                if aaaFromEVEX4of4(vex_pfx[3]) != 0 {
                    attrMask |= ATTR_EVEXK;
                }
                if lFromEVEX4of4(vex_pfx[3]) != 0 {
                    attrMask |= ATTR_EVEXL;
                }
                if l2FromEVEX4of4(vex_pfx[3]) != 0 {
                    attrMask |= ATTR_EVEXL2;
                }
            } else if self.vec_ext_ty == VectorExtensionType::VEX_3B && self.vec_ext_pfx.is_some() {
                let vex_pfx = self.vec_ext_pfx.unwrap();

                match VEXPrefixCode::from_u8(ppFromVEX3of3(vex_pfx[2])) {
                    Some(VEXPrefixCode::Prefix66) => {
                        attrMask |= ATTR_OPSIZE;
                    }
                    Some(VEXPrefixCode::PrefixF3) => {
                        attrMask |= ATTR_XS;
                    }
                    Some(VEXPrefixCode::PrefixF2) => {
                        attrMask |= ATTR_XD;
                    }
                    _ => {}
                }

                if lFromVEX3of3(vex_pfx[2]) != 0 {
                    attrMask |= ATTR_VEXL;
                }
            } else if self.vec_ext_ty == VectorExtensionType::VEX_2B && self.vec_ext_pfx.is_some() {
                let vex_pfx = self.vec_ext_pfx.unwrap();

                match VEXPrefixCode::from_u8(ppFromVEX2of2(vex_pfx[1])) {
                    Some(VEXPrefixCode::Prefix66) => {
                        attrMask |= ATTR_OPSIZE;
                    }
                    Some(VEXPrefixCode::PrefixF3) => {
                        attrMask |= ATTR_XS;
                    }
                    Some(VEXPrefixCode::PrefixF2) => {
                        attrMask |= ATTR_XD;
                    }
                    _ => {}
                }

                if lFromVEX2of2(vex_pfx[1]) != 0 {
                    attrMask |= ATTR_VEXL;
                }
            } else if self.vec_ext_ty == VectorExtensionType::XOP && self.vec_ext_pfx.is_some() {
                let vex_pfx = self.vec_ext_pfx.unwrap();

                match VEXPrefixCode::from_u8(ppFromXOP3of3(vex_pfx[2])) {
                    Some(VEXPrefixCode::Prefix66) => {
                        attrMask |= ATTR_OPSIZE;
                    }
                    Some(VEXPrefixCode::PrefixF3) => {
                        attrMask |= ATTR_XS;
                    }
                    Some(VEXPrefixCode::PrefixF2) => {
                        attrMask |= ATTR_XD;
                    }
                    _ => {}
                }

                if lFromXOP3of3(vex_pfx[2]) != 0 {
                    attrMask |= ATTR_VEXL;
                }
            } else {
                return false;
            }
        } else {
            match self.mandatory_pfx {
                Some(0xf2) => {
                    attrMask |= ATTR_XD;
                }
                Some(0xf3) => {
                    attrMask |= ATTR_XS;
                }
                Some(0x66) => {
                    if self.mode != Mode::Real {
                        attrMask |= ATTR_OPSIZE;
                    }
                }
                Some(0x67) => {
                    attrMask |= ATTR_ADSIZE;
                }
                None => {
                    // If we don't have mandatory prefix we should use legacy prefixes here
                    if self.hasOpSize && (self.mode != Mode::Real) {
                        attrMask |= ATTR_OPSIZE;
                    }
                    if self.hasAdSize {
                        attrMask |= ATTR_ADSIZE;
                    }
                    if self.opcodeType == OpcodeType::OneByte {
                        if self.repeatPrefix == Some(0xf3) && (self.opcode == 0x90) {
                            // Special support for PAUSE
                            attrMask |= ATTR_XS;
                        }
                    } else {
                        match self.repeatPrefix {
                            Some(0xf2) => {
                                attrMask |= ATTR_XD;
                            }
                            Some(0xf3) => {
                                attrMask |= ATTR_XS;
                            }
                            _ => {}
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        if self.rex_pfx.unwrap_or(0) & 0x08 != 0 {
            attrMask |= ATTR_REXW;
            attrMask &= !ATTR_ADSIZE;
        }

        /*
         * JCXZ/JECXZ need special handling for 16-bit mode because the meaning
         * of the AdSize prefix is inverted w.r.t. 32-bit mode.
         */
        if self.mode == Mode::Real && self.opcodeType == OpcodeType::OneByte && self.opcode == 0xE3
        {
            attrMask ^= ATTR_ADSIZE;
        }

        // If we're in 16-bit mode and this is one of the relative jumps and opsize
        // prefix isn't present, we need to force the opsize attribute since the
        // prefix is inverted relative to 32-bit mode.
        if self.mode == Mode::Real
            && !self.hasOpSize
            && self.opcodeType == OpcodeType::OneByte
            && (self.opcode == 0xE8 || self.opcode == 0xE9)
        {
            attrMask |= ATTR_OPSIZE;
        }

        if self.mode == Mode::Real
            && !self.hasOpSize
            && self.opcodeType == OpcodeType::TwoByte
            && self.opcode >= 0x80
            && self.opcode <= 0x8F
        {
            attrMask |= ATTR_OPSIZE;
        }

        let instructionID;

        if let Some(i) = self.getIDWithAttrMask(attrMask) {
            eprintln!("iid: {}", i);
            instructionID = i;
        } else {
            return false;
        }

        /* The following clauses compensate for limitations of the tables. */

        if self.mode != Mode::Long && self.vec_ext_ty != VectorExtensionType::NoVEX_XOP {
            /*
             * The tables can't distinquish between cases where the W-bit is used to
             * select register size and cases where its a required part of the opcode.
             */
            if (self.vec_ext_ty == VectorExtensionType::EVEX
                && self.vec_ext_pfx.is_some()
                && wFromEVEX3of4(self.vec_ext_pfx.unwrap()[2]) != 0)
                || (self.vec_ext_ty == VectorExtensionType::VEX_3B
                    && self.vec_ext_pfx.is_some()
                    && wFromVEX3of3(self.vec_ext_pfx.unwrap()[2]) != 0)
                || (self.vec_ext_ty == VectorExtensionType::XOP
                    && self.vec_ext_pfx.is_some()
                    && wFromXOP3of3(self.vec_ext_pfx.unwrap()[2]) != 0)
            {
                if let Some(instructionIDWithREXW) = self.getIDWithAttrMask(attrMask | ATTR_REXW) {
                    let specName = Self::get_instr_name(instructionIDWithREXW);
                    // If not a 64-bit instruction. Switch the opcode.
                    if !self.is64_bit(specName) {
                        self.instructionID = instructionIDWithREXW;
                        self.spec = INSTRUCTION_SPECIFIER[instructionIDWithREXW];
                        return true;
                    }
                } else {
                    self.instructionID = instructionID;
                    self.spec = INSTRUCTION_SPECIFIER[instructionID];
                    return true;
                }
            }
        }

        /*
         * Absolute moves, umonitor, and movdir64b need special handling.
         * -For 16-bit mode because the meaning of the AdSize and OpSize prefixes are
         *  inverted w.r.t.
         * -For 32-bit mode we need to ensure the ADSIZE prefix is observed in
         *  any position.
         */
        if (self.opcodeType == OpcodeType::OneByte && ((self.opcode & 0xFC) == 0xA0))
            || (self.opcodeType == OpcodeType::TwoByte && (self.opcode == 0xAE))
            || (self.opcodeType == OpcodeType::ThreeByte_38 && self.opcode == 0xF8)
        {
            /* Make sure we observed the prefixes in any position. */
            if self.hasAdSize {
                attrMask |= ATTR_ADSIZE;
            }
            if self.hasOpSize {
                attrMask |= ATTR_OPSIZE;
            }

            /* In 16-bit, invert the attributes. */
            if self.mode == Mode::Real {
                attrMask ^= ATTR_ADSIZE;

                /* The OpSize attribute is only valid with the absolute moves. */
                if self.opcodeType == OpcodeType::OneByte && ((self.opcode & 0xFC) == 0xA0) {
                    attrMask ^= ATTR_OPSIZE;
                }
            }

            if let Some(instructionID) = self.getIDWithAttrMask(attrMask) {
                self.instructionID = instructionID;
                self.spec = INSTRUCTION_SPECIFIER[instructionID];

                return true;
            } else {
                return false;
            }
        }

        if (self.mode == Mode::Real || self.hasOpSize) && (attrMask & ATTR_OPSIZE) == 0 {
            /*
             * The instruction tables make no distinction between instructions that
             * allow OpSize anywhere (i.e., 16-bit operations) and that need it in a
             * particular spot (i.e., many MMX operations).  In general we're
             * conservative, but in the specific case where OpSize is present but not
             * in the right place we check if there's a 16-bit operation.
             */

            let instructionIDWithOpsize;
            let spec = INSTRUCTION_SPECIFIER[instructionID];

            if let Some(iid) = self.getIDWithAttrMask(attrMask | ATTR_OPSIZE) {
                eprintln!("iid w/opsz: {}", iid);
                instructionIDWithOpsize = iid;
            } else {
                /*
                 * ModRM required with OpSize but not present; give up and return version
                 * without OpSize set
                 */

                self.instructionID = instructionID;
                self.spec = spec;
                return true;
            }

            let specName = Self::get_instr_name(instructionID);
            let specWithOpSizeName = Self::get_instr_name(instructionIDWithOpsize);

            eprintln!("{}/{}", specName, specWithOpSizeName);

            if Self::is16_bit_equivalent(specName, specWithOpSizeName)
                && (self.mode == Mode::Real) ^ self.hasOpSize
            {
                self.instructionID = instructionIDWithOpsize;
                self.spec = INSTRUCTION_SPECIFIER[instructionIDWithOpsize];
            } else {
                self.instructionID = instructionID;
                self.spec = spec;
            }
            return true;
        }

        if self.opcodeType == OpcodeType::OneByte
            && self.opcode == 0x90
            && self.rex_pfx.unwrap_or(0) & 0x01 != 0
        {
            /*
             * NOOP shouldn't decode as NOOP if REX.b is set. Instead
             * it should decode as XCHG %r8, %eax.
             */

            let instructionIDWithNewOpcode;
            let spec = INSTRUCTION_SPECIFIER[instructionID];

            /* Borrow opcode from one of the other XCHGar opcodes */
            self.opcode = 0x91;

            if let Some(iid) = self.getIDWithAttrMask(attrMask) {
                instructionIDWithNewOpcode = iid;
            } else {
                self.opcode = 0x90;

                self.instructionID = instructionID;
                self.spec = spec;
                return true;
            }

            let specWithNewOpcode = INSTRUCTION_SPECIFIER[instructionIDWithNewOpcode];

            /* Change back */
            self.opcode = 0x90;

            self.instructionID = instructionIDWithNewOpcode;
            self.spec = specWithNewOpcode;

            return true;
        }

        self.instructionID = instructionID;
        self.spec = INSTRUCTION_SPECIFIER[self.instructionID];

        true
    }

    /*
     * getIDWithAttrMask - Determines the ID of an instruction, consuming
     *   the ModR/M byte as appropriate for extended and escape opcodes,
     *   and using a supplied attribute mask.
     *
     * @param instructionID - A pointer whose target is filled in with the ID of the
     *                        instruction.
     * @param insn          - The instruction whose ID is to be determined.
     * @param attrMask      - The attribute mask to search.
     * @return              - 0 if the ModR/M could be read when needed or was not
     *                        needed; nonzero otherwise.
     */
    fn getIDWithAttrMask(&mut self, attrMask: usize) -> Option<usize> {
        let instructionClass = INSTRUCTION_CONTEXTS[attrMask];
        let hasModRMExtension = self.modrm_req(instructionClass);

        eprintln!("class: {:?}", instructionClass);
        eprintln!("hasModRMExt: {}", hasModRMExtension);

        let uid = if hasModRMExtension {
            if !self.read_modrm() {
                return None;
            }

            self.decode(instructionClass, self.modrm)
        } else {
            self.decode(instructionClass, 0)
        };

        match uid {
            0 => None,
            uid => Some(uid),
        }
    }

    /*
     * is16_bit_equivalent - Determines whether two instruction names refer to
     * equivalent instructions but one is 16-bit whereas the other is not.
     *
     * @param orig  - The instruction that is not 16-bit
     * @param equiv - The instruction that is 16-bit
     */
    fn is16_bit_equivalent(orig: &str, equiv: &str) -> bool {
        let orig_buf = orig.as_bytes();
        let equiv_buf = equiv.as_bytes();

        for i in 0..cmp::max(orig_buf.len(), equiv_buf.len()) {
            match (orig_buf.get(i), equiv_buf.get(i)) {
                (None, None) => return true,
                (None, Some(_)) | (Some(_), None) => return false,
                (Some(b'Q'), Some(b'W')) => continue,
                (Some(b'L'), Some(b'W')) => continue,
                (Some(b'6'), Some(b'1')) => continue,
                (Some(b'3'), Some(b'1')) => continue,
                (Some(b'4'), Some(b'6')) => continue,
                (Some(b'2'), Some(b'6')) => continue,
                (Some(a), Some(b)) if a != b => return false,
                (Some(a), Some(b)) => {
                    assert_eq!(a, b);
                }
            }
        }

        true
    }

    /*
     * is64_bit - Determines whether this instruction is a 64-bit instruction.
     *
     * @param name - The instruction that is not 16-bit
     */
    fn is64_bit(&self, name: &str) -> bool {
        name.find("64").is_some()
    }

    /*
     * decode_instruction - Reads and interprets a full instruction provided by the
     *   user.
     *
     * @param insn      - A pointer to the instruction to be populated.  Must be
     *                    pre-allocated.
     * @param reader    - The function to be used to read the instruction's bytes.
     * @param readerArg - A generic argument to be passed to the reader to store
     *                    any internal state.
     * @param logger    - If non-NULL, the function to be used to write log messages
     *                    and warnings.
     * @param loggerArg - A generic argument to be passed to the logger to store
     *                    any internal state.
     * @param startLoc  - The address (in the reader's address space) of the first
     *                    byte in the instruction.
     * @param mode      - The mode (real mode, IA-32e, or IA-32e in 64-bit mode) to
     *                    decode the instruction in.
     * @return          - 0 if the instruction's memory could be read; nonzero if
     *                    not.
     */
    fn decode_instruction(&mut self) -> bool {
        let read_prefixes = self.read_prefixes();
        eprintln!("read_prefixes: {}", read_prefixes);
        eprintln!("opsize: {}", self.hasOpSize);

        let read_opcode = self.read_opcode();
        eprintln!("read_opcode: {} ({})", read_opcode, self.opcode);
        eprintln!("mandatory_pfx: {:?}", self.mandatory_pfx);

        let get_id = self.getID();
        eprintln!(
            "getID: {}, instructionID: {}, {}",
            get_id,
            self.instructionID,
            self.name()
        );

        let read_operands = self.read_operands();
        eprintln!("read_operands: {}", read_operands);

        let hit =
            read_prefixes && read_opcode && get_id && self.instructionID != 0 && read_operands;

        if !hit {
            return false;
        }

        self.operands = Some(&OPERAND_SETS[self.spec]);
        self.semantics = SEMANTICS[self.instructionID];

        eprintln!("Read {}", self.cursor);

        if self.cursor > 15 {
            eprintln!("Instruction exceeds 15-byte limit");
        }

        true
    }

    /*
     * modrm_req - Reads the appropriate instruction table to determine whether
     *   the ModR/M byte is required to decode a particular instruction.
     *
     * @param type        - The opcode type (i.e., how many bytes it has).
     * @param insn_ctx - The context for the instruction, as returned by
     *                      contextForAttrs.
     * @param opcode      - The last byte of the instruction's opcode, not counting
     *                      ModR/M extensions and escapes.
     * @return            - true if the ModR/M byte is required, false otherwise.
     */
    fn modrm_req(&self, insn_ctx: InstructionContext) -> bool {
        let tbl = match self.opcodeType {
            OpcodeType::OneByte => &X86_DISASSEMBLER_ONE_BYTE_OPCODES,
            OpcodeType::TwoByte => &X86_DISASSEMBLER_TWO_BYTE_OPCODES,
            OpcodeType::ThreeByte_38 => &X86_DISASSEMBLER_THREE_BYTE_38_OPCODES,
            OpcodeType::ThreeByte_3A => &X86_DISASSEMBLER_THREE_BYTE_3A_OPCODES,
            OpcodeType::XOP8_Map => &X86_DISASSEMBLER_XOP8_OPCODES,
            OpcodeType::XOP9_Map => &X86_DISASSEMBLER_XOP9_OPCODES,
            OpcodeType::XOPA_Map => &X86_DISASSEMBLER_XOPA_OPCODES,
            OpcodeType::ThreeDNow_Map => &X86_DISASSEMBLER_3DNOW_OPCODES,
        };

        tbl[insn_ctx as usize].opcodeDecision[self.opcode as usize].modrmType
            != ModRMDecisionType::OneEntry
    }

    /*
     * decode - Reads the appropriate instruction table to obtain the unique ID of
     *   an instruction.
     *
     * @param type        - See modrm_req().
     * @param insn_ctx - See modrm_req().
     * @param opcode      - See modrm_req().
     * @param modrm       - The ModR/M byte if required, or any value if not.
     * @return            - The UID of the instruction.
     */
    fn decode(&self, insn_ctx: InstructionContext, modrm: u8) -> usize {
        eprintln!("decode()");
        eprintln!("decode() opcodeType: {:?}", self.opcodeType);

        let tbl = match self.opcodeType {
            OpcodeType::OneByte => &X86_DISASSEMBLER_ONE_BYTE_OPCODES,
            OpcodeType::TwoByte => &X86_DISASSEMBLER_TWO_BYTE_OPCODES,
            OpcodeType::ThreeByte_38 => &X86_DISASSEMBLER_THREE_BYTE_38_OPCODES,
            OpcodeType::ThreeByte_3A => &X86_DISASSEMBLER_THREE_BYTE_3A_OPCODES,
            OpcodeType::XOP8_Map => &X86_DISASSEMBLER_XOP8_OPCODES,
            OpcodeType::XOP9_Map => &X86_DISASSEMBLER_XOP9_OPCODES,
            OpcodeType::XOPA_Map => &X86_DISASSEMBLER_XOPA_OPCODES,
            OpcodeType::ThreeDNow_Map => &X86_DISASSEMBLER_3DNOW_OPCODES,
        };
        let dec = &tbl[insn_ctx as usize].opcodeDecision[self.opcode as usize];

        eprintln!("{:?}", dec);

        match dec.modrmType {
            ModRMDecisionType::OneEntry => MODRM_TABLE[dec.instrUids],
            ModRMDecisionType::SplitRM => {
                let ret = if modFromModRM(modrm) == 0x3 {
                    MODRM_TABLE[dec.instrUids + 1]
                } else {
                    MODRM_TABLE[dec.instrUids]
                };
                eprintln!("modrmtbl {:?}", ret);
                ret
            }
            ModRMDecisionType::SplitReg => {
                let idx = dec.instrUids + ((modrm & 0x38) as usize >> 3);
                if modFromModRM(modrm) == 0x3 {
                    MODRM_TABLE[idx + 8]
                } else {
                    MODRM_TABLE[idx]
                }
            }
            ModRMDecisionType::SplitMisc => {
                if modFromModRM(modrm) == 0x3 {
                    let idx = dec.instrUids + (modrm & 0x3f) as usize + 8;
                    MODRM_TABLE[idx]
                } else {
                    let idx = dec.instrUids + ((modrm & 0x38) as usize >> 3);
                    MODRM_TABLE[idx]
                }
            }
            ModRMDecisionType::Full => MODRM_TABLE[dec.instrUids + modrm as usize],
        }
    }

    /*
     * read_opcode_register - Reads an operand from the opcode field of an
     *   instruction and interprets it appropriately given the operand width.
     *   Handles AddRegFrm instructions.
     *
     * @param insn  - the instruction whose opcode field is to be read.
     * @param size  - The width (in bytes) of the register being specified.
     *                1 means AL and friends, 2 means AX, 4 means EAX, and 8 means
     *                RAX.
     * @return      - 0 on success; nonzero otherwise.
     */
    fn read_opcode_register(&mut self, mut size: usize) -> bool {
        eprintln!("read_opcode_register()");

        if size == 0 {
            size = self.registerSize;
        }

        match size {
            1 => {
                self.opcodeRegister = Reg::from_u8(
                    Reg::AL as u8
                        + ((bFromREX(self.rex_pfx.unwrap_or(0)) << 3) | (self.opcode as u8 & 7)),
                )
                .unwrap();
                if self.rex_pfx.unwrap_or(0) != 0
                    && (self.opcodeRegister as u8) >= Reg::AL as u8 + 0x4
                    && (self.opcodeRegister as u8) < Reg::AL as u8 + 0x8
                {
                    self.opcodeRegister = Reg::from_u8(
                        Reg::SPL as u8 + (self.opcodeRegister as u8 - Reg::AL as u8 - 4),
                    )
                    .unwrap();
                }
            }
            2 => {
                self.opcodeRegister = Reg::from_u8(
                    Reg::AX as u8
                        + ((bFromREX(self.rex_pfx.unwrap_or(0)) << 3) | (self.opcode as u8 & 7)),
                )
                .unwrap();
            }
            4 => {
                self.opcodeRegister = Reg::from_u8(
                    Reg::EAX as u8
                        + ((bFromREX(self.rex_pfx.unwrap_or(0)) << 3) | (self.opcode as u8 & 7)),
                )
                .unwrap();
            }
            8 => {
                self.opcodeRegister = Reg::from_u8(
                    Reg::RAX as u8
                        + ((bFromREX(self.rex_pfx.unwrap_or(0)) << 3) | (self.opcode as u8 & 7)),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }

        true
    }

    /*
     * read_immediate - Consumes an immediate operand from an instruction, given the
     *   desired operand size.
     *
     * @param insn  - The instruction whose operand is to be read.
     * @param size  - The width (in bytes) of the operand.
     * @return      - 0 if the immediate was successfully consumed; nonzero
     *                otherwise.
     */
    fn read_immediate(&mut self, mut size: u8) -> bool {
        eprintln!("read_immediate()");

        if self.numImmediatesConsumed == 2 {
            eprintln!("Already consumed two immediates");
            return false;
        }

        if size == 0 {
            size = self.immediateSize;
        } else {
            self.immediateSize = size;
        }
        self.immediateOffset = self.cursor as u8;

        match size {
            1 => {
                if let Some(&imm) = self.buffer.get(self.cursor) {
                    self.immediates[self.numImmediatesConsumed as usize] = imm as u64;
                    self.cursor += 1;
                } else {
                    return false;
                }
            }
            2 => {
                let mut cur = Cursor::new(&self.buffer[self.cursor..]);
                if let Ok(imm) = cur.read_u16::<LittleEndian>() {
                    self.immediates[self.numImmediatesConsumed as usize] = imm as u64;
                    self.cursor += 2;
                } else {
                    return false;
                }
            }
            4 => {
                let mut cur = Cursor::new(&self.buffer[self.cursor..]);
                if let Ok(imm) = cur.read_u32::<LittleEndian>() {
                    self.immediates[self.numImmediatesConsumed as usize] = imm as u64;
                    self.cursor += 4;
                } else {
                    return false;
                }
            }
            8 => {
                let mut cur = Cursor::new(&self.buffer[self.cursor..]);
                if let Ok(imm) = cur.read_u64::<LittleEndian>() {
                    self.immediates[self.numImmediatesConsumed as usize] = imm;
                    self.cursor += 8;
                } else {
                    return false;
                }
            }
            _ => unreachable!(),
        }

        self.numImmediatesConsumed += 1;

        true
    }

    /*
     * read_vvvv - Consumes vvvv from an instruction if it has a VEX prefix.
     *
     * @param insn  - The instruction whose operand is to be read.
     * @return      - 0 if the vvvv was successfully consumed; nonzero
     *                otherwise.
     */
    fn read_vvvv(&mut self) -> bool {
        eprintln!("read_vvvv()");

        let mut vvvv = if let Some(vex_pfx) = self.vec_ext_pfx {
            match self.vec_ext_ty {
                VectorExtensionType::EVEX => {
                    (v2FromEVEX4of4(vex_pfx[3]) << 4 | vvvvFromEVEX3of4(vex_pfx[2]))
                }
                VectorExtensionType::VEX_3B => vvvvFromVEX3of3(vex_pfx[2]),
                VectorExtensionType::VEX_2B => vvvvFromVEX2of2(vex_pfx[1]),
                VectorExtensionType::XOP => vvvvFromXOP3of3(vex_pfx[2]),
                _ => return false,
            }
        } else {
            return false;
        };

        if self.mode != Mode::Long {
            vvvv &= 0xf; // Can only clear bit 4. Bit 3 must be cleared later.
        }

        self.vvvv = Reg::from_u8(vvvv).unwrap();
        true
    }

    /*
     * read_mask_register - Reads an mask register from the opcode field of an
     *   instruction.
     *
     * @param insn    - The instruction whose opcode field is to be read.
     * @return        - 0 on success; nonzero otherwise.
     */
    fn read_mask_register(&mut self) -> bool {
        eprintln!("read_mask_register()");

        if self.vec_ext_ty != VectorExtensionType::EVEX {
            false
        } else if let Some(vex_pfx) = self.vec_ext_pfx {
            self.writemask = Reg::from_u8(aaaFromEVEX4of4(vex_pfx[3])).unwrap();
            true
        } else {
            false
        }
    }

    fn fixup_reg_value(&self, typ: OperandType, mut index: u8) -> Option<Reg> {
        match typ {
            OperandType::Rv => Reg::from_u8(self.reg_base as u8 + index),
            OperandType::R8 => {
                index &= 0x1f;
                if index > 0xf {
                    return None;
                }
                if self.rex_pfx.is_some() && index >= 4 && index <= 7 {
                    Reg::from_u8(Reg::SPL as u8 + (index - 4))
                } else {
                    Reg::from_u8(Reg::AL as u8 + index)
                }
            }
            OperandType::R16 => {
                index &= 0x1f;
                if index > 0xf {
                    return None;
                }
                Reg::from_u8(Reg::AX as u8 + index)
            }
            OperandType::R32 => {
                index &= 0x1f;
                if index > 0xf {
                    return None;
                }
                Reg::from_u8(Reg::EAX as u8 + index)
            }
            OperandType::R64 => {
                index &= 0x1f;
                if index > 0xf {
                    return None;
                }
                Reg::from_u8(Reg::RAX as u8 + index)
            }
            OperandType::ZMM => Reg::from_u8(Reg::ZMM0 as u8 + index),
            OperandType::YMM => Reg::from_u8(Reg::YMM0 as u8 + index),
            OperandType::XMM => Reg::from_u8(Reg::XMM0 as u8 + index),
            OperandType::VK => {
                index &= 0xf;
                if index > 7 {
                    return None;
                }
                Reg::from_u8(Reg::K0 as u8 + index)
            }
            OperandType::MM64 => Reg::from_u8(Reg::MM0 as u8 + (index & 0x7)),
            OperandType::SEGMENTREG => {
                if (index & 7) > 5 {
                    return None;
                }
                Reg::from_u8(Reg::ES as u8 + (index & 7))
            }
            OperandType::DEBUGREG => Reg::from_u8(Reg::DR0 as u8 + index),
            OperandType::CONTROLREG => Reg::from_u8(Reg::CR0 as u8 + index),
            OperandType::BNDR => {
                if index > 3 {
                    return None;
                }
                Reg::from_u8(Reg::BND0 as u8 + index)
            }
            OperandType::MVSIBX => Reg::from_u8(Reg::XMM0 as u8 + index),
            OperandType::MVSIBY => Reg::from_u8(Reg::YMM0 as u8 + index),
            OperandType::MVSIBZ => Reg::from_u8(Reg::ZMM0 as u8 + index),
            _ => {
                eprintln!("Unhandled register type");
                None
            }
        }
    }

    fn fixup_rm_value(&self, typ: OperandType, mut index: u8) -> Option<EABase> {
        match typ {
            OperandType::Rv => EABase::from_u8(self.ea_reg_base as u8 + index),
            OperandType::R8 => {
                index &= 0xf;
                if index > 0xf {
                    return None;
                }
                if self.rex_pfx.is_some() && index >= 4 && index <= 7 {
                    EABase::from_u8(EABase::RegSPL as u8 + (index - 4))
                } else {
                    EABase::from_u8(EABase::RegAL as u8 + index)
                }
            }
            OperandType::R16 => {
                index &= 0xf;
                if index > 0xf {
                    return None;
                }
                EABase::from_u8(EABase::RegAX as u8 + index)
            }
            OperandType::R32 => {
                index &= 0xf;
                if index > 0xf {
                    return None;
                }
                EABase::from_u8(EABase::RegEAX as u8 + index)
            }
            OperandType::R64 => {
                index &= 0xf;
                if index > 0xf {
                    return None;
                }
                EABase::from_u8(EABase::RegRAX as u8 + index)
            }
            OperandType::ZMM => EABase::from_u8(EABase::RegZMM0 as u8 + index),
            OperandType::YMM => EABase::from_u8(EABase::RegYMM0 as u8 + index),
            OperandType::XMM => EABase::from_u8(EABase::RegXMM0 as u8 + index),
            OperandType::VK => {
                index &= 0xf;
                if index > 7 {
                    return None;
                }
                EABase::from_u8(EABase::RegK0 as u8 + index)
            }
            OperandType::MM64 => EABase::from_u8(EABase::RegMM0 as u8 + (index & 0x7)),
            OperandType::SEGMENTREG => {
                if (index & 7) > 5 {
                    return None;
                }
                EABase::from_u8(EABase::RegES as u8 + (index & 7))
            }
            OperandType::DEBUGREG => EABase::from_u8(EABase::RegDR0 as u8 + index),
            OperandType::CONTROLREG => EABase::from_u8(EABase::RegCR0 as u8 + index),
            OperandType::BNDR => {
                if index > 3 {
                    return None;
                }
                EABase::from_u8(EABase::RegBND0 as u8 + index)
            }
            OperandType::MVSIBX => EABase::from_u8(EABase::RegXMM0 as u8 + index),
            OperandType::MVSIBY => EABase::from_u8(EABase::RegYMM0 as u8 + index),
            OperandType::MVSIBZ => EABase::from_u8(EABase::RegZMM0 as u8 + index),
            _ => {
                eprintln!("Unhandled register type");
                None
            }
        }
    }

    /*
     * fixup_reg - Consults an operand specifier to determine which of the
     *   fixup*Value functions to use in correcting readModRM()'ss interpretation.
     *
     * @param insn  - See fixup*Value().
     * @param op    - The operand specifier.
     * @return      - 0 if fixup was successful; -1 if the register returned was
     *                invalid for its class.
     */
    fn fixup_reg(&mut self, op: &OperandSpecifier) -> bool {
        eprintln!("fixup_reg()");

        match op.encoding {
            OperandEncoding::VVVV => {
                if let Some(vvvv) = self.fixup_reg_value(op.typ, self.vvvv as u8) {
                    self.vvvv = vvvv;
                    true
                } else {
                    false
                }
            }
            OperandEncoding::REG => {
                if let Some(reg) =
                    self.fixup_reg_value(op.typ, self.reg as u8 - self.reg_base as u8)
                {
                    self.reg = reg;
                    true
                } else {
                    false
                }
            }
            OperandEncoding::RM
            | OperandEncoding::RM_CD2
            | OperandEncoding::RM_CD4
            | OperandEncoding::RM_CD8
            | OperandEncoding::RM_CD16
            | OperandEncoding::RM_CD32
            | OperandEncoding::RM_CD64 => {
                if self.ea_base >= self.ea_reg_base {
                    if let Some(base) =
                        self.fixup_rm_value(op.typ, self.ea_base as u8 - self.ea_reg_base as u8)
                    {
                        self.ea_base = base;
                        true
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            _ => {
                eprintln!("Expected a REG or R/M encoding in fixup_reg");
                false
            }
        }
    }

    fn get_instr_name(spec: usize) -> &'static str {
        INSTRUCTION_NAMES[spec]
    }

    pub fn name(&self) -> &'static str {
        Self::get_instr_name(self.instructionID)
    }
}

pub fn decode_operand(
    insn: &mut Instruction,
    mut op_spec: OperandSpecifier,
    width: usize,
) -> Result<(Vec<Statement>, Value, Vec<Statement>)> {
    match op_spec.encoding {
        OperandEncoding::NONE => Err(format!("invalid operand encoding").into()),
        OperandEncoding::REG => {
            if let Some(r) = insn.reg.as_var() {
                Ok((Vec::default(), r.into(), Vec::default()))
            } else {
                Err(format!("invalid register operand").into())
            }
        }
        OperandEncoding::RM
        | OperandEncoding::RM_CD2
        | OperandEncoding::RM_CD4
        | OperandEncoding::RM_CD8
        | OperandEncoding::RM_CD16
        | OperandEncoding::RM_CD32
        | OperandEncoding::RM_CD64
        | OperandEncoding::VSIB
        | OperandEncoding::VSIB_CD2
        | OperandEncoding::VSIB_CD4
        | OperandEncoding::VSIB_CD8
        | OperandEncoding::VSIB_CD16
        | OperandEncoding::VSIB_CD32
        | OperandEncoding::VSIB_CD64 => match op_spec.typ {
            OperandType::R8
            | OperandType::R16
            | OperandType::R32
            | OperandType::R64
            | OperandType::Rv
            | OperandType::MM64
            | OperandType::XMM
            | OperandType::YMM
            | OperandType::ZMM
            | OperandType::VK
            | OperandType::DEBUGREG
            | OperandType::CONTROLREG
            | OperandType::BNDR => Ok((
                Vec::default(),
                decode_rm_register(insn, width)?,
                Vec::default(),
            )),
            OperandType::M
            | OperandType::MVSIBX
            | OperandType::MVSIBY
            | OperandType::MVSIBZ => Ok((
                Vec::default(),
                decode_rm_memory(insn, width)?,
                Vec::default(),
            )),
            _ => unimplemented!(),
        },
        OperandEncoding::VVVV => {
            Ok((Vec::default(), insn.vvvv.as_var().unwrap().into(), Vec::default()))
        }
        OperandEncoding::WRITEMASK => Ok((
            Vec::default(),
            insn.writemask.as_var().unwrap().into(),
            Vec::default(),
        )),
        OperandEncoding::IB
        | OperandEncoding::IW
        | OperandEncoding::ID
        | OperandEncoding::IO
        | OperandEncoding::Iv
        | OperandEncoding::Ia => {
            let imm = decode_immediate(
                insn,
                insn.immediates[insn.numImmediatesTranslated as usize],
                op_spec,
                width,
            )?;
            insn.numImmediatesTranslated += 1;
            Ok((Vec::default(), imm, Vec::default()))
        }
        OperandEncoding::RB
        | OperandEncoding::RW
        | OperandEncoding::RD
        | OperandEncoding::RO
        | OperandEncoding::Rv => {
            if let Some(r) = insn.opcodeRegister.as_var() {
                Ok((Vec::default(), r.into(), Vec::default()))
            } else {
                Err(format!("invalid register operand").into())
            }
        }
        OperandEncoding::FP => {
            let r = match insn.modrm & 7 {
                0 => Variable::new2("ST0", None, 80)?,
                1 => Variable::new2("ST1", None, 80)?,
                2 => Variable::new2("ST2", None, 80)?,
                3 => Variable::new2("ST3", None, 80)?,
                4 => Variable::new2("ST4", None, 80)?,
                5 => Variable::new2("ST5", None, 80)?,
                6 => Variable::new2("ST6", None, 80)?,
                7 => Variable::new2("ST7", None, 80)?,
                _ => unreachable!(),
            };

            Ok((Vec::default(), r.into(), Vec::default()))
        }
        OperandEncoding::IRC => Ok((
            Vec::default(),
            Value::val(insn.RC as u64, width as u16).unwrap(),
            Vec::default(),
        )),
        OperandEncoding::DUP => {
            let idx = op_spec.typ as usize - OperandType::DUP0 as usize;

            decode_operand(insn, insn.operands.unwrap()[idx].clone(), width)
        }
        OperandEncoding::SI => Ok((Vec::default(), decode_src_index(insn)?.into(), Vec::default())),
        OperandEncoding::DI => Ok((Vec::default(), decode_dst_index(insn)?.into(), Vec::default())),
    }
}

/// translateSrcIndex   - Appends a source index operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction.
pub fn decode_src_index(insn: &Instruction) -> Result<Variable> {
    let base_reg = match (insn.mode, insn.hasAdSize) {
        (Mode::Long, false) => Variable::new2("RSI", None, 64).unwrap(), 
        (Mode::Long, true) => Variable::new2("ESI", None, 32).unwrap(), 
        (Mode::Protected, false) => Variable::new2("ESI", None, 32).unwrap(), 
        (Mode::Protected, true) => Variable::new2("SI", None, 16).unwrap(), 
        (Mode::Real, false) => Variable::new2("SI", None, 16).unwrap(), 
        (Mode::Real, true) => Variable::new2("ESI", None, 32).unwrap(), 
    };
    let segmentReg = match insn.segmentOverride {
        SegmentOverride::None => None,
        SegmentOverride::CS => Some(Reg::CS),
        SegmentOverride::DS => Some(Reg::DS),
        SegmentOverride::ES => Some(Reg::ES),
        SegmentOverride::FS => Some(Reg::FS),
        SegmentOverride::GS => Some(Reg::GS),
        SegmentOverride::SS => Some(Reg::SS),
    };

    Ok(base_reg)
}

/// translateDstIndex   - Appends a destination index operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction.

pub fn decode_dst_index(insn: &Instruction) -> Result<Variable> {
    match (insn.mode, insn.hasAdSize) {
        (Mode::Long, false) => Variable::new2("RDI", None, 64), 
        (Mode::Long, true) => Variable::new2("EDI", None, 32), 
        (Mode::Protected, false) => Variable::new2("EDI", None, 32), 
        (Mode::Protected, true) => Variable::new2("DI", None, 16), 
        (Mode::Real, false) => Variable::new2("DI", None, 16), 
        (Mode::Real, true) => Variable::new2("EDI", None, 32), 
    }
}

/// translateRMRegister - Translates a register stored in the R/M field of the
///   ModR/M byte to its LLVM equivalent and appends it to an MCInst.
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction to extract the R/M field
///                       from.
/// @return             - 0 on success; -1 otherwise
pub fn decode_rm_register(insn: &Instruction, width: usize) -> Result<Value> {
    if insn.ea_base == EABase::Basesib || insn.ea_base == EABase::Basesib64 {
        return Err(format!("A R/M register operand may not have a SIB byte").into());
    }

    if let Some(r) = insn.ea_base.as_var() {
        Ok(r.into())
    } else {
        Err(
            format!("A R/M register operand may not have a base; the operand must be a register.")
                .into(),
        )
    }
}

pub fn decode_rm_memory(insn: &Instruction, width: usize) -> Result<Value> {
    // Addresses in an MCInst are represented as five operands:
    //   1. basereg       (register)  The R/M base, or (if there is a SIB) the
    //                                SIB base
    //   2. scaleamount   (immediate) 1, or (if there is a SIB) the specified
    //                                scale amount
    //   3. indexreg      (register)  x86_registerNONE, or (if there is a SIB)
    //                                the index (which is multiplied by the
    //                                scale amount)
    //   4. displacement  (immediate) 0, or the displacement if there is one
    //   5. segmentreg    (register)  x86_registerNONE for now, but could be set
    //                                if we have segment overrides

    let baseReg;
    let scaleAmount;
    let indexReg;
    let displacement;
    let segmentReg;
    let pcrel = 0;

    if insn.ea_base == EABase::Basesib || insn.ea_base == EABase::Basesib64 {
        if insn.sib_base != SIBBase::None {
            baseReg = insn.sib_base.as_var();
        } else {
            baseReg = None;
        }

        if insn.sib_index != SIBIndex::None {
            indexReg = insn.sib_index.as_var();
        } else {
            // Use EIZ/RIZ for a few ambiguous cases where the SIB byte is present,
            // but no index is used and modrm alone should have been enough.
            // -No base register in 32-bit mode. In 64-bit mode this is used to
            //  avoid rip-relative addressing.
            // -Any base register used other than ESP/RSP/R12D/R12. Using these as a
            //  base always requires a SIB byte.
            // -A scale other than 1 is used.
            if insn.sib_scale != 1
                || (insn.sib_base == SIBBase::None && insn.mode != Mode::Long)
                || (insn.sib_base != SIBBase::None
                    && insn.sib_base != SIBBase::ESP
                    && insn.sib_base != SIBBase::RSP
                    && insn.sib_base != SIBBase::R12D
                    && insn.sib_base != SIBBase::R12)
            {
                indexReg = if insn.addressSize == 4 {
                    Variable::new2("EIZ", None, 32).ok()
                } else {
                    Variable::new2("RIZ", None, 64).ok()
                }
            } else {
                indexReg = None;
            }
        }

        scaleAmount = Value::val(insn.sib_scale as u64, insn.addressSize as u16);
    } else {
        match insn.ea_base {
            EABase::BaseNone => {
                if insn.ea_displ == EADisplacement::DispNone {
                    return Err("EA_BASE_NONE and EA_DISP_NONE for ModR/M base".into());
                }
                if insn.mode == Mode::Long {
                    //pcrel = insn.startLocation + insn.displacementOffset + insn.displacementSize;
                    //tryAddingPcLoadReferenceComment(
                    //    insn.startLocation + insn.displacementOffset,
                    //    insn.displacement + pcrel,
                    //    Dis,
                    //);
                    // Section 2.2.1.6
                    if insn.addressSize == 4 {
                        baseReg = Variable::new2("EIP", None, 32).ok();
                    } else {
                        baseReg = Variable::new2("RIP", None, 64).ok();
                    }
                } else {
                    baseReg = None;
                }

                indexReg = None;
            }
            EABase::BaseBX_SI => {
                baseReg = Variable::new2("BX", None, 16).ok();
                indexReg = Variable::new2("SI", None, 16).ok();
            }
            EABase::BaseBX_DI => {
                baseReg = Variable::new2("BX", None, 16).ok();
                indexReg = Variable::new2("DI", None, 16).ok();
            }
            EABase::BaseBP_SI => {
                baseReg = Variable::new2("BP", None, 16).ok();
                indexReg = Variable::new2("SI", None, 16).ok();
            }
            EABase::BaseBP_DI => {
                baseReg = Variable::new2("BP", None, 16).ok();
                indexReg = Variable::new2("DI", None, 16).ok();
            }
            _ => {
                // Here, we will use the fill-ins defined above.  However,
                //   BX_SI, BX_DI, BP_SI, and BP_DI are all handled above and
                //   sib and sib64 were handled in the top-level if, so they're only
                //   placeholders to keep the compiler happy.
                let maybeIdxReg = insn.ea_base.as_base_var();

                if let Some(r) = maybeIdxReg {
                    indexReg = Some(r);
                } else {
                    return Err(format!("A R/M memory operand may not be a register; the base field must be a base.").into());
                }
            }
        }

        scaleAmount = Value::val(1, insn.addressSize as u16);
    }

    displacement = Value::val(insn.displacement as u64, insn.addressSize as u16);
    segmentReg = match insn.segmentOverride {
        SegmentOverride::None => None,
        SegmentOverride::CS => Some(Reg::CS),
        SegmentOverride::DS => Some(Reg::DS),
        SegmentOverride::ES => Some(Reg::ES),
        SegmentOverride::FS => Some(Reg::FS),
        SegmentOverride::GS => Some(Reg::GS),
        SegmentOverride::SS => Some(Reg::SS),
    };

    //mcInst.addOperand(baseReg);
    //mcInst.addOperand(scaleAmount);
    //mcInst.addOperand(indexReg);
    //if (!tryAddingSymbolicOperand(
    //    insn.displacement + pcrel,
    //    false,
    //    insn.startLocation,
    //    insn.displacementOffset,
    //    insn.displacementSize,
    //    mcInst,
    //    Dis,
    //)) {
    //    mcInst.addOperand(displacement);
    //}
    //mcInst.addOperand(segmentReg);

    Variable::new2("tt", None, width as u16).map(|x| x.into())
}

/// translateImmediate  - Appends an immediate operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param immediate    - The immediate value to append.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The internal instruction.
fn decode_immediate(insn: &Instruction, mut immediate: u64, op: OperandSpecifier, width: usize) -> Result<Value> {
    // Sign-extend the immediate if necessary.

    //let mut isBranch = false;
    //let mut pcrel = 0;

    if op.typ == OperandType::REL {
        //isBranch = true;
        //pcrel = insn.startLocation + insn.immediateOffset + insn.immediateSize;
        match op.encoding {
            OperandEncoding::Iv => match insn.displacementSize {
                1 => {
                    if immediate & 0x80 != 0 {
                        immediate |= !(0xffu64);
                    }
                }
                2 => {
                    if immediate & 0x8000 != 0 {
                        immediate |= !(0xffffu64);
                    }
                }
                4 => {
                    if immediate & 0x80000000 != 0 {
                        immediate |= !(0xffffffffu64);
                    }
                }
                8 => {}
                _ => {}
            },
            OperandEncoding::IB => {
                if immediate & 0x80 != 0 {
                    immediate |= !(0xffu64);
                }
            }
            OperandEncoding::IW => {
                if immediate & 0x8000 != 0 {
                    immediate |= !(0xffffu64);
                }
            }
            OperandEncoding::ID => {
                if immediate & 0x80000000 != 0 {
                    immediate |= !(0xffffffffu64);
                }
            }
            _ => {}
        }
    }
    // By default sign-extend all X86 immediates based on their encoding.
    else if op.typ == OperandType::IMM {
        match op.encoding {
            OperandEncoding::IB => {
                if immediate & 0x80 != 0 {
                    immediate |= !(0xffu64);
                }
            }
            OperandEncoding::IW => {
                if immediate & 0x8000 != 0 {
                    immediate |= !(0xffffu64);
                }
            }
            OperandEncoding::ID => {
                if immediate & 0x80000000 != 0 {
                    immediate |= !(0xffffffffu64);
                }
            }
            OperandEncoding::IO => {}
            _ => {}
        }
    }

    match op.typ {
        OperandType::XMM => Ok(Reg::from_u8(Reg::XMM0 as u8 + (immediate as u8 >> 4)).unwrap().as_var().unwrap().into()),
        OperandType::YMM => Ok(Reg::from_u8(Reg::YMM0 as u8 + (immediate as u8 >> 4)).unwrap().as_var().unwrap().into()),
        OperandType::ZMM => Ok(Reg::from_u8(Reg::ZMM0 as u8 + (immediate as u8 >> 4)).unwrap().as_var().unwrap().into()),
        _ => {
            //if !tryAddingSymbolicOperand(
            //    immediate + pcrel,
            //    isBranch,
            //    insn.startLocation,
            //    insn.immediateOffset,
            //    insn.immediateSize,
            //    mcInst,
            //    Dis,
            //) {
            let imm = Constant::new(immediate, width as u16)?;

            //if op.typ == OperandType::MOFFS {
            //    let segmentReg = MCOperand::createReg(segmentRegnums[insn.segmentOverride]);
            //    mcInst.addOperand(segmentReg);
            //}
            let segmentReg = match insn.segmentOverride {
                SegmentOverride::None => None,
                SegmentOverride::CS => Some(Reg::CS),
                SegmentOverride::DS => Some(Reg::DS),
                SegmentOverride::ES => Some(Reg::ES),
                SegmentOverride::FS => Some(Reg::FS),
                SegmentOverride::GS => Some(Reg::GS),
                SegmentOverride::SS => Some(Reg::SS),
            };

            Ok(imm.into())
        }
    }
}
