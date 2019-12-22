/*
 * Panopticon - A libre disassembler
 * Copyright (C) 2015, 2017  Panopticon authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::borrow::Cow;

use p8n_types::{
    Architecture,
    Region,
    Match,
    Result,
};

use crate::common::Mode;
use crate::decoder::Instruction;
use crate::semantics::SEMANTICS;

#[derive(Clone,Debug)]
pub enum Amd64 {}

impl Architecture for Amd64 {
    type Configuration = Mode;

    fn prepare(_: &Region, _: &Self::Configuration) -> Result<Cow<'static, [(&'static str, u64, &'static str)]>> {
        Ok(Cow::Owned(vec![]))
    }

    fn decode(reg: &Region, start: u64, cfg: &Mode, _: &mut Vec<Match>) -> Result<()> {
        let mut buf: Vec<u8> = vec![0u8; 15];
        let mut p = start;
        let mut il = vec![];

        while p < reg.defined().end {
            eprintln!("read from {:#x}",p);
            reg.try_read(p, &mut buf[..])?;

            eprintln!("disass @ {:#x}: {:?}", p, buf);
            match Instruction::new(*cfg, &buf) {
                Some(mut insn) => {
                    eprintln!("    {} ({}, {} bytes)", insn.name(), insn.instructionID, insn.cursor);

                    il.clear();

                    match insn.semantics {
                        Some(sem) => {
                            sem(&mut insn, &mut il).unwrap();
                        }
                        None =>  {}
                    }

                    p += insn.cursor as u64;
                }
                None => { p += 1; }
            }
        }
        //matches.push(ret);
        Ok(())
    }
}
