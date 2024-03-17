use std::{
    io::prelude::{Read, Seek},
    mem::take,
};

use binrw::{BinRead, BinResult};
use coriander_parser::metadata::{Token, TokenType, UserStringIdx};
use indexmap::IndexMap;

use crate::{
    AggregatePrefix,
    ArithmeticKind::{NonOverflowing, SignedOverflow, UnsignedOverflow},
    Constant, ConversionType, ElementLoadType, ElementStoreType, Instruction as I,
    InstructionLoadType, InstructionPoint, InstructionPrefix, InstructionRef, InstructionStoreType,
    InstructionTable, IntegerType as Int, PrefixFlags,
    Signage::{Signed, Unsigned},
    SkippedChecks,
};

fn read_i32_ir<R: Read + Seek>(reader: &mut R, offset: usize) -> BinResult<InstructionRef> {
    let x = i32::read_le(reader)? as isize;
    let idx = if x.is_negative() {
        offset - x.wrapping_abs() as u32 as usize
    } else {
        offset + x as usize
    };
    Ok(InstructionRef::new_thin(idx))
}

fn read_i8_ir<R: Read + Seek>(reader: &mut R, offset: usize) -> BinResult<InstructionRef> {
    let x = i8::read_le(reader)? as isize;
    let idx = if x.is_negative() {
        offset - x.wrapping_abs() as u8 as usize
    } else {
        offset + x as usize
    };
    Ok(InstructionRef::new_thin(idx))
}

fn read_token<R: Read + Seek, T: TokenType + ?Sized + 'static>(
    reader: &mut R,
) -> BinResult<Token<T>> {
    let token = Token::<()>::read_le(reader)?;
    token.retype().ok_or(()).or_else(|_| {
        Err(binrw::Error::Custom {
            pos: reader.stream_position()? - 4,
            err: Box::new(format!(
                "the table {:?} was not valid for a token of type {}",
                token.table_id(),
                std::any::type_name::<T>()
            )),
        })
    })
}

enum StreamElement {
    Instruction(I),
    Prefix(InstructionPrefix),
}

fn stream_instruction<R: Read + Seek>(
    reader: &mut R,
    current_idx: usize,
) -> BinResult<StreamElement> {
    let a = u8::read_le(reader)?;
    let i = match a {
        // 1-byte base instructions:
        0x58 => I::Add(NonOverflowing),
        0xd6 => I::Add(SignedOverflow),
        0xd7 => I::Add(UnsignedOverflow),
        0x5f => I::And,
        0x3b => I::Beq(read_i32_ir(reader, current_idx)?),
        0x2e => I::Beq(read_i8_ir(reader, current_idx)?),
        0x3c => I::Bge {
            sign: Signed,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x2f => I::Bge {
            sign: Signed,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x41 => I::Bge {
            sign: Unsigned,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x34 => I::Bge {
            sign: Unsigned,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x3d => I::Bgt {
            sign: Signed,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x30 => I::Bgt {
            sign: Signed,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x42 => I::Bgt {
            sign: Unsigned,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x35 => I::Bgt {
            sign: Unsigned,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x3e => I::Ble {
            sign: Signed,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x31 => I::Ble {
            sign: Signed,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x43 => I::Ble {
            sign: Unsigned,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x36 => I::Ble {
            sign: Unsigned,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x3f => I::Blt {
            sign: Signed,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x32 => I::Blt {
            sign: Signed,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x44 => I::Blt {
            sign: Unsigned,
            target: read_i32_ir(reader, current_idx)?,
        },
        0x37 => I::Blt {
            sign: Unsigned,
            target: read_i8_ir(reader, current_idx)?,
        },
        0x40 => I::BneUnsigned(read_i32_ir(reader, current_idx)?),
        0x33 => I::BneUnsigned(read_i8_ir(reader, current_idx)?),
        0x38 => I::Br(read_i32_ir(reader, current_idx)?),
        0x2b => I::Br(read_i8_ir(reader, current_idx)?),
        0x01 => I::Break,
        0x39 => I::BrFalse(read_i32_ir(reader, current_idx)?),
        0x2c => I::BrFalse(read_i8_ir(reader, current_idx)?),
        0x3a => I::BrTrue(read_i32_ir(reader, current_idx)?),
        0x2d => I::BrTrue(read_i8_ir(reader, current_idx)?),
        0x28 => I::Call(read_token(reader)?),
        0x29 => I::CallIndirect(read_token(reader)?),
        0xc3 => I::Ckfinite,
        0x67 => I::Conv(ConversionType::Int(Int::I1)),
        0x68 => I::Conv(ConversionType::Int(Int::I2)),
        0x69 => I::Conv(ConversionType::Int(Int::I4)),
        0x6a => I::Conv(ConversionType::Int(Int::I8)),
        0x6b => I::Conv(ConversionType::R4),
        0x6c => I::Conv(ConversionType::R8),
        0xd2 => I::Conv(ConversionType::Int(Int::U1)),
        0xd1 => I::Conv(ConversionType::Int(Int::U2)),
        0x6d => I::Conv(ConversionType::Int(Int::U4)),
        0x6e => I::Conv(ConversionType::Int(Int::U8)),
        0xd3 => I::Conv(ConversionType::Int(Int::I)),
        0xe0 => I::Conv(ConversionType::Int(Int::U)),
        0x76 => I::Conv(ConversionType::R),
        0xb3 => I::Conv(ConversionType::OvfSigned(Int::I1)),
        0xb5 => I::Conv(ConversionType::OvfSigned(Int::I2)),
        0xb7 => I::Conv(ConversionType::OvfSigned(Int::I4)),
        0xb9 => I::Conv(ConversionType::OvfSigned(Int::I8)),
        0xb4 => I::Conv(ConversionType::OvfSigned(Int::U1)),
        0xb6 => I::Conv(ConversionType::OvfSigned(Int::U2)),
        0xb8 => I::Conv(ConversionType::OvfSigned(Int::U4)),
        0xba => I::Conv(ConversionType::OvfSigned(Int::U8)),
        0xd4 => I::Conv(ConversionType::OvfSigned(Int::I)),
        0xd5 => I::Conv(ConversionType::OvfSigned(Int::U)),
        0x82 => I::Conv(ConversionType::OvfUnsigned(Int::I1)),
        0x83 => I::Conv(ConversionType::OvfUnsigned(Int::I2)),
        0x84 => I::Conv(ConversionType::OvfUnsigned(Int::I4)),
        0x85 => I::Conv(ConversionType::OvfUnsigned(Int::I8)),
        0x86 => I::Conv(ConversionType::OvfUnsigned(Int::U1)),
        0x87 => I::Conv(ConversionType::OvfUnsigned(Int::U2)),
        0x88 => I::Conv(ConversionType::OvfUnsigned(Int::U4)),
        0x89 => I::Conv(ConversionType::OvfUnsigned(Int::U8)),
        0x8a => I::Conv(ConversionType::OvfUnsigned(Int::I)),
        0x8b => I::Conv(ConversionType::OvfUnsigned(Int::U)),
        0x5b => I::Div(Signed),
        0x5c => I::Div(Unsigned),
        0x25 => I::Dup,
        0xdc => I::EndFault,
        0x27 => I::Jmp(read_token(reader)?),
        0x0e => I::LdArg(u8::read_le(reader)?.into()),
        0x02 => I::LdArg(0),
        0x03 => I::LdArg(1),
        0x04 => I::LdArg(2),
        0x05 => I::LdArg(3),
        0x0f => I::LdArgAddr(u8::read_le(reader)?.into()),
        0x20 => I::Ldc(Constant::Int32(i32::read_le(reader)?)),
        0x21 => I::Ldc(Constant::Int64(i64::read_le(reader)?)),
        0x22 => I::Ldc(Constant::Float32(f32::read_le(reader)?)),
        0x23 => I::Ldc(Constant::Float64(f64::read_le(reader)?)),
        0x16 => I::Ldc(Constant::Int32(0)),
        0x17 => I::Ldc(Constant::Int32(1)),
        0x18 => I::Ldc(Constant::Int32(2)),
        0x19 => I::Ldc(Constant::Int32(3)),
        0x1a => I::Ldc(Constant::Int32(4)),
        0x1b => I::Ldc(Constant::Int32(5)),
        0x1c => I::Ldc(Constant::Int32(6)),
        0x1d => I::Ldc(Constant::Int32(7)),
        0x1e => I::Ldc(Constant::Int32(8)),
        0x15 => I::Ldc(Constant::Int32(-1)),
        0x1f => I::Ldc(Constant::Int32(i8::read_le(reader)?.into())),
        0x46 => I::LdInd(InstructionLoadType::I1),
        0x48 => I::LdInd(InstructionLoadType::I2),
        0x4a => I::LdInd(InstructionLoadType::I4),
        // this is.. by far.. /the/ most unreliable document i have /ever/ read.
        0x4c => I::LdInd(InstructionLoadType::I8OrU8),
        0x47 => I::LdInd(InstructionLoadType::U1),
        0x49 => I::LdInd(InstructionLoadType::U2),
        0x4b => I::LdInd(InstructionLoadType::U4),
        0x4e => I::LdInd(InstructionLoadType::R4),
        0x4f => I::LdInd(InstructionLoadType::R8),
        0x4d => I::LdInd(InstructionLoadType::I),
        0x50 => I::LdInd(InstructionLoadType::Ref),
        0x11 => I::LdLoc(u8::read_le(reader)?.into()),
        0x06 => I::LdLoc(0),
        0x07 => I::LdLoc(1),
        0x08 => I::LdLoc(2),
        0x09 => I::LdLoc(3),
        0x12 => I::LdLocAddr(u8::read_le(reader)?.into()),
        0x14 => I::LdNull,
        0xdd => I::Leave(read_i32_ir(reader, current_idx)?),
        0xde => I::Leave(read_i8_ir(reader, current_idx)?),
        0x5a => I::Mul(NonOverflowing),
        0xd8 => I::Mul(SignedOverflow),
        0xd9 => I::Mul(UnsignedOverflow),
        0x65 => I::Neg,
        0x00 => I::Nop,
        0x66 => I::Not,
        0x60 => I::Or,
        0x26 => I::Pop,
        0x5d => I::Rem(Signed),
        0x5e => I::Rem(Unsigned),
        0x2a => I::Ret,
        0x62 => I::Shl,
        0x63 => I::Shr(Signed),
        0x64 => I::Shr(Unsigned),
        0x10 => I::StArg(u8::read_le(reader)?.into()),
        0x52 => I::StInd(InstructionStoreType::I1),
        0x53 => I::StInd(InstructionStoreType::I2),
        0x54 => I::StInd(InstructionStoreType::I4),
        0x55 => I::StInd(InstructionStoreType::I8),
        0x56 => I::StInd(InstructionStoreType::R4),
        0x57 => I::StInd(InstructionStoreType::R8),
        0xdf => I::StInd(InstructionStoreType::I),
        0x51 => I::StInd(InstructionStoreType::Ref),
        0x13 => I::StLoc(u8::read_le(reader)?.into()),
        0x0a => I::StLoc(0),
        0x0b => I::StLoc(1),
        0x0c => I::StLoc(2),
        0x0d => I::StLoc(3),
        0x59 => I::Sub(NonOverflowing),
        0xda => I::Sub(SignedOverflow),
        0xdb => I::Sub(UnsignedOverflow),
        0x45 => {
            let len = u32::read_le(reader)? as usize;
            let mut branches = Vec::new();
            for _ in 0..len {
                branches.push(read_i32_ir(reader, current_idx)?);
            }
            I::Switch(branches)
        }
        0x61 => I::Xor,

        // object model instructions:
        0x8c => I::Box(read_token(reader)?),
        0x6f => I::CallVirt(read_token(reader)?),
        0x74 => I::CastClass(read_token(reader)?),
        0x70 => I::CpObj(read_token(reader)?),
        0x75 => I::IsInst(read_token(reader)?),
        0xa3 => I::LdElem(read_token(reader).map(ElementLoadType::Other)?),
        0x90 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::I1)),
        0x92 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::I2)),
        0x94 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::I4)),
        0x96 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::I8OrU8)),
        0x91 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::U1)),
        0x93 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::U2)),
        0x95 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::U4)),
        0x98 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::R4)),
        0x99 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::R8)),
        0x97 => I::LdElem(ElementLoadType::Inline(InstructionLoadType::I)),
        0x9a => I::LdElem(ElementLoadType::Inline(InstructionLoadType::Ref)),
        0x8f => I::LdElemAddr(read_token(reader)?),
        0x7b => I::LdFld(read_token(reader)?),
        0x7c => I::LdFldAddr(read_token(reader)?),
        0x8e => I::LdLen,
        0x71 => I::LdObj(read_token(reader)?),
        0x7e => I::LdSfld(read_token(reader)?),
        0x7f => I::LdSfldAddr(read_token(reader)?),
        0x72 => I::LdStr(UserStringIdx::read_le(reader)?),
        0xd0 => I::LdToken(read_token(reader)?),
        0xc6 => I::MkRefAny(read_token(reader)?),
        0x8d => I::NewArr(read_token(reader)?),
        0x73 => I::NewObj(read_token(reader)?),
        0xc2 => I::RefAnyVal(read_token(reader)?),
        0xa4 => I::StElem(read_token(reader).map(ElementStoreType::Other)?),
        0x9c => I::StElem(ElementStoreType::Inline(InstructionStoreType::I1)),
        0x9d => I::StElem(ElementStoreType::Inline(InstructionStoreType::I2)),
        0x9e => I::StElem(ElementStoreType::Inline(InstructionStoreType::I4)),
        0x9f => I::StElem(ElementStoreType::Inline(InstructionStoreType::I8)),
        0xa0 => I::StElem(ElementStoreType::Inline(InstructionStoreType::R4)),
        0xa1 => I::StElem(ElementStoreType::Inline(InstructionStoreType::R8)),
        0x9b => I::StElem(ElementStoreType::Inline(InstructionStoreType::I)),
        0xa2 => I::StElem(ElementStoreType::Inline(InstructionStoreType::Ref)),
        0x7d => I::StFld(read_token(reader)?),
        0x81 => I::StObj(read_token(reader)?),
        0x80 => I::StSfld(read_token(reader)?),
        0x7a => I::Throw,
        0x79 => I::Unbox(read_token(reader)?),

        // 2-byte instructions:
        0xfe => {
            let b = u8::read_le(reader)?;
            match b {
                // base instructions:
                0x00 => I::Arglist,
                0x01 => I::Ceq,
                0x02 => I::Cgt(Signed),
                0x03 => I::Cgt(Unsigned),
                0x04 => I::Clt(Signed),
                0x05 => I::Clt(Unsigned),
                0x17 => I::Cpblk,
                0x11 => I::EndFilter,
                0x18 => I::InitBlk,
                0x09 => I::LdArg(u16::read_le(reader)?),
                0x0a => I::LdArgAddr(u16::read_le(reader)?),
                0x06 => I::LdFtn(read_token(reader)?),
                0x0c => I::LdLoc(u16::read_le(reader)?),
                0x0d => I::LdLocAddr(u16::read_le(reader)?),
                0x0f => I::LocAlloc,
                0x0b => I::StArg(u16::read_le(reader)?),
                0x0e => I::StLoc(u16::read_le(reader)?),

                // object model instructions:
                0x15 => I::CpObj(read_token(reader)?),
                0x07 => I::LdVirtFn(read_token(reader)?),
                0x1d => I::RefAnyType,
                0x1a => I::Rethrow,
                0x1c => I::SizeOf(read_token(reader)?),

                // prefixes:
                0x16 => {
                    let prefix = InstructionPrefix::Constrained(read_token(reader)?);
                    return Ok(StreamElement::Prefix(prefix));
                }
                0x19 => {
                    let prefix = InstructionPrefix::No(SkippedChecks::read_le(reader)?);
                    return Ok(StreamElement::Prefix(prefix));
                }
                0x1e => {
                    let prefix = InstructionPrefix::Readonly;
                    return Ok(StreamElement::Prefix(prefix));
                }
                0x14 => {
                    let prefix = InstructionPrefix::Tail;
                    return Ok(StreamElement::Prefix(prefix));
                }
                0x12 => {
                    let prefix = InstructionPrefix::Unaligned(u8::read_le(reader)?);
                    return Ok(StreamElement::Prefix(prefix));
                }
                0x13 => {
                    let prefix = InstructionPrefix::Volatile;
                    return Ok(StreamElement::Prefix(prefix));
                }
                _ => todo!(),
            }
        }
        _ => todo!(),
    };

    Ok(StreamElement::Instruction(i))
}

impl BinRead for InstructionTable {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: binrw::Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut table = InstructionTable::default();
        let mut prefix = AggregatePrefix::default();
        let mut current_idx = 0;
        loop {
            let element = stream_instruction(reader, current_idx)?;
            current_idx += 1;
            match element {
                StreamElement::Instruction(instruction) => {
                    table.push(InstructionPoint {
                        prefix: take(&mut prefix),
                        instruction,
                    });
                }
                // todo: verify prefixes are only used on the correct instructions.
                StreamElement::Prefix(p) => {
                    prefix.len += 1;
                    match p {
                        InstructionPrefix::Constrained(t) => {
                            prefix.type_constraint = Some(t);
                        }
                        InstructionPrefix::No(skip) => prefix.skipped_checks |= skip,
                        InstructionPrefix::Readonly => prefix.flags |= PrefixFlags::READONLY,
                        InstructionPrefix::Tail => prefix.flags |= PrefixFlags::TAIL,
                        InstructionPrefix::Volatile => prefix.flags |= PrefixFlags::VOLATILE,
                        InstructionPrefix::Unaligned(u) => prefix.alignment = Some(u),
                    }
                }
            }
        }
    }
}
