use core::slice;
use std::io::{Read, Seek, SeekFrom, Write};

use binrw::{BinRead, BinResult, BinWrite, Endian};
use bitflags::bitflags;

use super::{token_categories::TypeDefOrRef, BlobInt, MetaWrite, Rid, TableIdx, Token};

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(cx: &MetaWrite))]
pub enum TypeSpecialised {
    #[brw(magic = 0xf_u8)]
    Ptr {
        #[br(parse_with = read_while_trying)]
        #[bw(args(cx))]
        modifiers: Vec<CustomModifier>,
        #[bw(args(cx))]
        type_: PtrType,
    },
    #[brw(magic = 0x14_u8)]
    Array {
        #[bw(args(cx))]
        inner: Type,
        shape: ArrayShape,
    },
    #[brw(magic = 0x15_u8)]
    GenericInst {
        #[bw(args(cx))]
        generic: DefinedType,
        #[br(temp)]
        #[bw(try_calc = arguments.len().try_into())]
        arguments_len: BlobInt,
        #[br(count(usize::from(arguments_len)))]
        #[bw(args(cx))]
        arguments: Vec<Type>,
    },
    #[brw(magic = 0x1b_u8)]
    FnPtr(#[bw(args(cx))] Box<MethodSig>),
    #[brw(magic = 0x1d_u8)]
    SzArray {
        #[br(parse_with = read_while_trying)]
        #[bw(args(cx))]
        modifiers: Vec<CustomModifier>,
        #[bw(args(cx))]
        type_: Type,
    },
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum DefinedType {
    #[brw(magic = 0x11_u8)]
    ValueType(
        #[br(parse_with = parse_type_def_or_ref)]
        #[bw(args_raw = cx, write_with = write_type_def_or_ref)]
        Token<TypeDefOrRef>,
    ),
    #[brw(magic = 0x12_u8)]
    Class(
        #[br(parse_with = parse_type_def_or_ref)]
        #[bw(args_raw = cx, write_with = write_type_def_or_ref)]
        Token<TypeDefOrRef>,
    ),
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum Type {
    #[brw(magic = 0x2_u8)]
    Boolean,
    #[brw(magic = 0x3_u8)]
    Char,
    #[brw(magic = 0x4_u8)]
    I1,
    #[brw(magic = 0x5_u8)]
    U1,
    #[brw(magic = 0x6_u8)]
    I2,
    #[brw(magic = 0x7_u8)]
    U2,
    #[brw(magic = 0x8_u8)]
    I4,
    #[brw(magic = 0x9_u8)]
    U4,
    #[brw(magic = 0xa_u8)]
    I8,
    #[brw(magic = 0xb_u8)]
    U8,
    #[brw(magic = 0xc_u8)]
    R4,
    #[brw(magic = 0xd_u8)]
    R8,
    #[brw(magic = 0xe_u8)]
    String,
    #[brw(magic = 0x13_u8)]
    Var(BlobInt),
    #[brw(magic = 0x18_u8)]
    I,
    #[brw(magic = 0x19_u8)]
    U,
    #[brw(magic = 0x1c_u8)]
    Object,
    #[brw(magic = 0x1e_u8)]
    MVar(BlobInt),
    #[brw(magic = 0x21_u8)]
    CliInternal,
    RefType(#[bw(args(cx))] DefinedType),
    TypeSpec(#[bw(args(cx))] Box<TypeSpecialised>),
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum PtrType {
    #[brw(magic = 0x1_u8)]
    Void,
    Type(#[bw(args(cx))] Type),
}

fn read_while_trying<'a, R: Read + Seek, T: BinRead + 'a>(
    reader: &mut R,
    endian: Endian,
    args: T::Args<'a>,
) -> BinResult<Vec<T>>
where
    T::Args<'a>: Clone,
{
    let mut elements = Vec::new();
    loop {
        let pos = reader.stream_position()?;
        let atmpt = T::read_options(reader, endian, args.clone());
        if let Ok(element) = atmpt {
            elements.push(element);
        } else {
            reader.seek(SeekFrom::Start(pos))?;
            return Ok(elements);
        }
    }
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum ParamType {
    #[brw(magic = 0x10_u8)]
    ByRef(#[bw(args(cx))] Type),
    #[brw(magic = 0x16_u8)]
    TypedByRef,
    Type(#[bw(args(cx))] Type),
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub struct Param {
    #[br(parse_with = read_while_trying)]
    #[bw(args(cx))]
    pub modifiers: Vec<CustomModifier>,
    #[bw(args(cx))]
    pub type_: ParamType,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum ReturnType {
    #[brw(magic = 0x1_u8)]
    Void,
    #[brw(magic = 0x10_u8)]
    ByRef(#[bw(args(cx))] Type),
    #[brw(magic = 0x16_u8)]
    TypedByRef,
    Type(#[bw(args(cx))] Type),
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub struct Return {
    #[br(parse_with = read_while_trying)]
    #[bw(args(cx))]
    pub modifiers: Vec<CustomModifier>,
    #[bw(args(cx))]
    pub type_: ReturnType,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum CustomModifier {
    #[brw(magic = 0x1f_u8)]
    #[doc(alias = "CModReqd")]
    Required(
        #[br(parse_with = parse_type_def_or_ref)]
        #[bw(args_raw = cx, write_with = write_type_def_or_ref)]
        Token<TypeDefOrRef>,
    ),
    #[brw(magic = 0x20_u8)]
    #[doc(alias = "CModOpt")]
    Optional(
        #[br(parse_with = parse_type_def_or_ref)]
        #[bw(args_raw = cx, write_with = write_type_def_or_ref)]
        Token<TypeDefOrRef>,
    ),
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct TypeElementModifier: u8 {
        const IS_MODIFIER = 0x40;
        const SENTINEL = 0x41;
        const PINNED = 0x45;
        const IS_TYPE = 0x50;
        const IS_BOXED_OBJECT = 0x51;
        #[doc(hidden)]
        const _RESERVED = 0x52;
        const FIELD = 0x53;
        const PROPERTY = 0x54;
        const ENUM = 0x55;
    }
}

bitflags_brw!(TypeElementModifier: u8);

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum TypeElement {
    #[br(assert(flags.contains(TypeElementModifier::IS_MODIFIER)))]
    Modifier {
        flags: TypeElementModifier,
    },
    Type(#[bw(args(cx))] Type),
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct MethodRefSigFlags: u8 {
        const HAS_THIS = 0x20;
        const EXPLICIT_THIS = 0x40;
        const VARARG = 0x5;
        const GENERIC = 0x10;
    }
}

#[derive(Debug, BinRead, BinWrite)]
pub enum CallingConvention {
    C,
    Stdcall,
    Thiscall,
    Fastcall,
    Default,
    VarArg {
        #[br(calc = None)]
        #[bw(ignore)]
        variadic_start: Option<usize>,
    },
    Generic {
        param_count: BlobInt,
    },
}

#[derive(Debug)]
pub enum This {
    None,
    Implicit,
    Explicit,
}

#[derive(Debug)]
pub struct MethodSig {
    pub instance: This,
    pub convention: CallingConvention,
    pub return_type: Return,
    pub params: Vec<Param>,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
enum VariadicParam {
    #[brw(magic = 0x41_u8)]
    Sentinel,
    Param(#[bw(args(cx))] Param),
}

impl BinRead for MethodSig {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut header = 0;
        reader.read_exact(slice::from_mut(&mut header))?;
        let instance = if (header & 0x20) != 0 {
            if (header & 0x40) != 0 {
                This::Explicit
            } else {
                This::Implicit
            }
        } else {
            This::None
        };
        let mut convention = if (header & 0x5) != 0 {
            CallingConvention::VarArg {
                variadic_start: None,
            }
        } else if (header & 0x10) != 0 {
            CallingConvention::Generic {
                param_count: BlobInt::read_options(reader, endian, ())?,
            }
        } else {
            CallingConvention::Default
        };
        let params_len: usize = BlobInt::read_options(reader, endian, ())?.into();
        let return_type = Return::read_options(reader, endian, ())?;
        let params = {
            let mut i = 0;
            let mut params = Vec::new();
            while i < params_len {
                let param = VariadicParam::read_options(reader, endian, ())?;
                match (param, &mut convention) {
                    (
                        VariadicParam::Sentinel,
                        CallingConvention::VarArg {
                            variadic_start: start @ None,
                        },
                    ) => {
                        *start = Some(i);
                        continue;
                    }
                    (
                        VariadicParam::Sentinel,
                        CallingConvention::VarArg {
                            variadic_start: Some(_),
                        },
                    ) => {
                        return Err(binrw::Error::Custom {
                            pos: reader.stream_position()?,
                            err: Box::new("second unexpected variadic sentinel"),
                        });
                    }
                    (VariadicParam::Sentinel, _) => {
                        return Err(binrw::Error::Custom {
                            pos: reader.stream_position()?,
                            err: Box::new("variadic sentinel found on non-variadic method"),
                        })
                    }
                    (VariadicParam::Param(param), _) => params.push(param),
                }
                i += 1;
            }
            params
        };
        Ok(Self {
            instance,
            convention,
            return_type,
            params,
        })
    }
}

impl BinWrite for MethodSig {
    type Args<'a> = (&'a MetaWrite,);

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        cx_tuple: Self::Args<'_>,
    ) -> BinResult<()> {
        let instance = match self.instance {
            This::None => 0,
            This::Implicit => 0x20,
            This::Explicit => 0x60,
        };
        let convention_header = match &self.convention {
            CallingConvention::Default => 0x0,
            CallingConvention::C => 0x1,
            CallingConvention::Stdcall => 0x2,
            CallingConvention::Thiscall => 0x3,
            CallingConvention::Fastcall => 0x4,
            CallingConvention::VarArg { .. } => 0x5,
            CallingConvention::Generic { .. } => 0x10,
        };
        writer.write(slice::from_ref(&(instance | convention_header)))?;
        let variadic_start = match self.convention {
            CallingConvention::VarArg { variadic_start } => variadic_start,
            CallingConvention::Generic { param_count } => {
                param_count.write_options(writer, endian, ())?;
                None
            }
            _ => None,
        };

        BlobInt::try_from(self.params.len())
            .or_else(|int| {
                Err(binrw::Error::Custom {
                    pos: writer.stream_position()?,
                    err: Box::new(int),
                })
            })?
            .write_options(writer, endian, ())?;
        self.return_type.write_options(writer, endian, cx_tuple)?;

        for param in &self.params[0..variadic_start.unwrap_or(self.params.len())] {
            param.write_options(writer, endian, cx_tuple)?;
        }
        if let Some(variadic_start) = variadic_start {
            0x41.write_options(writer, endian, ())?;
            for param in &self.params[variadic_start..] {
                param.write_options(writer, endian, cx_tuple)?;
            }
        }

        Ok(())
    }
}

pub fn parse_type_def_or_ref<R: Read + Seek>(
    reader: &mut R,
    endian: Endian,
    _: (),
) -> BinResult<Token<TypeDefOrRef>> {
    let BlobInt(encoded) = BlobInt::read_options(reader, endian, ())?;
    let table = match encoded & 0b11 {
        0 => TypeDefOrRef::TypeDef,
        1 => TypeDefOrRef::TypeRef,
        2 => TypeDefOrRef::TypeSpec,
        _ => {
            return Err(binrw::Error::BadMagic {
                pos: reader.stream_position()?,
                found: Box::new(encoded),
            })
        }
    };
    let rid = Rid::new(encoded >> 2).ok_or(()).or_else(|_| {
        Err(binrw::Error::BadMagic {
            pos: reader.stream_position()?,
            found: Box::new(encoded),
        })
    })?;

    Ok(Token {
        table,
        idx: TableIdx::from_rid(rid),
    })
}

pub fn write_type_def_or_ref<W: Write + Seek>(
    &token: &Token<TypeDefOrRef>,
    writer: &mut W,
    endian: Endian,
    cx: &MetaWrite,
) -> BinResult<()> {
    let rid = cx.token_rid(token)?;
    let encoded = (rid.to_u32() << 2) & (token.table as u32);
    BlobInt(encoded).write_options(writer, endian, ())
}

#[binrw::binrw]
#[derive(Debug)]
pub struct ArrayShape {
    pub rank: BlobInt,
    #[br(temp)]
    #[bw(try_calc = sizes.len().try_into())]
    sizes_len: BlobInt,
    #[br(count(usize::from(sizes_len)))]
    pub sizes: Vec<BlobInt>,
    #[br(temp)]
    #[bw(try_calc = lo_bounds.len().try_into())]
    lo_bounds_len: BlobInt,
    #[br(count(usize::from(lo_bounds_len)))]
    pub lo_bounds: Vec<BlobInt>,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub struct ModifiedType {
    #[br(parse_with = read_while_trying)]
    #[bw(args(cx))]
    pub modifiers: Vec<CustomModifier>,
    #[bw(args(cx))]
    pub type_: Type,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
#[brw(magic = 0x6_u8)]
pub struct FieldSig {
    #[bw(args(cx))]
    pub type_: ModifiedType,
}

#[derive(Debug, BinRead, BinWrite)]
pub enum Constraint {
    #[brw(magic = 0x45_u8)]
    Pinned,
}

// todo: this is abysmal.
#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum LocalVarModifier {
    Both {
        #[bw(args(cx))]
        modifier: CustomModifier,
        constraint: Constraint,
    },
    Modifier(#[bw(args(cx))] CustomModifier),
    Constriant(Constraint),
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum LocalVar {
    #[brw(magic = 0x10_u8)]
    #[br(assert({
        println!("{modifiers:?}\n >> {type_:?}");
        true
    }))]
    ByRef {
        #[br(parse_with = read_while_trying)]
        #[bw(args(cx))]
        modifiers: Vec<LocalVarModifier>,
        #[bw(args(cx))]
        type_: Type,
    },
    #[brw(magic = 0x16_u8)]
    #[br(pre_assert({
        println!("a woohoo!");
        true
    }))]
    TypedByRef,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(cx: &MetaWrite))]
#[brw(magic = 0x7_u8)]
pub struct LocalVarSig {
    #[br(temp)]
    #[bw(try_calc = vars.len().try_into())]
    vars_len: BlobInt,
    #[br(count(usize::from(vars_len)))]
    #[bw(args(cx))]
    pub vars: Vec<LocalVar>,
}

#[derive(Debug, BinRead, BinWrite)]
#[bw(import(cx: &MetaWrite))]
pub enum StandAloneSignature {
    LocalVars(#[bw(args(cx))] LocalVarSig),
    Method(#[bw(args(cx))] MethodSig),
}

#[derive(Debug, BinRead, BinWrite)]
pub enum ThisProperty {
    #[brw(magic = 0x8_u8)]
    None,
    #[brw(magic = 0x28_u8)]
    HasThis,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(cx: &MetaWrite))]
pub struct PropertySig {
    #[br(map = |this| matches!(this, ThisProperty::HasThis))]
    #[bw(map = |&has_this| if has_this { ThisProperty::HasThis } else { ThisProperty::None })]
    pub has_this: bool,
    #[br(temp)]
    #[bw(try_calc = params.len().try_into())]
    params_len: BlobInt,
    #[bw(args(cx))]
    pub base_type: ModifiedType,
    #[br(count(usize::from(params_len)))]
    #[bw(args(cx))]
    pub params: Vec<Param>,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(cx: &MetaWrite))]
#[brw(magic = 0x0a_u8)]
pub struct MethodSpec {
    #[br(temp)]
    #[bw(try_calc = arguments.len().try_into())]
    arguments_len: BlobInt,
    #[br(count(usize::from(arguments_len)))]
    #[bw(args(cx))]
    pub arguments: Vec<Type>,
}

#[derive(Debug, BinRead, BinWrite)]
pub enum MarshalDescriptor {
    #[brw(magic = 0x2_u8)]
    Boolean,
    #[brw(magic = 0x3_u8)]
    I1,
    #[brw(magic = 0x4_u8)]
    U1,
    #[brw(magic = 0x5_u8)]
    I2,
    #[brw(magic = 0x6_u8)]
    U2,
    #[brw(magic = 0x7_u8)]
    I4,
    #[brw(magic = 0x8_u8)]
    U4,
    #[brw(magic = 0x9_u8)]
    I8,
    #[brw(magic = 0xa_u8)]
    U8,
    #[brw(magic = 0xb_u8)]
    R4,
    #[brw(magic = 0xc_u8)]
    R8,
    #[brw(magic = 0x14_u8)]
    LpStr,
    #[brw(magic = 0x15_u8)]
    LpwStr,
    #[brw(magic = 0x1f_u8)]
    Int,
    #[brw(magic = 0x20_u8)]
    UInt,
    #[brw(magic = 0x26_u8)]
    Func,
    #[brw(magic = 0x2a_u8)]
    Array {
        #[br(map = |()| todo!("array marshalling"))]
        #[bw(map = |()| {
            todo!("array marshalling");
            #[allow(unreachable_code)]
            ()
        })]
        marker: (),
    },
}
