use std::mem::replace;

use bitflags::bitflags;
use coriander_parser::{
    bitflags_brw,
    metadata::{StandAloneSig, Token, UserStringIdx},
};
use indexmap::IndexMap;

mod rw;

mod token {
    use coriander_parser::metadata::{TableId, TokenType};

    #[derive(Debug, Clone, Copy)]
    pub enum Type {
        Def,
        Ref,
        Spec,
    }

    impl TokenType for Type {
        type TableIdRepr = Self;

        fn from_table_repr(repr: Self) -> TableId {
            match repr {
                Type::Def => TableId::TypeDef,
                Type::Ref => TableId::TypeRef,
                Type::Spec => TableId::TypeSpec,
            }
        }

        fn into_table_repr(table: TableId) -> Option<Self> {
            match table {
                TableId::TypeDef => Some(Type::Def),
                TableId::TypeRef => Some(Type::Ref),
                TableId::TypeSpec => Some(Type::Spec),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Method {
        Def,
        Ref,
        Spec,
    }

    impl TokenType for Method {
        type TableIdRepr = Self;

        fn from_table_repr(repr: Self) -> TableId {
            match repr {
                Method::Def => TableId::MethodDef,
                Method::Ref => TableId::MemberRef,
                Method::Spec => TableId::MethodSpec,
            }
        }

        fn into_table_repr(table: TableId) -> Option<Self> {
            match table {
                TableId::MethodDef => Some(Method::Def),
                TableId::MemberRef => Some(Method::Ref),
                TableId::MethodSpec => Some(Method::Spec),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum MethodNoSpec {
        Def,
        Ref,
    }

    impl TokenType for MethodNoSpec {
        type TableIdRepr = Self;

        fn from_table_repr(repr: Self) -> TableId {
            match repr {
                MethodNoSpec::Def => TableId::MethodDef,
                MethodNoSpec::Ref => TableId::MemberRef,
            }
        }

        fn into_table_repr(table: TableId) -> Option<Self> {
            match table {
                TableId::MethodDef => Some(MethodNoSpec::Def),
                TableId::MemberRef => Some(MethodNoSpec::Ref),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum Field {
        Def,
        Ref,
    }

    impl TokenType for Field {
        type TableIdRepr = Self;

        fn from_table_repr(repr: Self) -> TableId {
            match repr {
                Field::Def => TableId::Field,
                Field::Ref => TableId::MemberRef,
            }
        }

        fn into_table_repr(table: TableId) -> Option<Self> {
            match table {
                TableId::Field => Some(Field::Def),
                TableId::MemberRef => Some(Field::Ref),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum MetaToken {
        FieldDef,
        MethodDef,
        MethodSpec,
        MemberRef,
        TypeDef,
        TypeRef,
        TypeSpec,
    }

    impl TokenType for MetaToken {
        type TableIdRepr = Self;

        fn from_table_repr(repr: Self) -> TableId {
            match repr {
                MetaToken::FieldDef => TableId::Field,
                MetaToken::MethodDef => TableId::MethodDef,
                MetaToken::MethodSpec => TableId::MethodSpec,
                MetaToken::MemberRef => TableId::MemberRef,
                MetaToken::TypeDef => TableId::TypeDef,
                MetaToken::TypeRef => TableId::TypeRef,
                MetaToken::TypeSpec => TableId::TypeSpec,
            }
        }

        fn into_table_repr(table: TableId) -> Option<Self> {
            match table {
                TableId::Field => Some(MetaToken::FieldDef),
                TableId::MethodDef => Some(MetaToken::MethodDef),
                TableId::MethodSpec => Some(MetaToken::MethodSpec),
                TableId::MemberRef => Some(MetaToken::MemberRef),
                TableId::TypeDef => Some(MetaToken::TypeDef),
                TableId::TypeRef => Some(MetaToken::TypeRef),
                TableId::TypeSpec => Some(MetaToken::TypeSpec),
                _ => None,
            }
        }
    }
}

/// The direct types which CIL instructions operate directly on.
#[derive(Debug, Clone, Copy)]
pub enum StackType {
    /// 32-bit integer.
    ///
    /// While signedness is not stored on the stack,
    /// assume the number is signed unless otherwise specified.
    Int32,
    /// 64-bit integer.
    ///
    /// While signedness is not stored on the stack,
    /// assume the number is signed unless otherwise specified.
    ///
    /// Arithmetic between `Int64` and other numeric types is not supported
    /// without a converting first.
    Int64,
    /// Native-sized integer.
    ///
    /// While signedness is not stored on the stack,
    /// assume the number is signed unless otherwise specified.
    NativeInt,
    // /// Native-sized, unmanaged (not garbage collected) pointer, what CLI calls `native unsinged int`.
    // ///
    // /// **NB**: This is not an integer.
    // ///
    // /// This can be null, which takes the zero bit pattern.
    // ///
    // /// Unmanaged pointers can be passed as arguments to functions if they
    // /// represent pointers which would be valid if tagged as managed.
    // ///
    // /// # Verifiability
    // /// Using any unmanaged pointer immediately marks the program as unverifiable.
    // UnmanagedPtr,
    /// Arbitrarily-sized floating point number, what CLI calls `F`.
    Float,
    /// An untyped object reference, what CLI calls `O`.
    ///
    /// This can be null, which takes the zero bit pattern.
    ///
    /// Instances of value types cannot be objects unless they are boxed.
    ObjectRef,
    /// Native-sized, managed (garbage collected) pointer, what CLI calls `&`.
    ///
    /// This cannot be null (the zero bit pattern).
    ///
    /// Managed pointers are allowed to point outside of the garbage collectors scope,
    /// and will be ignored by it as a consequence.
    ManagedPtr,
}

/// The types which the CLI supports.
///
/// While only the types in [`StackType`] can be used on the stack,
/// these types are supported in locations like arguments, statics and fields.
#[derive(Debug, Clone, Copy)]
pub enum StorageType {
    Int8,
    Int16,
    Int32,
    Int64,
    NativeInt,
    Float32,
    Float64,
    Boolean,
    Character,
    OnStack(StackType),
}

impl From<StorageType> for StackType {
    fn from(value: StorageType) -> Self {
        match value {
            StorageType::Boolean
            | StorageType::Character
            | StorageType::Int8
            | StorageType::Int16
            | StorageType::Int32 => StackType::Int32,
            StorageType::Int64 => StackType::Int64,
            StorageType::NativeInt => StackType::NativeInt,
            StorageType::Float32 | StorageType::Float64 => StackType::Float,
            StorageType::OnStack(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationType {
    Int8,
    Int16,
    Int32,
    NativeInt,
    Float32,
    Float64,
}

#[derive(Debug, Clone, Copy)]
pub enum ArithmeticKind {
    /// For integers, wrap and for floating point numbers, return an infinity.
    NonOverflowing,
    SignedOverflow,
    UnsignedOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructionRef(usize);

impl InstructionRef {
    pub fn new_thin(i: usize) -> Self {
        Self(i)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Signage {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy)]
pub enum IntegerType {
    I1,
    I2,
    I4,
    I8,
    U1,
    U2,
    U4,
    U8,
    I,
    U,
}
impl From<IntegerType> for StackType {
    fn from(value: IntegerType) -> Self {
        match value {
            IntegerType::I1
            | IntegerType::I2
            | IntegerType::I4
            | IntegerType::U1
            | IntegerType::U2
            | IntegerType::U4 => Self::Int32,
            IntegerType::I8 | IntegerType::U8 => Self::Int64,
            IntegerType::I | IntegerType::U => Self::NativeInt,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ConversionType {
    Int(IntegerType),
    R4,
    R8,
    R,
    OvfSigned(IntegerType),
    OvfUnsigned(IntegerType),
}

impl From<ConversionType> for StackType {
    fn from(value: ConversionType) -> Self {
        match value {
            ConversionType::Int(i)
            | ConversionType::OvfSigned(i)
            | ConversionType::OvfUnsigned(i) => i.into(),
            ConversionType::R4 | ConversionType::R8 | ConversionType::R => Self::Float,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Constant {
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
}

#[derive(Debug, Clone, Copy)]
pub enum InstructionLoadType {
    I1,
    I2,
    I4,
    I8OrU8,
    U1,
    U2,
    U4,
    I,
    R4,
    R8,
    Ref,
}

#[derive(Debug, Clone, Copy)]
pub enum InstructionStoreType {
    I1,
    I2,
    I4,
    I8,
    I,
    R4,
    R8,
    Ref,
}

#[derive(Debug, Clone, Copy)]
pub enum ElementLoadType {
    Inline(InstructionLoadType),
    Other(Token<token::Type>),
}

#[derive(Debug, Clone, Copy)]
pub enum ElementStoreType {
    Inline(InstructionStoreType),
    Other(Token<token::Type>),
}

#[derive(Debug, Clone)]
pub enum Instruction {
    Add(ArithmeticKind),
    And,
    Arglist,
    Beq(InstructionRef),
    Bge {
        sign: Signage,
        target: InstructionRef,
    },
    Bgt {
        sign: Signage,
        target: InstructionRef,
    },
    Ble {
        sign: Signage,
        target: InstructionRef,
    },
    Blt {
        sign: Signage,
        target: InstructionRef,
    },
    BneUnsigned(InstructionRef),
    Br(InstructionRef),
    Break,
    #[doc(alias = "BrZero", alias = "BrNull")]
    BrFalse(InstructionRef),
    #[doc(alias = "BrInst")]
    BrTrue(InstructionRef),
    Call(Token<token::Method>),
    #[doc(alias = "CallI")]
    CallIndirect(Token<StandAloneSig>),
    Ceq,
    Cgt(Signage),
    Ckfinite,
    Clt(Signage),
    Conv(ConversionType),
    Cpblk,
    Div(Signage),
    Dup,
    EndFilter,
    #[doc(alias = "EndFinally")]
    EndFault,
    InitBlk,
    Jmp(Token<token::MethodNoSpec>),
    LdArg(u16),
    #[doc(alias = "LdArgA")]
    LdArgAddr(u16),
    Ldc(Constant),
    LdFtn(Token<token::MethodNoSpec>),
    LdInd(InstructionLoadType),
    LdLoc(u16),
    #[doc(alias = "LdLocA")]
    LdLocAddr(u16),
    LdNull,
    Leave(InstructionRef),
    LocAlloc,
    Mul(ArithmeticKind),
    Neg,
    Nop,
    Not,
    Or,
    Pop,
    Rem(Signage),
    Ret,
    Shl,
    Shr(Signage),
    StArg(u16),
    StInd(InstructionStoreType),
    StLoc(u16),
    Sub(ArithmeticKind),
    Switch(Vec<InstructionRef>),
    Xor,
    Box(Token<token::Type>),
    CallVirt(Token<token::Method>),
    CastClass(Token<token::Type>),
    CpObj(Token<token::Type>),
    InitObj(Token<token::Type>),
    IsInst(Token<token::Type>),
    LdElem(ElementLoadType),
    #[doc(alias = "LdElemA")]
    LdElemAddr(Token<token::Type>),
    LdFld(Token<token::Field>),
    #[doc(alias = "LdFldA")]
    LdFldAddr(Token<token::Field>),
    LdLen,
    LdObj(Token<token::Type>),
    LdSfld(Token<token::Field>),
    #[doc(alias = "LdSfldA")]
    LdSfldAddr(Token<token::Field>),
    LdStr(UserStringIdx),
    LdToken(Token<token::MetaToken>),
    LdVirtFn(Token<token::Method>),
    MkRefAny(Token<token::Type>),
    NewArr(Token<token::Type>),
    NewObj(Token<token::MethodNoSpec>),
    RefAnyType,
    RefAnyVal(Token<token::Type>),
    Rethrow,
    SizeOf(Token<token::Type>),
    StElem(ElementStoreType),
    StFld(Token<token::Field>),
    StObj(Token<token::Type>),
    StSfld(Token<token::Field>),
    Throw,
    Unbox(Token<token::Type>),
    UnboxAny(Token<token::Type>),
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct SkippedChecks: u8 {
        const TYPE = 0x1;
        const RANGE = 0x2;
        const NULL = 0x4;
    }
}
bitflags_brw!(SkippedChecks: u8);

#[derive(Debug, Clone)]
pub enum InstructionPrefix {
    Constrained(Token<token::Type>),
    No(SkippedChecks),
    Readonly,
    Tail,
    Unaligned(u8),
    Volatile,
}

#[derive(Debug, Clone, Default)]
pub struct AggregatePrefix {
    pub readonly: bool,
    pub tail: bool,
    pub voltaile: bool,
    pub type_constraint: Option<Token<token::Type>>,
    pub alignment: Option<u8>,
    pub skipped_checks: SkippedChecks,
}

#[derive(Debug, Clone)]
pub struct InstructionPoint {
    pub prefix: Option<Box<AggregatePrefix>>,
    pub instruction: Instruction,
}

impl InstructionPoint {
    pub fn byte_len(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct InstructionTable {
    locations: IndexMap<InstructionRef, InstructionPoint>,
    next_ref: InstructionRef,
}

impl Default for InstructionTable {
    fn default() -> Self {
        Self {
            locations: Default::default(),
            next_ref: InstructionRef(0),
        }
    }
}

impl InstructionTable {
    fn insert_with_idx(&mut self, idx: usize, i: InstructionPoint) -> InstructionRef {
        let key = {
            // we offset by `InstructionPoint::len` so that `InstructionRef::thin_new` is kept
            // in sync over prefixes.
            let future = InstructionRef(self.next_ref.0 + 1);
            replace(&mut self.next_ref, future)
        };
        self.locations.shift_insert(idx, key, i);
        key
    }

    fn index_of(&self, p: InstructionRef) -> Option<usize> {
        self.locations.get_index_of(&p)
    }

    /// Skip `count` reference indices.
    ///
    /// This is a convinient way to raise future-compatible references.
    ///
    /// `InstructionRef` synchronisation is preserved since the index is still strictly increasing
    pub fn skip_refs(&mut self, count: usize) {
        self.next_ref = InstructionRef(self.next_ref.0 + count);
    }

    pub fn offset_from_to(&self, a: InstructionRef, b: InstructionRef) -> Option<i32> {
        let Some(a) = self.index_of(a) else {
            return None;
        };
        let Some(b) = self.index_of(b) else {
            return None;
        };
        let range = if b >= a { a..b } else { b..a };
        let sum: usize = self.locations[range]
            .iter()
            .map(|(_, i)| i.byte_len())
            .sum();
        Some(if b >= a { sum as i32 } else { -(sum as i32) })
    }

    pub fn len(&self) -> usize {
        self.locations.len()
    }

    pub fn try_insert_before(
        &mut self,
        p: InstructionRef,
        i: InstructionPoint,
    ) -> Result<InstructionRef, InstructionPoint> {
        let Some(idx) = self.index_of(p) else {
            return Err(i);
        };
        Ok(self.insert_with_idx(idx, i))
    }

    pub fn try_insert_after(
        &mut self,
        p: InstructionRef,
        i: InstructionPoint,
    ) -> Result<InstructionRef, InstructionPoint> {
        let Some(idx) = self.index_of(p) else {
            return Err(i);
        };
        Ok(self.insert_with_idx(idx + 1, i))
    }

    pub fn push(&mut self, i: InstructionPoint) -> InstructionRef {
        self.insert_with_idx(self.len(), i)
    }

    pub fn remove(&mut self, p: InstructionRef) -> Option<(usize, InstructionPoint)> {
        self.locations.shift_remove_full(&p).map(|(x, _, i)| (x, i))
    }

    pub fn get(&self, p: InstructionRef) -> Option<&InstructionPoint> {
        self.locations.get(&p)
    }

    pub fn get_mut(&mut self, p: InstructionRef) -> Option<&mut InstructionPoint> {
        self.locations.get_mut(&p)
    }
}

#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub max_stack: u16,
    pub local_var_sig: Option<Token<StandAloneSig>>,
}

impl Default for MethodInfo {
    fn default() -> Self {
        MethodInfo {
            max_stack: 8,
            local_var_sig: None,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct MethodBody {
    pub header: MethodInfo,
    pub instructions: InstructionTable,
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use binrw::BinRead as _;
    use coriander_parser::{pe::Pe, ClrExe};

    use crate::MethodBody;

    #[test]
    fn test() -> anyhow::Result<()> {
        let file = fs::read("/home/seth/projects/cshp/disco/il2cppbridge/lib/um/mscorlib.dll")?;
        let mut cursor = io::Cursor::new(file);
        let clr = ClrExe::new(Pe::read_le(&mut cursor)?)?;

        for (_, method) in clr.metadata.metadata.tables.method_def.iter() {
            if method.rva.0 == 0 {
                continue;
            }
            let section = method.rva.find_containing(&clr.pe.sections).unwrap();
            println!(
                "{}: @ {}",
                method.name,
                (method.rva - section.virtual_address).0 + section.body_offset.unwrap()
            );
            let body_slice = method.rva.slice_section(&section).unwrap();

            let mut body_cursor = io::Cursor::new(body_slice);

            let body = MethodBody::read_le(&mut body_cursor)?;
            // eprintln!("{name} ::: {body:#?}", name = method.name);
        }

        panic!("we're called elizabethans; you're all a bunch of heathens.")
    }
}
