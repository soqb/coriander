use core::fmt;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom, Write},
    num::NonZeroU32,
};

use binrw::{BinRead, BinResult, BinWrite, Endian};
use bitflags::bitflags;

use super::{HeapSizes, MetaRead, MetaWrite, TableIdx, TablesOrder, TokenTableFlags};
use crate::utils::{BinReadOptional, BinWriteOptional};

#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum TableId {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    Field = 0x04,
    MethodDef = 0x06,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    Constant = 0x0B,
    CustomAttribute = 0x0C,
    FieldMarshal = 0x0D,
    DeclSecurity = 0x0E,
    ClassLayout = 0x0F,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    Event = 0x14,
    PropertyMap = 0x15,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    ImplMap = 0x1C,
    FieldRva = 0x1D,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOs = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
}

impl TableId {
    pub const MAX_PLUS_ONE: u8 = 0x2D;
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TokenCategoryFlags: u16 {
        const TYPE_DEF_OR_REF = 1 << 0;
        const HAS_CONSTANT = 1 << 1;
        const HAS_CUSTOM_ATTRIBUTE = 1 << 2;
        const HAS_FIELD_MARSHALL = 1 << 3;
        const MEMBER_REF_PARENT = 1 << 4;
        const HAS_DECL_SECURITY = 1 << 5;
        const HAS_SEMANTICS = 1 << 6;
        const METHOD_DEF_OR_REF = 1 << 7;
        const MEMBER_FORWARDED = 1 << 8;
        const IMPLEMENTATION = 1 << 9;
        const CUSTOM_ATTRIBUTE_TYPE = 1 << 10;
        const RESOLUTION_SCOPE = 1 << 11;
        const TYPE_OR_METHOD_DEF = 1 << 12;
    }
}

#[derive(Clone, Debug)]
pub struct SizeFlags {
    heap_sizes: HeapSizes,
    big_tables: TokenTableFlags,
    big_categories: TokenCategoryFlags,
}

impl SizeFlags {
    pub fn stream_is_big(&self, stream: HeapSizes) -> bool {
        self.heap_sizes.contains(stream)
    }

    pub fn table_is_big(&self, table: TokenTableFlags) -> bool {
        self.big_tables.contains(table)
    }

    pub fn cat_is_big(&self, category: TokenCategoryFlags) -> bool {
        self.big_categories.contains(category)
    }

    fn collect_tables(iter: impl IntoIterator<Item = (TableId, u32)>) -> TokenTableFlags {
        let mut flags = TokenTableFlags::default();

        for (table_id, row_count) in iter {
            if row_count >= 2u32.pow(16) {
                flags |= TokenTableFlags::from_discrete(table_id);
            }
        }

        flags
    }

    pub fn new(heap_sizes: HeapSizes, map: &HashMap<TableId, u32>) -> Self {
        Self {
            heap_sizes,
            big_tables: Self::collect_tables(map.iter().map(|(&a, &b)| (a, b))),
            big_categories: token_categories::big_category_flags(|id| {
                map.get(&id).copied().unwrap_or(0)
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rid {
    id: NonZeroU32,
}

impl Rid {
    pub fn new_raw(id: NonZeroU32) -> Self {
        Rid { id }
    }

    pub fn new(id: u32) -> Option<Self> {
        NonZeroU32::new(id).map(Self::new_raw)
    }

    pub fn to_u32(self) -> u32 {
        self.id.into()
    }
}

impl BinReadOptional for Rid {
    type Args<'a> = (bool,);

    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (table_is_big,): Self::Args<'_>,
    ) -> BinResult<Option<Self>> {
        let id = if table_is_big {
            u32::read_options(reader, endian, ())?
        } else {
            u16::read_options(reader, endian, ())? as u32
        };
        Ok(Rid::new(id))
    }
}

impl BinWriteOptional for Rid {
    type Args<'a> = (bool,);

    fn write_some<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        (table_is_big,): Self::Args<'_>,
    ) -> BinResult<()> {
        if table_is_big {
            self.to_u32().write_options(writer, endian, ())
        } else {
            (self.to_u32() as u16).write_options(writer, endian, ())
        }
    }

    fn write_none<W: Write + Seek>(
        writer: &mut W,
        _: Endian,
        (table_is_big,): Self::Args<'_>,
    ) -> BinResult<()> {
        if table_is_big {
            writer.write_all(&[0; 4])?;
        } else {
            writer.write_all(&[0; 2])?;
        }

        Ok(())
    }
}

impl_brw_optional!(for Rid);

mod stream_idxs {
    use super::*;
    use crate::metadata::MetaRead;

    macro_rules! def_idx {
        (
            $(#[$attr:meta])*
            $vis:vis $name:ident($stream_flag:expr);
        ) => {
            $(#[$attr])*
            $vis struct $name(pub NonZeroU32);

            impl $name {
                pub fn to_u32(self) -> u32 {
                    self.0.into()
                }
            }

            impl BinReadOptional for $name {
                type Args<'a> = &'a MetaRead;

                fn read_optional<R: Read + Seek>(
                    reader: &mut R,
                    endian: Endian,
                    big_tables: Self::Args<'_>,
                ) -> BinResult<Option<Self>> {
                    let idx = if big_tables.sizes().stream_is_big($stream_flag) {
                        u32::read_options(reader, endian, ())?
                    } else {
                        u16::read_options(reader, endian, ())?.into()
                    };
                    Ok(NonZeroU32::new(idx).map(Self))
                }
            }

            impl BinWriteOptional for $name {
                type Args<'a> = &'a  MetaWrite;

                fn write_some<W: Write + Seek>(
                    &self,
                    writer: &mut W,
                    endian: Endian,
                    big_tables: Self::Args<'_>,
                ) -> BinResult<()> {
                    if big_tables.sizes().stream_is_big($stream_flag) {
                        NonZeroU32::from(self.0).write_options(writer, endian, ())
                    } else {
                        self.0.write_options(writer, endian, ())
                    }
                }

                fn write_none<W: Write + Seek>(
                    writer: &mut W,
                    _: Endian,
                    big_tables: Self::Args<'_>,
                ) -> BinResult<()> {
                    if big_tables.sizes().stream_is_big($stream_flag) {
                        writer.write_all(&[0; 4])?;
                    } else {
                        writer.write_all(&[0; 2])?;
                    }

                    Ok(())
                }
            }

            impl_brw_optional!(for $name);
        };
    }

    def_idx! {
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub BlobIdx(HeapSizes::BLOB_STREAM_IS_BIG);
    }

    def_idx! {
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub StringIdx(HeapSizes::STRING_STREAM_IS_BIG);
    }

    def_idx! {
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub GuidIdx(HeapSizes::GUID_STREAM_IS_BIG);
    }

    #[derive(Debug, Clone, Copy, PartialEq, BinRead, BinWrite)]
    pub struct UserStringIdx(pub u32);
}

pub use stream_idxs::*;

pub trait TokenType {
    type TableIdRepr: Copy;

    fn from_table_repr(repr: Self::TableIdRepr) -> TableId;
    fn into_table_repr(table: TableId) -> Option<Self::TableIdRepr>;
}

macro_rules! def_token_categories {
    ($($vis:vis $name:ident($cat_flag:expr; $tag_bits:literal) { $($pat:literal => $table:ident),* $(,)? })*) => {
        $(
            #[derive(BinRead, BinWrite, Clone, Copy, Debug)]
            #[brw(repr = u8)]
            #[repr(u8)]
            $vis enum $name {
                $(
                    $table = TableId::$table as u8,
                )*
            }

            impl TokenType for $name {
                type TableIdRepr = Self;

                fn from_table_repr(repr: Self) -> TableId {
                    match repr {
                        $(
                            Self::$table => TableId::$table,
                        )*
                    }
                }

                fn into_table_repr(table: TableId) -> Option<Self> {
                    match table {
                        $(
                            TableId::$table => Some(Self::$table),
                        )*
                        _ => None,
                    }
                }
            }

            impl BinReadOptional for Token<$name> {
                type Args<'a> = &'a MetaRead;

                fn read_optional<R: Read + Seek>(
                    reader: &mut R,
                    endian: Endian,
                    cx: Self::Args<'_>,
                ) -> BinResult<Option<Self>> {
                    let (rid, tag) = if cx.sizes().cat_is_big($cat_flag) {

                        // Token::<()>::read_optional(reader, endian, ())?.map(|tok| {
                        //         tok.retype().ok_or(()).or_else(|_| Err(binrw::Error::Custom {
                        //             pos: reader.stream_position()?,
                        //             err: Box::new(
                        //                 format!(
                        //                     "invalid table {table:?} for token with category {category}",
                        //                     table = tok.table_id(),
                        //                     category = stringify!($name),
                        //                 ),
                        //             ),
                        //         }))
                        //     }).transpose()
                        let bits = u32::read_options(reader, endian, ())?;
                        let rid = bits >> $tag_bits;
                        let tag = bits & ((1 << $tag_bits) - 1);
                        (rid, tag)
                    } else {
                        let bits = u16::read_options(reader, endian, ())?;
                        let rid = bits >> $tag_bits;
                        let tag = bits & ((1 << $tag_bits) - 1);
                        (rid as u32, tag as u32)
                    };

                    if rid == 0 {
                        return Ok(None);
                    }
                    let table = match tag {
                        $(
                            $pat => $name::$table,
                        )*
                        _ => {
                            let offset = if cx.sizes().cat_is_big($cat_flag) {
                                4
                            } else {
                                2
                            };
                            return Err(binrw::Error::NoVariantMatch { pos: reader.stream_position()? - offset })
                        },
                    };

                    Ok(Rid::new(rid as u32).map(TableIdx::new_thin).map(|idx| Token { table, idx }))
                }
            }

            impl BinWriteOptional for Token<$name> {
                type Args<'a> = &'a MetaWrite;
                fn write_some<W: Write + Seek>(
                    &self,
                    writer: &mut W,
                    endian: Endian,
                    cx: Self::Args<'_>,
                ) -> BinResult<()> {
                    let tag: u32 = match self.table {
                        $(
                            $name::$table => $pat,
                        )*
                    };
                    let rid = cx.order().token_rid(*self)?.to_u32();

                    if cx.sizes().cat_is_big($cat_flag) {
                        let bits = (rid << $tag_bits) | tag;
                        bits.write_options(writer, endian, ())
                    } else {
                        let bits: u16 = ((rid as u16) << $tag_bits) | tag as u16;
                        bits.write_options(writer, endian, ())
                    }
                }

                fn write_none<W: Write + Seek>(
                    writer: &mut W,
                    endian: Endian,
                    cx: Self::Args<'_>,
                ) -> BinResult<()> {
                    Rid::write_none(writer, endian, (cx.sizes().cat_is_big($cat_flag),))
                }
            }

            impl_brw_optional!(for Token<$name>);
        )*

        pub(crate) fn big_category_flags(mapping: impl Fn(TableId) -> u32) -> TokenCategoryFlags {
            let mut flags = TokenCategoryFlags::default();
            $(
                {
                    const MAX_SMALL_IDX: u32 = 1 << (16 - $tag_bits);
                    if false $(
                        || mapping(TableId::$table) >= MAX_SMALL_IDX
                    )* {
                        flags |= $cat_flag;
                    }
                }
            )*
            flags
        }
    };
}

pub mod token_categories {
    use super::*;

    def_token_categories! {
        pub TypeDefOrRef(TokenCategoryFlags::TYPE_DEF_OR_REF; 2) {
            0 => TypeDef,
            1 => TypeRef,
            2 => TypeSpec,
        }

        pub HasConstant(TokenCategoryFlags::HAS_CONSTANT; 2) {
            0 => Field,
            1 => Param,
            2 => Property,
        }

        pub HasCustomAttribute(TokenCategoryFlags::HAS_CUSTOM_ATTRIBUTE; 5) {
            0 => MethodDef,
            1 => Field,
            2 => TypeRef,
            3 => TypeDef,
            4 => Param,
            5 => InterfaceImpl,
            6 => MemberRef,
            7 => Module,
            8 => DeclSecurity, // we've assumed (quite reasonably) this is what the spec means by "Permission"
            9 => Property,
            10 => Event,
            11 => StandAloneSig,
            12 => ModuleRef,
            13 => TypeSpec,
            14 => Assembly,
            15 => AssemblyRef,
            16 => File,
            17 => ExportedType,
            18 => ManifestResource,
            19 => GenericParam,
            20 => GenericParamConstraint,
            21 => MethodSpec,
        }

        pub HasFieldMarshal(TokenCategoryFlags::HAS_FIELD_MARSHALL; 1) {
            0 => Field,
            1 => Param,
        }

        pub HasDeclSecurity(TokenCategoryFlags::HAS_DECL_SECURITY; 2) {
            0 => TypeDef,
            1 => MethodDef,
            2 => Assembly,
        }

        pub MemberRefParent(TokenCategoryFlags::MEMBER_REF_PARENT; 3) {
            0 => TypeDef,
            1 => TypeRef,
            2 => ModuleRef,
            3 => MethodDef,
            4 => TypeSpec,
        }

        pub HasSemantics(TokenCategoryFlags::HAS_SEMANTICS; 1) {
            0 => Field,
            1 => Param,
        }

        pub MethodDefOrRef(TokenCategoryFlags::METHOD_DEF_OR_REF; 1) {
            0 => MethodDef,
            1 => MemberRef,
        }

        pub MemberForwarded(TokenCategoryFlags::MEMBER_FORWARDED; 1) {
            0 => Field,
            1 => MethodDef,
        }

        pub Implementation(TokenCategoryFlags::IMPLEMENTATION; 2) {
            0 => File,
            1 => AssemblyRef,
            2 => ExportedType,
        }

        pub CustomAttributeType(TokenCategoryFlags::CUSTOM_ATTRIBUTE_TYPE; 3) {
            // 0, 1 unused
            2 => MethodDef,
            3 => MemberRef,
        }

        pub ResolutionScope(TokenCategoryFlags::RESOLUTION_SCOPE; 2) {
            0 => Module,
            1 => ModuleRef,
            2 => AssemblyRef,
            3 => TypeRef,
        }

        pub TypeOrMethodDef(TokenCategoryFlags::TYPE_OR_METHOD_DEF; 1) {
            0 => TypeDef,
            1 => MethodDef,
        }
    }
}

impl TokenType for () {
    type TableIdRepr = TableId;

    fn from_table_repr(repr: Self::TableIdRepr) -> TableId {
        repr
    }

    fn into_table_repr(table: TableId) -> Option<Self::TableIdRepr> {
        Some(table)
    }
}

impl BinReadOptional for Token<()> {
    type Args<'a> = ();

    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Option<Self>> {
        // todo: It's ambiguous in the spec as to what exactly a "null" token is.
        // Specifically, whether the bit patterns of the form `0xNM000000` are all valid nulls.
        // We assume they are, but don't preserve their exact form (i.e. all nulls are written as zeros).
        let (table, id) = if endian == Endian::Little {
            let table = TableId::read_options(reader, endian, ())?;

            let mut triplet = [0; 3];
            reader.read_exact(&mut triplet)?;
            let id = u32::from_le_bytes([triplet[0], triplet[1], triplet[2], 0]);
            (table, id)
        } else {
            let mut triplet = [0; 3];
            reader.read_exact(&mut triplet)?;
            let id = u32::from_le_bytes([triplet[0], triplet[1], triplet[2], 0]);

            let table = TableId::read_options(reader, endian, ())?;
            (table, id)
        };

        Ok(Rid::new(id)
            .map(TableIdx::new_thin)
            .map(|idx| Token { table, idx }))
    }
}

impl BinWriteOptional for Token<()> {
    type Args<'a> = &'a TablesOrder;

    fn write_some<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        cx: Self::Args<'_>,
    ) -> BinResult<()> {
        let id = cx.token_rid(*self)?.to_u32();
        assert!(id < 2u32.pow(24));

        if endian == Endian::Little {
            self.table.write_options(writer, endian, ())?;
            writer.write_all(&id.to_le_bytes()[0..3])?;
        } else {
            writer.write_all(&id.to_be_bytes()[1..])?;
            self.table.write_options(writer, endian, ())?;
        }

        Ok(())
    }

    fn write_none<W: Write + Seek>(writer: &mut W, _: Endian, _: Self::Args<'_>) -> BinResult<()> {
        writer.write_all(&[0; 4])?;
        Ok(())
    }
}

impl_brw_optional!(for Token<()>);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token<T: TokenType + ?Sized = ()> {
    pub table: T::TableIdRepr,
    pub idx: TableIdx,
}

impl<T: TokenType + ?Sized> Clone for Token<T> {
    fn clone(&self) -> Self {
        Self {
            table: self.table,
            idx: self.idx,
        }
    }
}

impl<T: TokenType + ?Sized> Copy for Token<T> {}

impl<T: TokenType + ?Sized> Token<T> {
    pub fn new(idx: TableIdx) -> Self
    where
        T::TableIdRepr: Default,
    {
        Token {
            table: T::TableIdRepr::default(),
            idx,
        }
    }

    pub fn table_id(self) -> TableId {
        T::from_table_repr(self.table)
    }

    pub fn to_abstract(self) -> Token {
        Token {
            table: self.table_id(),
            idx: self.idx,
        }
    }

    pub fn retype<U: TokenType + ?Sized>(self) -> Option<Token<U>> {
        Some(Token {
            table: U::into_table_repr(T::from_table_repr(self.table))?,
            idx: self.idx,
        })
    }
}

impl<T: TokenType + ?Sized> fmt::Debug for Token<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({:?}:{})", self.table_id(), self.idx.0)
    }
}
