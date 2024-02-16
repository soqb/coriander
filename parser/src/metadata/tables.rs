use std::io::{Read, Seek, Write};
use std::num::NonZeroU32;

use binrw::{BinRead, BinResult, BinWrite, Endian};
use bitflags::bitflags;

use super::signatures::{
    self, FieldSig, MarshalDescriptor, MethodSig, PropertySig, StandAloneSignature, Type,
};
use super::{
    token_categories::*, BlobIdx, Blobbed, Guid, MetaRead, MetaString, MetaWrite, Rid, TableId,
    TableIdx, Token, TokenTableFlags, TokenType,
};
use crate::utils::BinRemote;
use crate::{
    utils::{BinReadOptional, BinWriteOptional},
    Rva, VersionU16, VersionU32,
};

macro_rules! def_table_entries {
    (
        read_args($rarg:ident: $rarg_ty:ty);
        write_args($warg:ident: $warg_ty:ty);
        $(
            $(#[$attr:meta])*
            $vis:vis $name:ident($table_flag:expr) { $(
                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident: $field_ty:ty
            ),* $(,)? }
        )*
    ) => {
        $(
            #[binrw::binrw]
            #[derive(Debug)]
            #[br(import($rarg: $rarg_ty))]
            #[bw(import($warg: $warg_ty))]
            $(#[$attr])*
            $vis struct $name { $(
                $(#[$field_attr])*
                $field_vis $field: $field_ty,
            )* }
            impl TokenType for $name {
                type TableIdRepr = ();
                type ReadArgs<'a> = &'a MetaRead;
                type WriteArgs<'a> = &'a MetaWrite;

                fn from_table_repr(_: ()) -> TableId {
                    TableId::$name
                }

                fn into_table_repr(table: TableId) -> Option<()> {
                    if table == TableId::$name {
                        Some(())
                    } else {
                        None
                    }
                }

                fn read_token_optional<R: Read + Seek>(
                    reader: &mut R,
                    endian: Endian,
                    meta_cx: Self::ReadArgs<'_>,
                ) -> BinResult<Option<Token<Self>>> {
                    let Some(rid) = Rid::read_optional(reader, endian, (meta_cx.sizes().table_is_big($table_flag),))? else {
                        return Ok(None);
                    };
                    Ok(Some(Token::new(TableIdx::from_rid(rid))))
                }

                fn write_token<W: Write + Seek>(
                    &token: &Token<Self>,
                    writer: &mut W,
                    endian: Endian,
                    meta_cx: Self::WriteArgs<'_>,
                ) -> BinResult<()> {
                    meta_cx.token_rid(token)?.write_options(writer, endian, (meta_cx.sizes().table_is_big($table_flag),))
                }

                fn write_null_token<W: Write + Seek>(
                    writer: &mut W,
                    endian: Endian,
                    meta_cx: Self::WriteArgs<'_>,
                ) -> BinResult<()> {
                    Rid::write_none(writer, endian, (meta_cx.sizes().table_is_big($table_flag),))
                }
            }
        )*
    };
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct AssemblyFlags: u32 {
        const PUBLIC_KEY = 0x1;
        const RETARGETABLE = 0x100;
        const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
        const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
    }
}
bitflags_brw!(AssemblyFlags: u32);

#[derive(BinRead, BinWrite, Debug)]
pub struct AssemblyVersion {
    pub version: VersionU16,
    pub build_number: u16,
    pub revision: u16,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum ValueElementType {
    Boolean = 0x02,
    Char = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0A,
    U8 = 0x0B,
    R4 = 0x0C,
    R8 = 0x0D,
    String = 0x0E,
    Class = 0x12,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct EventAttributes: u16 {
        const SPECIAL_NAME = 0x0200;
        const RT_SPECIAL_NAME = 0x0400;
    }
}
bitflags_brw!(EventAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TypeAttributes: u32 {
        // visibility:
        const NOT_PUBLIC = 0x00000000;
        const PUBLIC = 0x00000001;
        const NESTED_PUBLIC = 0x00000002;
        const NESTED_PRIVATE = 0x00000003;
        const NESTED_FAMILY = 0x00000004;
        const NESTED_ASSEMBLY = 0x00000005;
        const NESTED_FAMILY_AND_ASSEMBLY = 0x00000006;
        const NESTED_FAMILY_OR_ASSEMBLY = 0x00000007;
        // layout:
        const AUTO_LAYOUT = 0x00000000;
        const SEQUENTIAL_LAYOUT = 0x00000008;
        const EXPLICIT_LAYOUT = 0x00000010;
        // class semantics:
        const CLASS = 0x00000000;
        const INTERFACE = 0x00000020;
        // special class semantics:
        const ABSTRACT = 0x00000080;
        const SEALED = 0x00000100;
        const SPECIAL_NAME = 0x00000400;
        // implementation attributes:
        const IMPORT = 0x00001000;
        const SERIALIZABLE = 0x00002000;
        // string format attributes:
        const ANSI_CLASS = 0x00000000;
        const UNICODE_CLASS = 0x00010000;
        const AUTO_CLASS = 0x00020000;
        const CUSTOM_FORMAT_CLASS = 0x00030000;
        // class initialization attributes:
        const BEFORE_FIELD_INIT = 0x00100000;
        // additional flags:
        const RT_SPECIAL_NAME = 0x00000800;
        const HAS_SECURITY = 0x00040000;
    }
}
bitflags_brw!(TypeAttributes: u32);

impl TypeAttributes {
    pub fn visibility(self) -> Self {
        self & Self::NOT_PUBLIC
            | Self::PUBLIC
            | Self::NESTED_PUBLIC
            | Self::NESTED_PRIVATE
            | Self::NESTED_FAMILY
            | Self::NESTED_ASSEMBLY
            | Self::NESTED_FAMILY_AND_ASSEMBLY
            | Self::NESTED_FAMILY_OR_ASSEMBLY
    }

    pub fn layout(self) -> Self {
        self & Self::AUTO_LAYOUT | Self::SEQUENTIAL_LAYOUT | Self::EXPLICIT_LAYOUT
    }
    pub fn class_semantics(self) -> Self {
        self & Self::CLASS | Self::INTERFACE
    }

    pub fn string_format(self) -> Self {
        self & Self::ANSI_CLASS | Self::UNICODE_CLASS | Self::AUTO_CLASS | Self::CUSTOM_FORMAT_CLASS
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct FieldAttributes: u16 {
        // access:
        const COMPILER_CONTROLLED = 0x0000;
        const PRIVATE = 0x0001;
        const FAMILY_AND_ASSEMBLY = 0x0002;
        const ASSEMBLY = 0x0003;
        const FAMILY = 0x0004;
        const FAMILY_OR_ASSEMBLY = 0x0005;
        const PUBLIC = 0x0006;
        const STATIC = 0x0010;
        const INIT_ONLY = 0x0020;
        const LITERAL = 0x0040;
        const NOT_SERIALIZED = 0x0080;
        const SPECIAL_NAME = 0x0200;
        // interop:
        const P_INVOKE_IMPL = 0x2000;
        // additional flags:
        const RT_SPECIAL_NAME = 0x0400;
        const HAS_FIELD_MARSHALL = 0x1000;
        const HAS_DEFAULT = 0x8000;
        const HAS_FIELD_RVA = 0x0100;
    }
}
bitflags_brw!(FieldAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct FileAttributes: u32 {
        const CONTAINS_META_DATA = 0x0000;
        const CONTAINS_NO_META_DATA = 0x0001;
    }
}
bitflags_brw!(FileAttributes: u32);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct GenericParamAttributes: u16 {
        // variance:
        #[doc(alias = "NONE")]
        const INVARIANT = 0x0000;
        const COVARIANT = 0x0001;
        const CONTRAVARIANT = 0x0002;
        // special constraint:
        const REFERENCE_TYPE_CONSTRAINT = 0x0004;
        const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT = 0x0008;
        const DEFAULT_CONSTRUCTOR_CONSTRAINT = 0x0010;
    }
}
bitflags_brw!(GenericParamAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PInvokeAttributes: u16 {
        const NO_MANGLE = 0x0001;
        // character set:
        const CHAR_SET_NOT_SPEC = 0x0000;
        const CHAR_SET_ANSI = 0x0002;
        const CHAR_SET_UNICODE = 0x0004;
        const CHAR_SET_AUTO = 0x0006;
        const SUPPORTS_LAST_ERROR = 0x0040;
        // calling convention:
        const CALL_CONV_WINAPI = 0x0100;
        const CALL_CONV_CDECL = 0x0200;
        const CALL_CONV_STDCALL = 0x0300;
        const CALL_CONV_THISCALL = 0x0400;
        const CALL_CONV_FASTCALL = 0x0500;
    }
}
bitflags_brw!(PInvokeAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ManifestResourceAttributes: u32 {
        const PUBLIC = 0x0001;
        const PRIVATE = 0x0002;
    }
}
bitflags_brw!(ManifestResourceAttributes: u32);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct MethodAttributes: u16 {
        // member access:
        const COMPILER_CONTROLLED = 0x0000;
        const PRIVATE = 0x0001;
        const FAMILY_AND_ASSEMBLY = 0x0002;
        const ASSEMBLY = 0x0003;
        const FAMILY = 0x0004;
        const FAMILY_OR_ASSEMBLY = 0x0005;
        const PUBLIC = 0x0006;
        const STATIC = 0x0010;
        const FINAL = 0x0020;
        const VIRTUAL = 0x0040;
        const HIDE_BY_SIG = 0x0080;
        // vtable layout:
        const REUSE_SLOT = 0x0000;
        const NEW_SLOT = 0x0100;
        const STRICT = 0x0200;
        const ABSTRACT = 0x0400;
        const SPECIAL_NAME = 0x0800;
        // interop attributes:
        const P_INVOKE_IMPL = 0x2000;
        const UNMANAGED_EXPORT = 0x0008;
        // additional flags:
        const RT_SPECIAL_NAME = 0x1000;
        const HAS_SECURITY = 0x4000;
        const REQUIRE_SEC_OBJECT = 0x8000;
    }
}
bitflags_brw!(MethodAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct MethodImplAttributes: u16 {
        // code type:
        const IL = 0x0000;
        const NATIVE = 0x0001;
        const OPTIL = 0x0002;
        const RUNTIME = 0x0003;
        const UNMANAGED = 0x0004;
        const MANAGED = 0x0000;
        // implementation info and interop:
        const FORWARD_REF = 0x0010;
        const PRESERVE_SIG = 0x0080;
        const INTERNAL_CALL = 0x1000;
        const SYNCHRONISED = 0x0020;
        const NO_INLINING = 0x0008;
    }
}
bitflags_brw!(MethodImplAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct MethodSemanticsAttributes: u16 {
        const SETTER = 0x0001;
        const GETTER = 0x0002;
        const OTHER = 0x0004;
        const ADD_ON = 0x0008;
        const REMOVE_ON = 0x0010;
        const FIRE = 0x0020;
    }
}
bitflags_brw!(MethodSemanticsAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ParamAttributes: u16 {
        const IN = 0x0001;
        const OUT = 0x0002;
        const OPTIONAL = 0x0010;
        const HAS_DEFAULT = 0x1000;
        const HAS_FIELD_MARSHALL = 0x2000;
    }
}
bitflags_brw!(ParamAttributes: u16);

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PropertyAttributes: u16 {
        const SPECIAL_NAME = 0x0200;
        const RT_SPECIAL_NAME = 0x0400;
        const HAS_DEFAULT = 0x1000;
    }
}
bitflags_brw!(PropertyAttributes: u16);

def_table_entries! {
    read_args(_cx: &MetaRead);
    write_args(_cx: &MetaWrite);

    pub Assembly(TokenTableFlags::ASSEMBLY) {
        pub hash_algorithm_id: u32,
        pub version: AssemblyVersion,
        pub flags: AssemblyFlags,
        #[br(parse_with = parse_args!(BlobIdx::read_optional; _cx))]
        #[bw(write_with = write_args!(BlobIdx::write_optional; _cx))]
        pub public_key: Option<BlobIdx>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[br(parse_with = parse_args!(MetaString::read_opt; _cx))]
        #[bw(write_with = write_args!(MetaString::write_opt; _cx))]
        pub culture: Option<String>,
    }

    pub AssemblyOs(TokenTableFlags::ASSEMBLY_OS) {
        pub platform_id: u32,
        pub version: VersionU32,
    }

    pub AssemblyProcessor(TokenTableFlags::ASSEMBLY_PROCESSOR) {
        pub processor: u32,
    }

    pub AssemblyRef(TokenTableFlags::ASSEMBLY_REF) {
        pub version: AssemblyVersion,
        pub flags: AssemblyFlags, // todo: verify only the PUBLIC_KEY bit is set.
        #[br(parse_with = parse_args!(BlobIdx::read_optional; _cx))]
        #[bw(write_with = write_args!(BlobIdx::write_optional; _cx))]
        pub public_key_or_token: Option<BlobIdx>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[br(parse_with = parse_args!(MetaString::read_opt; _cx))]
        #[bw(write_with = write_args!(MetaString::write_opt; _cx))]
        pub culture: Option<String>,
        #[br(parse_with = parse_args!(BlobIdx::read_optional; _cx))]
        #[bw(write_with = write_args!(BlobIdx::write_optional; _cx))]
        pub hash_value: Option<BlobIdx>,
    }

    pub AssemblyRefOs(TokenTableFlags::ASSEMBLY_REF_OS) {
        pub platform_id: u32,
        pub version: VersionU32,
        #[brw(args_raw = _cx)]
        pub assembly_ref: Token<AssemblyRef>,
    }

    pub AssemblyRefProcessor(TokenTableFlags::ASSEMBLY_REF_PROCESSOR) {
        pub processor: u32,
        #[brw(args_raw = _cx)]
        pub assembly_ref: Token<AssemblyRef>,
    }

    pub ClassLayout(TokenTableFlags::CLASS_LAYOUT) {
        pub packing_size: u16,
        pub class_size: u32,
        #[brw(args_raw = _cx)]
        pub parent: Token<TypeDef>,
    }

    pub Constant(TokenTableFlags::CONSTANT) {
        #[brw(pad_after = 0x1)]
        pub element_type: ValueElementType,
        #[brw(args_raw = _cx)]
        pub parent: Token<HasConstant>,
        #[brw(args_raw = _cx)]
        pub value: BlobIdx,
    }

    pub CustomAttribute(TokenTableFlags::CUSTOM_ATTRIBUTE) {
        #[brw(args_raw = _cx)]
        pub parent: Token<HasCustomAttribute>,
        #[brw(args_raw = _cx)]
        pub type_: Token<CustomAttributeType>,
        #[br(parse_with = parse_args!(BlobIdx::read_optional; _cx))]
        #[bw(write_with = write_args!(BlobIdx::write_optional; _cx))]
        pub value: Option<BlobIdx>,
    }

    pub DeclSecurity(TokenTableFlags::DECL_SECURITY) {
        pub action: u16, // todo: enumify
        #[brw(args_raw = _cx)]
        pub parent: Token<HasDeclSecurity>,
        #[brw(args_raw = _cx)]
        pub permission_set: BlobIdx,
    }

    pub EventMap(TokenTableFlags::EVENT_MAP) {
        #[brw(args_raw = _cx)]
        pub vparent: Token<TypeDef>,
        #[brw(args_raw = _cx)]
        pub vevent_list_start: Token<Event>,
    }

    pub Event(TokenTableFlags::EVENT) {
        pub flags: EventAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub type_: Option<Token<TypeDefOrRef>>,
    }

    pub ExportedType(TokenTableFlags::EXPORTED_TYPE) {
        pub flags: TypeAttributes,
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub type_: Option<Token<TypeDef>>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[br(parse_with = parse_args!(MetaString::read_opt; _cx))]
        #[bw(write_with = write_args!(MetaString::write_opt; _cx))]
        pub namespace: Option<String>,
        #[brw(args_raw = _cx)]
        pub implementation: Token<Implementation>,
    }

    pub Field(TokenTableFlags::FIELD) {
        pub flags: FieldAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub signature: Blobbed<FieldSig>,
    }

    pub FieldLayout(TokenTableFlags::FIELD_LAYOUT) {
        pub offset: NonZeroU32,
        #[brw(args_raw = _cx)]
        pub field: Token<Field>,
    }

    pub FieldMarshal(TokenTableFlags::FIELD_MARSHAL) {
        #[brw(args_raw = _cx)]
        pub parent: Token<HasFieldMarshal>,
        #[brw(args_raw = _cx)]
        pub native_type: Blobbed<MarshalDescriptor>,
    }

    pub FieldRva(TokenTableFlags::FIELD_RVA) {
        pub rva: Rva,
        #[brw(args_raw = _cx)]
        pub field: Token<Field>,
    }

    pub File(TokenTableFlags::FILE) {
        pub flags: FileAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub hash_value: BlobIdx,
    }

    pub GenericParam(TokenTableFlags::GENERIC_PARAM) {
        pub number: u16,
        pub flags: GenericParamAttributes,
        #[brw(args_raw = _cx)]
        pub owner: Token<TypeOrMethodDef>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
    }

    pub GenericParamConstraint(TokenTableFlags::GENERIC_PARAM_CONSTRAINT) {
        #[brw(args_raw = _cx)]
        pub owner: Token<GenericParam>,
        #[brw(args_raw = _cx)]
        pub constraint: Token<TypeDefOrRef>,
    }

    pub ImplMap(TokenTableFlags::IMPL_MAP) {
        pub mapping_flags: PInvokeAttributes,
        #[brw(args_raw = _cx)]
        pub member_forwarded: Token<MemberForwarded>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub import_name: String,
        #[brw(args_raw = _cx)]
        pub import_scope: Token<ModuleRef>,
    }

    pub InterfaceImpl(TokenTableFlags::INTERFACE_IMPL) {
        #[brw(args_raw = _cx)]
        pub class: Token<TypeDef>,
        #[brw(args_raw = _cx)]
        pub interface: Token<TypeDefOrRef>,
    }

    pub ManifestResource(TokenTableFlags::MANIFEST_RESOURCE) {
        pub offset: u32,
        pub flags: ManifestResourceAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
    }

    pub MemberRef(TokenTableFlags::MEMBER_REF) {
        #[brw(args_raw = _cx)]
        pub class: Token<MemberRefParent>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub signature: BlobIdx,
    }

    pub MethodDef(TokenTableFlags::METHOD_DEF) {
        pub rva: Rva,
        pub impl_falgs: MethodImplAttributes,
        pub flags: MethodAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub signature: Blobbed<MethodSig>,
         // todo: make a list; this run extends until the end of the table or until the next chronological `param_list_start`
        #[brw(args_raw = _cx)]
        pub param_list_start: Token<Param>,
    }

    pub MethodImpl(TokenTableFlags::METHOD_IMPL) {
        #[brw(args_raw = _cx)]
        pub class: Token<TypeDef>,
        #[brw(args_raw = _cx)]
        pub method_body: Token<MethodDefOrRef>,
        #[brw(args_raw = _cx)]
        pub method_declaration: Token<MethodDefOrRef>,
    }

    pub MethodSemantics(TokenTableFlags::METHOD_SEMANTICS) {
        pub semantics: MethodSemanticsAttributes,
        #[brw(args_raw = _cx)]
        pub method: Token<MethodDef>,
        #[brw(args_raw = _cx)]
        pub association: Token<HasSemantics>,
    }

    pub MethodSpec(TokenTableFlags::METHOD_SPEC) {
        #[brw(args_raw = _cx)]
        pub method: Token<MethodDefOrRef>,
        #[brw(args_raw = _cx)]
        pub instantiation: Blobbed<signatures::MethodSpec>,
    }

    pub Module(TokenTableFlags::MODULE) {
        pub generation: u16,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub mv_id: Guid,
        #[br(parse_with = parse_args!(Guid::read_optional; _cx))]
        #[bw(write_with = write_args!(Guid::write_optional; _cx))]
        pub enc_id: Option<Guid>,
        #[br(parse_with = parse_args!(Guid::read_optional; _cx))]
        #[bw(write_with = write_args!(Guid::write_optional; _cx))]
        pub enc_base_id: Option<Guid>,
    }

    pub ModuleRef(TokenTableFlags::MODULE_REF) {
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
    }

    pub NestedClass(TokenTableFlags::NESTED_CLASS) {
        #[brw(args_raw = _cx)]
        pub nested_class: Token<TypeDef>,
        #[brw(args_raw = _cx)]
        pub enclosing_class: Token<TypeDef>,
    }

    pub Param(TokenTableFlags::PARAM) {
        pub flags: ParamAttributes,
        pub sequence: u16,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
    }

    pub Property(TokenTableFlags::PROPERTY) {
        pub flags: PropertyAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub name: String,
        #[brw(args_raw = _cx)]
        pub type_signature: Blobbed<PropertySig>,
    }

    pub PropertyMap(TokenTableFlags::PROPERTY_MAP) {
        #[brw(args_raw = _cx)]
        pub parent: Token<TypeDef>,
         // todo: make a list; this run extends until the end of the table or until the next chronological `property_list_start`
        #[brw(args_raw = _cx)]
        pub property_list_start: Token<Property>,
    }

    pub StandAloneSig(TokenTableFlags::STAND_ALONE_SIG) {
        #[brw(args_raw = _cx)]
        pub signature: Blobbed<StandAloneSignature>,
    }

    pub TypeDef(TokenTableFlags::TYPE_DEF) {
        pub flags: TypeAttributes,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub type_name: String,
        #[br(parse_with = parse_args!(MetaString::read_opt; _cx))]
        #[bw(write_with = write_args!(MetaString::write_opt; _cx))]
        pub type_namespace: Option<String>,
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub extends: Option<Token<TypeDefOrRef>>,
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub field_list_start: Option<Token<Field>>,
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub method_list_start: Option<Token<MethodDef>>,
    }

    pub TypeRef(TokenTableFlags::TYPE_REF) {
        #[br(parse_with = parse_args!(Token::read_optional; _cx))]
        #[bw(write_with = write_args!(Token::write_optional; _cx))]
        pub resolution_scope: Option<Token<ResolutionScope>>,
        #[br(parse_with = parse_args!(MetaString::read_unwrap; _cx))]
        #[bw(write_with = write_args!(MetaString::write_wrap; _cx))]
        pub type_name: String,
        #[br(parse_with = parse_args!(MetaString::read_opt; _cx))]
        #[bw(write_with = write_args!(MetaString::write_opt; _cx))]
        pub type_namespace: Option<String>,
    }

    pub TypeSpec(TokenTableFlags::TYPE_SPEC) {
        #[brw(args_raw = _cx)]
        pub signature: Blobbed<Type>,
    }
}
