pub mod signatures;
mod tables;
mod token;

use core::fmt;
use std::{
    cmp::Ordering,
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    iter,
};

use binrw::{BinRead, BinResult, BinWrite, Endian};
use bitflags::bitflags;

pub use tables::*;
pub use token::*;

use crate::{
    utils::{BinReadOptional, BinRemote, BinWriteOptional, ZString},
    VersionU16, VersionU8,
};

#[binrw::binrw]
#[derive(Debug)]
#[brw(magic = 0x424A5342_u32, stream = stream_for_pos)]
pub struct MetadataRoot {
    #[br(temp, try_calc = stream_for_pos.stream_position().map(|pos| pos - 4))]
    #[bw(ignore)]
    stream_pos: u64,
    pub version: VersionU16,
    #[brw(pad_before = 0x4)]
    #[br(temp)]
    #[bw(
        assert(version_name.len() % 4 == 0, "the length of the version string should be aligned to 4 bytes."),
        try_calc(u8::try_from(version_name.len()).map(u32::from)),
    )]
    string_length: u32,
    #[br(try_map = |bytes| String::from_utf8(bytes), count = string_length)]
    #[bw(map = |string| string.as_bytes())]
    pub version_name: String,
    // todo: this might need to be aligned to 4 but i think its redundant since `string_length` is already similarly restricted.
    pub flags: u16,
    #[br(args(stream_pos), map = Streams::unwrap)]
    #[bw(map = Streams::wrap)]
    pub metadata: Metadata,
}

fn with_seek<S: Seek, T>(
    seek: SeekFrom,
    stream: &mut S,
    f: impl FnOnce(&mut S) -> BinResult<T>,
) -> BinResult<T> {
    let old_pos = stream.stream_position()?;
    stream.seek(seek)?;
    let val = f(stream)?;
    stream.seek(SeekFrom::Start(old_pos))?;
    Ok(val)
}

#[derive(Debug, Clone, Copy)]
pub struct Guid(pub u128);

impl BinReadOptional for Guid {
    type Args<'a> = &'a MetaRead;

    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        cx: Self::Args<'_>,
    ) -> BinResult<Option<Self>> {
        GuidIdx::read_optional(reader, endian, cx)
            .transpose()
            .map(|idx| {
                // multiply by 16 since `GuidIdx`s are index-based not byte-based.
                let offset = u64::from(idx?.to_u32()) * 16;
                with_seek(
                    SeekFrom::Start(cx.heaps.guid.offset + offset),
                    reader,
                    move |reader| u128::read_options(reader, endian, ()).map(Guid),
                )
            })
            .transpose()
    }
}

impl BinWriteOptional for Guid {
    type Args<'a> = &'a MetaWrite;

    fn write_some<W: std::io::prelude::Write + Seek>(
        &self,
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }

    fn write_none<W: std::io::prelude::Write + Seek>(
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }
}

impl_brw_optional!(for Guid);

binrw_remote! {
    pub MetaString <- String;
}

impl BinReadOptional for MetaString {
    type Args<'a> = &'a MetaRead;

    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        cx: Self::Args<'_>,
    ) -> BinResult<Option<Self>> {
        StringIdx::read_optional(reader, endian, cx)
            .transpose()
            .map(|idx| {
                let offset = u64::from(idx?.to_u32());
                with_seek(
                    SeekFrom::Start(cx.heaps.string.offset + offset),
                    reader,
                    move |reader| {
                        ZString::read_options(reader, endian, ())
                            .map(|ZString(data)| MetaString(data))
                    },
                )
            })
            .transpose()
    }
}

impl BinWriteOptional for MetaString {
    type Args<'a> = &'a MetaWrite;

    fn write_some<W: std::io::prelude::Write + Seek>(
        &self,
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }

    fn write_none<W: std::io::prelude::Write + Seek>(
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }
}

impl_brw_optional!(for MetaString);

#[derive(ref_cast::RefCastCustom, Debug)]
#[repr(transparent)]
pub struct Blobbed<T>(pub Box<T>);

impl<T> BinRemote<Box<T>> for Blobbed<T> {
    #[ref_cast::ref_cast_custom]
    fn wrap(value: &Box<T>) -> &Self;
    fn unwrap(self) -> Box<T> {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobInt(pub u32);

impl From<BlobInt> for usize {
    fn from(value: BlobInt) -> usize {
        value.0 as usize
    }
}

impl TryFrom<usize> for BlobInt {
    type Error = std::num::TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        u32::try_from(value).map(Self)
    }
}

impl BinRead for BlobInt {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let a = u8::read_options(reader, Endian::Little, ())?;
        let value = match a.leading_ones() {
            0 => a as u32,
            1 => {
                let b = u8::read_options(reader, Endian::Little, ())?;
                (u16::from_le_bytes([b, a & 0x3f])).into()
            }
            2 => {
                let [b, c, d] = <[u8; 3]>::read_options(reader, Endian::Little, ())?;
                u32::from_le_bytes([d, c, b, a & 0x1f])
            }
            _ => {
                return Err(binrw::Error::Custom {
                    pos: reader.stream_position()?,
                    err: Box::new("invalid blob int"),
                })
            }
        };
        Ok(Self(value))
    }
}

impl BinWrite for BlobInt {
    type Args<'a> = ();

    fn write_options<W: std::io::prelude::Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<()> {
        let abcd = self.0;
        match abcd {
            0..=0x7f => {
                let [a, ..] = abcd.to_le_bytes();
                a.write_options(writer, endian, ())
            }
            0x80..=0x3fff => {
                let [b, a, ..] = abcd.to_le_bytes();
                let ab = u16::from_le_bytes([b, a]);
                (ab | 0x8000).write_options(writer, Endian::Big, ())
            }
            0x4000..=0x1fffffff => (abcd | 0xc0000000).write_options(writer, Endian::Big, ()),
            _ => Err(binrw::Error::Custom {
                pos: writer.stream_position()?,
                err: Box::new("too large blob int"),
            }),
        }
    }
}

pub(crate) trait BlobArgs<C> {
    fn from_cx(blob_size: u32, cx: C) -> Self;
}

impl<C> BlobArgs<C> for () {
    fn from_cx(_: u32, _: C) -> Self {
        ()
    }
}

impl<'a> BlobArgs<Self> for &'a MetaRead {
    fn from_cx(_: u32, cx: Self) -> Self {
        cx
    }
}

impl<'a> BlobArgs<Self> for &'a MetaWrite {
    fn from_cx(_: u32, cx: Self) -> Self {
        cx
    }
}

impl<C> BlobArgs<C> for (C,) {
    fn from_cx(_: u32, cx: C) -> Self {
        (cx,)
    }
}

impl<T: BinRead> BinReadOptional for Blobbed<T>
where
    for<'a> T::Args<'a>: BlobArgs<&'a MetaRead>,
{
    type Args<'a> = &'a MetaRead;

    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        cx: Self::Args<'_>,
    ) -> BinResult<Option<Self>> {
        BlobIdx::read_optional(reader, endian, cx)
            .transpose()
            .map(|idx| {
                let offset = u64::from(idx?.to_u32());
                with_seek(
                    SeekFrom::Start(cx.heaps.blob.offset + offset),
                    reader,
                    move |reader| {
                        let BlobInt(blob_size) = BlobInt::read_options(reader, endian, ())?;

                        T::read_options(reader, endian, T::Args::from_cx(blob_size, cx))
                            .map(|x| Blobbed(Box::new(x)))
                    },
                )
            })
            .transpose()
    }
}

impl<T: BinWrite> BinWriteOptional for Blobbed<T>
where
    for<'a> T::Args<'a>: BlobArgs<&'a MetaWrite>,
{
    type Args<'a> = &'a MetaWrite;

    fn write_some<W: std::io::prelude::Write + Seek>(
        &self,
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }

    fn write_none<W: std::io::prelude::Write + Seek>(
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }
}

impl_brw_optional!({T} for Blobbed<T>);

#[derive(Clone, Copy, Debug)]
pub struct Heap {
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct Heaps {
    string: Heap,
    user_string: Heap,
    blob: Heap,
    guid: Heap,
}

impl Heaps {
    fn heap_sizes(&self) -> HeapSizes {
        const HEAP_SIZE_BIG: u64 = 1 << 16;

        let mut sizes = HeapSizes::empty();

        if self.string.size >= HEAP_SIZE_BIG {
            sizes |= HeapSizes::STRING_STREAM_IS_BIG;
        }
        if self.blob.size >= HEAP_SIZE_BIG {
            sizes |= HeapSizes::BLOB_STREAM_IS_BIG;
        }
        if self.guid.size >= HEAP_SIZE_BIG {
            sizes |= HeapSizes::GUID_STREAM_IS_BIG;
        }

        sizes
    }
}

impl Default for Heaps {
    fn default() -> Self {
        let empty = Heap { offset: 0, size: 0 };
        Heaps {
            string: empty,
            user_string: empty,
            blob: empty,
            guid: empty,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetaRead {
    heaps: Heaps,
    sizes: SizeFlags,
}

impl MetaRead {
    pub fn new(sizes: SizeFlags, heaps: Heaps) -> Self {
        Self { sizes, heaps }
    }

    pub fn sizes(&self) -> &SizeFlags {
        &self.sizes
    }
}

#[derive(Debug)]
pub struct MetaWrite {
    sizes: SizeFlags,
    order: TablesOrder,
}

impl MetaWrite {
    pub fn new(sizes: SizeFlags, order: TablesOrder) -> Self {
        Self { sizes, order }
    }

    pub fn sizes(&self) -> &SizeFlags {
        &self.sizes
    }

    pub fn order(&self) -> &TablesOrder {
        &self.order
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("stale token encountered: {idx:?} in the {table:?} table")]
pub struct StaleTokenError {
    table: TableId,
    idx: TableIdx,
}

impl From<StaleTokenError> for binrw::Error {
    fn from(value: StaleTokenError) -> Self {
        Self::Custom {
            pos: 0,
            err: Box::new(value),
        }
    }
}

binrw_remote! {
    Streams <- Metadata;
}

impl BinRead for Streams {
    type Args<'a> = (u64,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (metadata_root_pos,): Self::Args<'_>,
    ) -> BinResult<Self> {
        let count = u16::read_options(reader, endian, ())?;
        let headers: HashMap<String, (u32, u32)> =
            iter::repeat_with(|| BinRead::read_options(reader, endian, ()))
                .take(count.into())
                .map(|res| {
                    res.map(|header: StreamHeader| {
                        (header.name, (header.offset_from_metadata_root, header.size))
                    })
                })
                .collect::<BinResult<_>>()?;

        let header = |name: &str| {
            headers
                .get(name)
                .map(|&(offset, size)| Heap {
                    offset: metadata_root_pos + u64::from(offset),
                    size: size.into(),
                })
                .ok_or_else(|| binrw::Error::Custom {
                    pos: metadata_root_pos,
                    err: Box::new(format!("no {name} stream found")),
                })
        };

        let heaps = Heaps {
            string: header("#Strings")?,
            user_string: header("#US")?,
            blob: header("#Blob")?,
            guid: header("#GUID")?,
        };

        let metadata = {
            let Heap { offset, size } = header("#~")?;

            reader.seek(SeekFrom::Start(offset))?;
            let value = Metadata::read_options(reader, endian, (heaps,))?;
            reader.seek(SeekFrom::Start(offset + size))?;
            value
        };

        Ok(Self(metadata))
    }
}

impl BinWrite for Streams {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + Seek>(
        &self,
        _writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        todo!()
    }
}

#[derive(BinRead, BinWrite, Debug)]
pub struct StreamHeader {
    pub offset_from_metadata_root: u32,
    pub size: u32,
    #[brw(align_after = 0x4)]
    #[brw(assert(name.len() <= 32))]
    #[br(map = ZString::unwrap)]
    #[bw(map = ZString::wrap)]
    pub name: String,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct HeapSizes: u8 {
        const STRING_STREAM_IS_BIG = 0x01;
        const GUID_STREAM_IS_BIG = 0x02;
        const BLOB_STREAM_IS_BIG = 0x04;
    }
}
bitflags_brw!(HeapSizes: u8);

#[binrw::binrw]
#[derive(Debug)]
#[brw(import(heaps: Heaps))]
pub struct Metadata {
    #[bw(assert(*reserved == 0))]
    pub reserved: u32,
    #[br(assert(version == VersionU8 { major: 2, minor: 0 }))]
    #[bw(assert(*version == VersionU8 { major: 2, minor: 0 }))]
    pub version: VersionU8,
    #[br(temp)]
    #[bw(ignore)]
    heap_sizes: HeapSizes,
    #[bw(assert(*reserved2 == 1))]
    pub reserved2: u8,
    #[br(args(heaps, heap_sizes))]
    #[bw(args(&heaps.heap_sizes()))]
    pub tables: Tables,
}

macro_rules! def_tables {
    ($vis:vis $name:ident {
        $(
            $field:ident : $table:ident,
        )*
    }) => {
        #[derive(Debug)]
        $vis struct $name {
            pub module: Module,
            $(
                pub $field: Table<$table>,
            )*
        }

        impl Tables {
            pub fn new(module: Module) -> Self {
                Self {
                    module,
                    $(
                        $field: Default::default(),
                    )*
                }
            }
        }

        impl BinRead for Tables {
            type Args<'a> = (Heaps, HeapSizes);

            fn read_options<R: Read + Seek>(
                reader: &mut R,
                endian: Endian,
                (heaps, heap_sizes,): Self::Args<'_>,
            ) -> BinResult<Self> {
                let present_tables = TokenTableFlags::read_options(reader, endian, ())?;
                let _sorted_tables = TokenTableFlags::read_options(reader, endian, ())? & present_tables;

                let row_count_map = present_tables
                    .iter()
                    .flat_map(TokenTableFlags::to_discrete)
                    .zip(iter::from_fn(|| {
                        Some(u32::read_options(reader, endian, ()))
                    }))
                    .map(|(table, count)| count.map(|count| (table, count)))
                    .collect::<BinResult<HashMap<_, _>>>()?;

                let sizes = SizeFlags::new(heap_sizes, &row_count_map);
                let cx = MetaRead::new(sizes, heaps);

                let mut tables = Tables::new(Module::read_options(reader, endian, (&cx,))?);

                // sort of janky iterator because we need the correct order (todo: consider IndexMap?).
                for (table_id, &row_count) in present_tables
                    .iter()
                    .flat_map(TokenTableFlags::to_discrete)
                    .flat_map(|table| row_count_map.get(&table).map(|count| (table, count)))
                {
                    println!("{table_id:?}: {row_count}");
                    match table_id {
                        TableId::Module => continue,
                        $(
                            TableId::$table => {
                                // todo: handle sorting
                                for _ in 0..row_count {
                                    let row = <$table>::read_options(reader, endian, (&cx,))?;
                                    tables.$field.push_row(row);
                                }
                            }
                        )*
                    }
                }

                Ok(tables)
            }
        }

        impl BinWrite for Tables {
            type Args<'a> = (&'a HeapSizes,);

            fn write_options<W: std::io::Write + Seek>(
                &self,
                writer: &mut W,
                endian: Endian,
                (&heap_sizes,): Self::Args<'_>,
            ) -> BinResult<()> {
                let mut present_tables = TokenTableFlags::MODULE;
                let _sorted_tables = TokenTableFlags::default();
                $(
                    if !self.$field.is_empty() {
                        present_tables |= TokenTableFlags::from_discrete(TableId::$table);
                        // todo: handle sorting of tables (all should be sorted?)
                    }
                )*
                present_tables.write_options(writer, endian, ())?;
                _sorted_tables.write_options(writer, endian, ())?;

                // todo: probably should assert that this is sorted correctly.
                let row_counts = [
                    (TableId::Module, 1),
                    $((TableId::$table, self.$field.len() as u32),)*
                ];

                for (_, row_count) in &row_counts {
                    row_count.write_options(writer, endian, ())?;
                }

                let row_count_map = row_counts.into_iter().collect();

                let sizes = SizeFlags::new(heap_sizes, &row_count_map);
                let cx = MetaWrite::new(sizes, Self::order(self));

                self.module.write_options(writer, endian, (&cx,))?;

                $({
                    for row in cx.order().iter_rows(&self.$field, TableId::$table) {
                        row.write_options(writer, endian, (&cx,))?;
                    }
                })*

                Ok(())
            }
        }
        impl $name {
            pub fn order(_tables: &$name) -> TablesOrder {
                todo!()
            }
        }
    };
}

def_tables!(pub Tables {
    type_ref: TypeRef,
    type_def: TypeDef,
    field: Field,
    method_def: MethodDef,
    param: Param,
    interface_impl: InterfaceImpl,
    member_ref: MemberRef,
    constant: Constant,
    custom_attribute: CustomAttribute,
    field_marshal: FieldMarshal,
    decl_security: DeclSecurity,
    class_layout: ClassLayout,
    field_layout: FieldLayout,
    stand_alone_sig: StandAloneSig,
    event_map: EventMap,
    event: Event,
    property_map: PropertyMap,
    property: Property,
    method_semantics: MethodSemantics,
    method_impl: MethodImpl,
    module_ref: ModuleRef,
    type_spec: TypeSpec,
    impl_map: ImplMap,
    field_rva: FieldRva,
    assembly: Assembly,
    assembly_processor: AssemblyProcessor,
    assembly_os: AssemblyOs,
    assembly_ref: AssemblyRef,
    assembly_ref_processor: AssemblyRefProcessor,
    assembly_ref_os: AssemblyRefOs,
    file: File,
    exported_type: ExportedType,
    manifest_resource: ManifestResource,
    nested_class: NestedClass,
    generic_param: GenericParam,
    method_spec: MethodSpec,
    generic_param_constraint: GenericParamConstraint,
});

/// An index into a [`Table`].
///
/// This allows us a level of indirection which makes it convenient and performant
/// to reorder tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableIdx(usize);

impl TableIdx {
    /// Thinly creates a [`TableIdx`] from a [`Rid`].
    ///
    /// # Usage
    /// For logical consistency, the relevant table must not have had
    /// any rows removed. Otherwise, the [`Rid`]s will be out of sync with the table.
    pub fn new_thin(rid: Rid) -> Self {
        Self(rid.to_u32() as usize - 1)
    }
}

/// An unordered list of rows, containing CLI metadata.
pub struct Table<T> {
    // NB: right now this is leaky. idk if we need to do anyhting about it.
    rows: Vec<Option<T>>,
}

impl<T: fmt::Debug> fmt::Debug for Table<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (i, row) in self.rows.iter().enumerate() {
            map.entry(&i, row);
        }
        map.finish()
    }
}

impl<T> Default for Table<T> {
    fn default() -> Self {
        Self {
            rows: Default::default(),
        }
    }
}

impl<T> Table<T> {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn contains(&self, idx: TableIdx) -> bool {
        self.get(idx).is_some()
    }

    pub fn get(&self, idx: TableIdx) -> Option<&T> {
        self.rows.get(idx.0).and_then(Option::as_ref)
    }

    pub fn get_mut(&mut self, idx: TableIdx) -> Option<&mut T> {
        self.rows.get_mut(idx.0).and_then(Option::as_mut)
    }

    pub fn remove_row(&mut self, idx: TableIdx) -> Option<T> {
        self.rows.get_mut(idx.0).and_then(Option::take)
    }

    pub fn push_row(&mut self, value: T) -> TableIdx {
        let idx = self.len();
        self.rows.push(Some(value));
        TableIdx(idx)
    }
}

#[derive(Debug)]
pub struct TableEntryOrder {
    idx_to_rid: HashMap<TableIdx, Rid>,
    rid_to_idx: Vec<TableIdx>,
}

impl TableEntryOrder {
    pub fn unsorted<T>(table: &Table<T>) -> Self {
        let idx_to_rid = table
            .rows
            .iter()
            .enumerate()
            .scan(0, |used_idx: &mut u32, (i, row)| {
                if row.is_some() {
                    *used_idx += 1;
                    let entry = (TableIdx(i), Rid::new(*used_idx + 1).unwrap());
                    Some(Some(entry))
                } else {
                    Some(None)
                }
            })
            .flatten()
            .collect();
        Self {
            idx_to_rid,
            rid_to_idx: (0..table.rows.len())
                .map(TableIdx)
                .filter(|&idx| table.contains(idx))
                .collect(),
        }
    }

    pub fn sorted_by<T>(table: &Table<T>, mut f: impl FnMut(&T, &T) -> Ordering) -> Self {
        let mut rid_to_idx: Vec<TableIdx> = (0..)
            .take(table.len())
            .map(|idx| TableIdx(idx))
            .filter(|&idx| table.contains(idx))
            .collect();
        rid_to_idx.sort_unstable_by(|&a, &b| f(table.get(a).unwrap(), table.get(b).unwrap()));
        let rids = rid_to_idx
            .iter()
            .enumerate()
            .map(|(rid_i, &idx)| (idx, Rid::new((rid_i + 1) as u32).unwrap()))
            .collect();
        Self {
            idx_to_rid: rids,
            rid_to_idx,
        }
    }

    pub fn get_rid(&self, idx: TableIdx) -> Option<Rid> {
        self.idx_to_rid.get(&idx).copied()
    }

    pub fn iter_rows<'a, T>(&'a self, table: &'a Table<T>) -> impl Iterator<Item = &'a T> + 'a {
        self.rid_to_idx
            .iter()
            .map(|&idx| table.get(idx).expect("table should contain row {idx:?}"))
    }
}

#[derive(Debug)]
pub struct TablesOrder {
    // hmm. there are some ids that are skipped, but i think this approach is sufficient.
    storage: [TableEntryOrder; TableId::MAX_PLUS_ONE as usize],
}

impl TablesOrder {
    fn table_order(&self, id: TableId) -> &TableEntryOrder {
        &self.storage[id as u8 as usize]
    }

    pub fn token_rid<T: TokenType + ?Sized>(
        &self,
        token: Token<T>,
    ) -> Result<Rid, StaleTokenError> {
        self.table_order(token.table_id())
            .get_rid(token.idx)
            .ok_or_else(|| StaleTokenError {
                table: token.table_id(),
                idx: token.idx,
            })
    }

    pub fn iter_rows<'a, T>(
        &'a self,
        table: &'a Table<T>,
        table_id: TableId,
    ) -> impl Iterator<Item = &'a T> + 'a {
        self.table_order(table_id).iter_rows(table)
    }
}

macro_rules! def_enum_flags {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident: $repr:ty { $enum_:ty as $enum_repr:ty } {
            $($flag:ident = $variant:ident);* $(;)?
        }
    ) => {
        bitflags! {
            $(#[$attr])*
            $vis struct $name: $repr {
                $(
                    const $flag = 1 << (<$enum_>::$variant as $enum_repr);
                )*
            }
        }

        impl $name {
            pub const fn to_discrete(self) -> Option<$enum_> {
                match self {
                    $(
                        Self::$flag => Some(<$enum_>::$variant),
                    )*
                    _ => None,
                }
            }

            pub const fn from_discrete(discrete: $enum_) -> Self {
                Self::from_bits_retain(1 << (discrete as $enum_repr))
            }
        }
    };
}

def_enum_flags! {
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TokenTableFlags: u64 { TableId as u8 } {
        MODULE = Module;
        TYPE_REF = TypeRef;
        TYPE_DEF = TypeDef;
        FIELD = Field;
        METHOD_DEF = MethodDef;
        PARAM = Param;
        INTERFACE_IMPL = InterfaceImpl;
        MEMBER_REF = MemberRef;
        CONSTANT = Constant;
        CUSTOM_ATTRIBUTE = CustomAttribute;
        FIELD_MARSHAL = FieldMarshal;
        DECL_SECURITY = DeclSecurity;
        CLASS_LAYOUT = ClassLayout;
        FIELD_LAYOUT = FieldLayout;
        STAND_ALONE_SIG = StandAloneSig;
        EVENT_MAP = EventMap;
        EVENT = Event;
        PROPERTY_MAP = PropertyMap;
        PROPERTY = Property;
        METHOD_SEMANTICS = MethodSemantics;
        METHOD_IMPL = MethodImpl;
        MODULE_REF = ModuleRef;
        TYPE_SPEC = TypeSpec;
        IMPL_MAP = ImplMap;
        FIELD_RVA = FieldRva;
        ASSEMBLY = Assembly;
        ASSEMBLY_PROCESSOR = AssemblyProcessor;
        ASSEMBLY_OS = AssemblyOs;
        ASSEMBLY_REF = AssemblyRef;
        ASSEMBLY_REF_PROCESSOR = AssemblyRefProcessor;
        ASSEMBLY_REF_OS = AssemblyRefOs;
        FILE = File;
        EXPORTED_TYPE = ExportedType;
        MANIFEST_RESOURCE = ManifestResource;
        NESTED_CLASS = NestedClass;
        GENERIC_PARAM = GenericParam;
        METHOD_SPEC = MethodSpec;
        GENERIC_PARAM_CONSTRAINT = GenericParamConstraint;
    }
}

bitflags_brw!(TokenTableFlags: u64);

#[cfg(test)]
mod tests {
    use binrw::{BinRead, BinResult, BinWrite, Endian};

    use crate::metadata::BlobInt;

    #[test]
    fn blob_int() -> BinResult<()> {
        macro_rules! test {
            ($x:literal, $expected:expr) => {{
                let mut buf = [0; 4];
                {
                    let mut cursor = std::io::Cursor::new(&mut buf[..]);
                    BlobInt($x).write_options(&mut cursor, Endian::Little, ())?;
                }

                assert_eq!(
                    buf,
                    $expected,
                    "written blob int didn't match {}",
                    stringify!($expected)
                );

                let mut cursor = std::io::Cursor::new(&mut buf[..]);
                let roundtrip =
                    BlobInt::read_options(&mut cursor, Endian::Little, ()).map(|BlobInt(x)| x)?;

                assert_eq!(
                    roundtrip,
                    $x,
                    "read blob int didn't match {}",
                    stringify!($x)
                );
            }};
        }

        test!(0x03, [0x03, 0, 0, 0]);
        test!(0x7f, [0x7f, 0, 0, 0]);
        test!(0x80, [0x80, 0x80, 0, 0]);
        test!(0x2e57, [0xae, 0x57, 0, 0]);
        test!(0x3fff, [0xbf, 0xff, 0, 0]);
        test!(0x4000, [0xc0, 0x00, 0x40, 0x00]);
        test!(0x1fffffff, [0xdf, 0xff, 0xff, 0xff]);

        Ok(())
    }
}
