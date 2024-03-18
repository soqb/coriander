use core::fmt;
use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    ops,
};

use binrw::{BinRead, BinResult, BinWrite, Endian};
use bitflags::bitflags;
use deref_derive::{Deref, DerefMut};

#[derive(Deref, DerefMut, BinWrite)]
pub struct Bytes(pub Vec<u8>);

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[... {:?} bytes ...]", self.0.len())
    }
}

fn bytes_until_offset<R: Read + Seek>(
    end_offset: usize,
) -> impl Fn(&mut R, Endian, ()) -> BinResult<Bytes> {
    move |reader, _, _| {
        let offset = reader.stream_position()? as usize;
        let mut vec = vec![0; end_offset - offset];
        reader.read_exact(&mut vec)?;
        Ok(Bytes(vec))
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct CoffCharacteristics: u16 {
        const IS_DLL = 0x2000;
    }
}
bitflags_brw!(CoffCharacteristics: u16);

macro_rules! raw_brw {
    (
        $(#[$attr:meta])*
        $vis:vis struct ($read:ident & $write:ident <- $nice:ident) {
            $(
                $({
                    $(#[$var_attr:meta])*
                    let $var:ident : $var_ty:ty;
                })*

                $(#[$field_attr:meta])*
                $field_vis:vis $field:ident : $field_ty:ty,
            )*
        }
    ) => {
        #[derive(BinRead)]
        $(#[$attr])*
        $vis struct $read {
            $(
                $(
                    $(#[$var_attr])*
                    $var: $var_ty,
                )*
                $(#[$field_attr])*
                $field_vis $field: $field_ty,
            )*
        }

        #[derive(BinWrite)]
        $(#[$attr])*
        $vis struct $write<'a> {
            $(
                $(
                    $(#[$var_attr])*
                    $var: $var_ty,
                )*
                $(#[$field_attr])*
                $field_vis $field: &'a $field_ty,
            )*
        }

        #[derive(Debug)]
        $vis struct $nice {
            $(
                $field_vis $field: $field_ty,
            )*
        }

        impl<'a> $write<'a> {
            pub fn new(
                $nice {
                    $( $field, )*
                }: &'a $nice,
                $(
                    $( $var: $var_ty, )*
                )*
            ) -> Self {
                Self {
                    $($( $var, )*)*
                    $( $field, )*
                }
            }
        }

        impl<'a> $write<'a> {
            pub fn factory(
                $(
                    $( $var: $var_ty, )*
                )*
            ) -> impl Fn(&'_ $nice) -> $write<'_> {
                move |$nice {
                    $( $field, )*
                }| {
                    $write {
                        $($( $var, )*)*
                        $( $field, )*
                    }
                }

            }
        }

        impl $read {
            pub fn unpack($read { $($( $var, )*)* $( $field, )* }: Self) -> ($nice, $($($var_ty,)*)*) {
                (
                    $nice {
                        $( $field, )*
                    },
                    $($( $var, )*)*
                )
            }
        }

        impl From<$read> for ($nice, $($($var_ty,)*)*) {
            fn from(
                $read {
                    $($( $var, )*)*
                    $( $field, )*
                }: $read,
            ) -> Self {
                (
                    $nice {
                        $( $field, )*
                    },
                    $($( $var, )*)*
                )
            }
        }
    };
}

raw_brw! {
    #[derive(Debug)]
    #[brw(magic = b"PE\0\0")]
    pub struct (ReadCoffHeader & WriteCoffHeader <- CoffHeader) {
        {
            #[brw(pad_before = 0x2)]
            let sections_len: u16;
        }
        pub time_date_stamp: u32,
        #[brw(pad_before = 0xA)]
        pub characteristics: CoffCharacteristics,
    }
}

// #[derive(Debug)]
// pub struct CoffHeader {
//     pub time_date_stamp: u32,
//     pub characteristics: CoffCharacteristics,
// }

#[derive(BinRead, BinWrite, Debug)]
pub enum CpuSize {
    #[brw(magic = b"\x0b\x01")]
    X86,
    #[brw(magic = b"\x0b\x02")]
    X64,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct StandardCoffFields {
    #[brw(pad_after = 0x1A)]
    pub cpu_size: CpuSize,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(repr = u16)]
pub enum Subsystem {
    Unknown,
    Native,
    Gui,
    Console,
    Os2,
    Posix,
    NativeWindows,
    WindowsCeGui,
    EfiApp,
    EfiBootServiceDriver,
    EfiRuntimeDriver,
    EfiRom,
    Xbox,
    WindowsBootApp,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct NtFields {
    #[brw(pad_before = 0x28, pad_after = 0x1A)]
    pub subsystem: Subsystem,
}

#[derive(BinRead, BinWrite, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rva(pub u32);

impl fmt::Debug for Rva {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r:{:#010x}", self.0)
    }
}

impl ops::Add for Rva {
    type Output = Rva;

    fn add(self, rhs: Self) -> Self::Output {
        self + rhs.0
    }
}

impl ops::Sub for Rva {
    type Output = Rva;

    fn sub(self, rhs: Self) -> Self::Output {
        self - rhs.0
    }
}

impl ops::Add<u32> for Rva {
    type Output = Rva;

    fn add(self, rhs: u32) -> Self::Output {
        Rva(self.0 + rhs)
    }
}

impl ops::Sub<u32> for Rva {
    type Output = Rva;

    fn sub(self, rhs: u32) -> Self::Output {
        Rva(self.0 - rhs)
    }
}

#[derive(BinRead, BinWrite, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Region {
    pub ptr: Rva,
    pub size: u32,
}

impl Region {
    pub fn read_reversed<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (): (),
    ) -> BinResult<Self> {
        Ok(Self {
            size: u32::read_options(reader, endian, ())?,
            ptr: Rva::read_options(reader, endian, ())?,
        })
    }

    pub fn write_reversed<W: Write + Seek>(
        Self { ptr, size }: Self,
        writer: &mut W,
        endian: Endian,
        (): (),
    ) -> BinResult<()> {
        size.write_options(writer, endian, ())?;
        ptr.write_options(writer, endian, ())
    }
}

impl Region {
    pub fn is_empty(&self) -> bool {
        self.ptr == Rva(0) && self.size == 0
    }
}

#[derive(BinRead, BinWrite, Debug)]
pub struct DataDirectories {
    pub export_table: Region,
    pub import_table: Region,
    pub resource_table: Region,
    pub exception_table: Region,
    pub certificate_table: Region,
    pub base_relocation_table: Region,
    pub debug: Region,
    pub architecture_data: Region,
    #[brw(pad_after = 0x4)]
    pub global_ptr: Rva,
    pub tls_table: Region,
    pub load_config_table: Region,
    pub bound_import: Region,
    pub import_address_table: Region,
    pub delay_import_descriptor: Region,
    #[brw(pad_after = 0x8)]
    pub cli_header: Region,
}

fn read_section_name<R: Read + Seek>(reader: &mut R, _: Endian, _: ()) -> BinResult<String> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes.iter().copied().filter(|&x| x != 0).collect()).or_else(|err| {
        Err(binrw::Error::Custom {
            pos: reader.stream_position()? - 8,
            err: Box::new(err),
        })
    })
}

fn write_section_name<W: Write + Seek>(
    string: &String,
    writer: &mut W,
    _: Endian,
    _: (),
) -> BinResult<()> {
    assert!(string.len() <= 8);
    writer.write(string.as_bytes())?;
    for _ in string.len()..8 {
        writer.write(&[0])?;
    }

    Ok(())
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SectionCharacteristics: u32 {
        const TYPE_NO_PAD = 0x8;
        const CNT_CODE = 0x20;
        const CNT_INITIALIZED_DATA = 0x40;
        const CNT_UNINITIALIZED_DATA = 0x80;
        const LNK_INFO = 0x200;
        const LNK_REMOVE = 0x800;
        const LNK_COMDAT = 0x1000;
        const GPREL = 0x8000;
        const ALIGN_1 = 0x100000;
        const ALIGN_2 = 0x200000;
        const ALIGN_4 = 0x300000;
        const ALIGN_8 = 0x400000;
        const ALIGN_16 = 0x500000;
        const ALIGN_32 = 0x600000;
        const ALIGN_64 = 0x700000;
        const ALIGN_128 = 0x800000;
        const ALIGN_256 = 0x900000;
        const ALIGN_512 = 0xA00000;
        const ALIGN_1024 = 0xB00000;
        const ALIGN_2048 = 0xC00000;
        const ALIGN_4096 = 0xD00000;
        const ALIGN_8192 = 0xE00000;
        const LNK_NRELOC_OVFL = 0x1000000;
        const MEM_DISCARDABLE = 0x2000000;
        const MEM_NOT_CACHED = 0x4000000;
        const MEM_NOT_PAGED = 0x8000000;
        const MEM_SHARED = 0x10000000;
        const MEM_EXECUTE = 0x20000000;
        const MEM_READ = 0x40000000;
        const MEM_WRITE = 0x80000000;
    }
}
bitflags_brw!(SectionCharacteristics: u32);

#[binrw::binrw]
#[derive(Debug)]
pub struct SectionHeader {
    #[br(parse_with = read_section_name)]
    #[bw(write_with = write_section_name)]
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: Rva,

    pub data_len: u32,
    pub data_offset: u32,
    #[brw(pad_before = 0xC)]
    pub characteristics: SectionCharacteristics,
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: Rva,
    pub characteristics: SectionCharacteristics,
    pub body_offset: Option<u32>,
    pub body: Bytes,
}

fn read_sections<R: Read + Seek>(
    reader: &mut R,
    endian: Endian,
    (count,): (u16,),
) -> BinResult<Vec<Section>> {
    let mut sections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let SectionHeader {
            name,
            virtual_size,
            virtual_address,
            data_len,
            data_offset,
            characteristics,
        } = SectionHeader::read_options(reader, endian, ())?;
        let section = Section {
            name,
            virtual_size,
            virtual_address,
            characteristics,
            body: {
                let before = reader.stream_position()?;
                reader.seek(SeekFrom::Start(data_offset as u64))?;
                let mut value = vec![0; data_len as usize];
                reader.read_exact(&mut value)?;
                reader.seek(SeekFrom::Start(before))?;
                Bytes(value)
            },
            body_offset: Some(data_offset),
        };
        sections.push(section);
    }
    Ok(sections)
}

fn write_sections<W: Write + Seek>(
    sections: &Vec<Section>,
    writer: &mut W,
    endian: Endian,
    _args: (),
) -> BinResult<()> {
    let mut data_offset = writer.stream_position()? as u32 + (sections.len() * 0x28) as u32;
    for &Section {
        ref name,
        virtual_size,
        virtual_address,
        characteristics,
        ref body,
        body_offset: _,
    } in sections
    {
        let data_len = body.len() as u32;
        let header = SectionHeader {
            name: name.clone(),
            virtual_size,
            virtual_address,
            data_len,
            data_offset,
            characteristics,
        };

        header.write_options(writer, endian, ())?;

        data_offset += data_len;
    }
    for Section { body, .. } in sections {
        writer.write_all(body)?;
    }
    Ok(())
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little, magic = b"MZ")]
pub struct Pe {
    #[brw(align_before = 0x3C, align_after = 0x40)]
    #[bw(calc = 0x40 + dos_stub.len() as u32)]
    pe_signature_offset: u32,
    #[br(parse_with = bytes_until_offset(pe_signature_offset as usize))]
    pub dos_stub: Bytes,

    #[br(temp, map = ReadCoffHeader::unpack)]
    #[bw(ignore)]
    read_coff_header: (CoffHeader, u16),
    #[br(calc = read_coff_header.0)]
    #[bw(map = WriteCoffHeader::factory(sections.len() as u16))]
    pub coff_header: CoffHeader,

    pub standard_fields: StandardCoffFields,
    pub nt_fields: NtFields,
    pub data_dirs: DataDirectories,
    #[br(parse_with = read_sections, args(read_coff_header.1))]
    #[bw(write_with = write_sections)]
    pub sections: Vec<Section>,
}

impl Rva {
    pub fn is_contained_in(self, section: &Section) -> bool {
        section.virtual_address < self && self < section.virtual_address + section.virtual_size
    }

    pub fn slice_section(self, section: &Section) -> Option<&[u8]> {
        self.is_contained_in(section)
            .then(|| (self - section.virtual_address).0)
            .map(|x| &section.body[x as usize..])
    }

    pub fn find_containing<'a>(
        self,
        sections: impl IntoIterator<Item = &'a Section>,
    ) -> Option<&'a Section> {
        sections
            .into_iter()
            .find(|section| self.is_contained_in(section))
    }

    pub fn slice_sections<'a>(
        self,
        sections: impl IntoIterator<Item = &'a Section>,
    ) -> Option<&'a [u8]> {
        sections
            .into_iter()
            .find_map(|section| self.slice_section(section))
    }
}

impl Region {
    pub fn slice_section(self, section: &Section) -> Option<&[u8]> {
        if self.is_empty() {
            return None;
        }

        self.ptr
            .slice_section(section)
            .map(|bytes| &bytes[0..self.size as usize])
    }

    pub fn slice_sections(self, sections: &[Section]) -> Option<&[u8]> {
        if self.is_empty() {
            return None;
        }

        self.ptr
            .slice_sections(sections)
            .map(|bytes| &bytes[0..self.size as usize])
    }

    pub fn parse_options<T: BinRead>(
        self,
        section: &Section,
        endian: Endian,
        args: T::Args<'_>,
    ) -> BinResult<Option<T>> {
        self.slice_section(section)
            .map(|bytes| {
                let mut cursor = Cursor::new(bytes);
                T::read_options(&mut cursor, endian, args)
            })
            .transpose()
    }

    pub fn parse_le<T: BinRead>(self, section: &Section) -> BinResult<Option<T>>
    where
        for<'a> T::Args<'a>: Default,
    {
        self.parse_options(section, Endian::Little, <T::Args<'_>>::default())
    }
}
