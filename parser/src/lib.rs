use anyhow::anyhow;
use binrw::{BinRead, BinWrite};
use bitflags::bitflags;

#[macro_use]
pub mod utils;

#[macro_use]
pub mod pe;
pub mod metadata;

use metadata::MetadataRoot;
use pe::{Pe, Region};

pub(crate) use pe::Rva;

#[derive(BinRead, BinWrite, Debug, PartialEq)]
pub struct VersionU8 {
    pub major: u8,
    pub minor: u8,
}

#[derive(BinRead, BinWrite, Debug, PartialEq)]
pub struct VersionU16 {
    pub major: u16,
    pub minor: u16,
}

#[derive(BinRead, BinWrite, Debug, PartialEq)]
pub struct VersionU32 {
    pub major: u32,
    pub minor: u32,
}

bitflags! {
    #[derive(Debug)]
    pub struct RuntimeFlags: u32 {
        const ILONLY = 0x1;
        #[doc(alias = "32BITREQUIRED")]
        const THIRTY_TWO_BIT_REQUIRED = 0x2;
        #[doc(alias = "STRONGNAMESIGNED")]
        const STRONG_NAME_SIGNED = 0x8;
        /// Should not be set for a compliant CLR binary.
        const NATIVE_ENTRYPOINT = 0x10;
        /// Should not be set for a compliant CLR binary.
        #[doc(alias = "TRACKDEBUGDATA")]
        const TRACK_DEBUG_DATA = 0x10000;
    }
}
bitflags_brw!(RuntimeFlags: u32);

#[derive(BinRead, BinWrite, Debug)]
pub struct CliHeader {
    #[brw(pad_before = 0x4)]
    pub version: VersionU16,
    pub metadata: Region,
    pub flags: RuntimeFlags,
    // sorry entrypoint. you will be restored to full strength in time.
    pub entrypoint: u32,
    pub implementation_resources: Region,
    #[brw(pad_after = 0x4)]
    pub strong_name_signature: Rva,
    #[brw(pad_before = 0x8, pad_after = 0xC)]
    pub v_table_fixups: Rva,
}

#[derive(Debug)]
pub struct ClrExe {
    pub pe: Pe,
    pub cli_header: CliHeader,
    pub metadata: MetadataRoot,
    pub metadata_section_idx: usize,
}

impl ClrExe {
    pub fn new(pe: Pe) -> anyhow::Result<Self> {
        let cli_header_section = pe.data_dirs.cli_header.ptr.find_containing(&pe.sections);
        let Some(cli_header) = cli_header_section
            .map(|section| {
                pe.data_dirs.cli_header.parse_options::<CliHeader>(
                    section,
                    binrw::Endian::Little,
                    (),
                )
            })
            .transpose()?
            .flatten()
        else {
            return Err(anyhow!("PE is not CLR-capable"));
        };

        println!("{:#?}", cli_header);
        let metadata_section_idx = pe
            .sections
            .iter()
            .take_while(|section| !cli_header.metadata.ptr.is_contained_in(section))
            .count();
        {
            let a = pe.sections[metadata_section_idx].body_offset.unwrap();
            let b = cli_header.metadata.ptr.0;
            let c = 0x2000;
            println!(
                "metadata offset: {a:#x} + {b:#x} - {c:#x} = {:#x}",
                a + b - c,
            );
        }
        let Some(metadata) = cli_header
            .metadata
            .parse_le::<MetadataRoot>(&pe.sections[metadata_section_idx])?
        else {
            return Err(anyhow!("metadata section not present"));
        };

        Ok(Self {
            pe,
            cli_header,
            metadata,
            metadata_section_idx,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use binrw::BinRead;

    use crate::{ClrExe, Pe};

    #[test]
    fn test_pe() -> anyhow::Result<()> {
        let file = fs::read("/home/seth/projects/cshp/disco/il2cppbridge/lib/XNode.dll")?;
        let mut cursor = io::Cursor::new(file);

        let pe = Pe::read_le(&mut cursor)?;
        let clr = ClrExe::new(pe)?;
        println!("{clr:#?}");

        panic!("rn");
    }
}
