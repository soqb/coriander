use std::io::{Read, Seek, Write};

use binrw::{BinRead, BinResult, BinWrite, Endian};

macro_rules! parse_args {
    ($fn:expr; $args:expr) => {
        move |reader, endian, _: ()| $fn(reader, endian, $args)
    };
}

macro_rules! write_args {
    ($fn:expr; $args:expr) => {
        move |token, writer, endian, _: ()| $fn(token, writer, endian, $args)
    };
}

pub trait BinRemote<T> {
    fn wrap(value: &T) -> &Self;
    fn unwrap(self) -> T;

    fn read_opt<S: Read + Seek>(
        reader: &mut S,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Option<T>>
    where
        Self: BinReadOptional,
    {
        let meta = Self::read_optional(reader, endian, args)?;
        Ok(meta.map(Self::unwrap))
    }

    fn write_opt<S: Write + Seek>(
        value: &Option<T>,
        writer: &mut S,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()>
    where
        Self: BinWriteOptional,
    {
        match value {
            Some(t) => Self::wrap(t).write_some(writer, endian, args),
            None => Self::write_none(writer, endian, args),
        }
    }

    fn read_unwrap<S: Read + Seek>(
        writer: &mut S,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<T>
    where
        Self: BinRead,
    {
        Self::read_options(writer, endian, args).map(Self::unwrap)
    }

    fn write_wrap<S: Write + Seek>(
        value: &T,
        writer: &mut S,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()>
    where
        Self: BinWrite,
    {
        Self::wrap(value).write_options(writer, endian, args)
    }
}

impl<T> BinRemote<T> for T {
    fn wrap(value: &T) -> &T {
        value
    }
    fn unwrap(self) -> T {
        self
    }
}

macro_rules! binrw_remote {
    (
        $(#[$attr:meta])*
        $({ $($tt:tt)* })? $vis:vis $wrapper:ident$(<$($a:ty),* $(,)?>)? <- $inner:ty;
    ) => {
        #[derive(ref_cast::RefCastCustom)]
        $(#[$attr])*
        #[repr(transparent)]
        $vis struct $wrapper$(< $($tt)* >)?(pub $inner);

        impl$(< $($tt)* >)? $crate::utils::BinRemote<$inner> for $wrapper$(< $($a)* >)? {
            #[ref_cast::ref_cast_custom]
            fn wrap(value: &$inner) -> &Self;
            fn unwrap(self) -> $inner {
                self.0
            }
        }
    };
}

binrw_remote! {
    pub ZString <- String;
}

// `BinRead` and `BinWrite` impls modified slightly from `binrw::NullString`.
impl BinRead for ZString {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        (): Self::Args<'_>,
    ) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        let mut values = vec![];

        loop {
            let val = <u8>::read_options(reader, endian, ())?;
            if val == 0 {
                return String::from_utf8(values)
                    .or_else(|e| {
                        Err(binrw::Error::Custom {
                            pos,
                            err: Box::new(e),
                        })
                    })
                    .map(Self);
            }
            values.push(val);
        }
    }
}

impl BinWrite for ZString {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.0.as_bytes().write_options(writer, endian, args)?;
        0u8.write_options(writer, endian, args)?;

        Ok(())
    }
}

impl From<ZString> for String {
    fn from(value: ZString) -> Self {
        value.0
    }
}

#[macro_export]
macro_rules! bitflags_brw {
    ($ty:ty : $inner:ty) => {
        impl binrw::BinRead for $ty {
            type Args<'a> = ();

            fn read_options<R: std::io::Read + std::io::Seek>(
                reader: &mut R,
                endian: binrw::Endian,
                _: (),
            ) -> binrw::BinResult<Self> {
                <$inner as binrw::BinRead>::read_options(reader, endian, ())
                    .map(Self::from_bits_truncate)
            }
        }

        impl binrw::BinWrite for $ty {
            type Args<'a> = ();

            fn write_options<W: std::io::Write + std::io::Seek>(
                &self,
                writer: &mut W,
                endian: binrw::Endian,
                _: (),
            ) -> binrw::BinResult<()> {
                <$inner as binrw::BinWrite>::write_options(&self.bits(), writer, endian, ())
            }
        }
    };
}

pub trait BinReadOptional: Sized {
    type Args<'a>;
    fn read_optional<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Option<Self>>;
}

pub trait BinWriteOptional: Sized {
    type Args<'a>;
    fn write_some<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()>;
    fn write_none<W: Write + Seek>(
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()>;

    fn write_optional<W: Write + Seek>(
        value: &Option<Self>,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        match value.as_ref() {
            Some(value) => value.write_some(writer, endian, args),
            None => Self::write_none(writer, endian, args),
        }
    }
}

macro_rules! impl_brw_optional {
    ($({ $($tt:tt)* })? for $ty:ty) => {
        impl $(<$($tt)*>)? binrw::BinRead for $ty
        where $ty: BinReadOptional {
            type Args<'a> = <$ty as BinReadOptional>::Args<'a>;
            fn read_options<R: std::io::Read + std::io::Seek>(
                reader: &mut R,
                endian: binrw::Endian,
                args: Self::Args<'_>,
            ) -> binrw::BinResult<Self> {
                Self::read_optional(reader, endian, args)?
                    .ok_or(())
                    .or_else(|_| Err(binrw::Error::Custom {
                        pos: reader.stream_position()?,
                        err: Box::new("unexpected null found"),
                    }))
            }
        }

        impl $(<$($tt)*>)? binrw::BinWrite for $ty
        where $ty: BinWriteOptional {
            type Args<'a> = <$ty as BinWriteOptional>::Args<'a>;
            fn write_options<W: std::io::Write + std::io::Seek>(
                &self,
                reader: &mut W,
                endian: binrw::Endian,
                args: Self::Args<'_>,
            ) -> binrw::BinResult<()> {
                self.write_some(reader, endian, args)
            }
        }
    };
}
