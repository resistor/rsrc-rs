use winnow::binary::u16;
use winnow::binary::u24;
use winnow::binary::u32;
use winnow::binary::u8;
use winnow::binary::Endianness;
use winnow::multi::length_count;
use winnow::multi::length_data;
use winnow::combinator::count;
use winnow::token::take;
use winnow::IResult;
use winnow::Parser;
use bitflags::bitflags;
use encoding::{Encoding, DecoderTrap};
use encoding::all::MAC_ROMAN;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct ResourceForkAttributes: u16 {
        const MAP_READ_ONLY = 128;
        const MAP_COMPACT = 64;
        const MAP_CHANGED = 32;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct ResourceAttributes: u8 {
        const SYSHEAP = 64;
        const PURGEABLE = 32;
        const LOCKED = 16;
        const PROTECTED = 8;
        const PRELOAD = 4;
        const CHANGED = 1;
    }
}

#[derive(Debug)]
pub struct ResourceReference<'a> {
    id: u16,
    attributes: ResourceAttributes,
    name: Option<String>,
    data: &'a [u8],
}

#[derive(Debug)]
struct ResourceType<'a> {
    name: String,
    resources: Vec<ResourceReference<'a>>,
}


#[derive(Debug)]
pub struct ResourceFork<'a> {
    attributes: ResourceForkAttributes,
    resources: Vec<ResourceType<'a>>,
}

fn rsrc_reference_parser<'a>(
    rsrc_name_list: &'a [u8],
    rsrc_data: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], ResourceReference<'a>> {
    |input: &'a [u8]| {
        let (rest, id) = u16(Endianness::Big).parse_next(input)?;
        let (rest, name_offset) = u16(Endianness::Big).parse_next(rest)?;
        let (rest, attributes) = u8(rest)?;
        let (rest, data_offset) = u24(Endianness::Big).parse_next(rest)?;
        let rest = &rest[4..];

        let name = if name_offset != 0xFFFF {
            let name_rest = &rsrc_name_list[name_offset as usize..];
            let (_, name_bytes) = length_data(u8).parse_next(name_rest)?;
            MAC_ROMAN.decode(name_bytes, DecoderTrap::Strict).ok()
        } else {
            None
        };

        let data_rest = &rsrc_data[data_offset as usize..];
        let (_, data) = length_data(u32(Endianness::Big)).parse_next(data_rest)?;

        Ok((
            rest,
            ResourceReference {
                id,
                attributes: ResourceAttributes::from_bits_retain(attributes),
                name,
                data,
            },
        ))
}
}

fn rsrc_type_parser<'a>(rsrc_name_list: &'a [u8], rsrc_data: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<ResourceType<'a>>> {
    |input: &'a [u8]| {
        let v: (_, Vec<_>) = length_count(
            u16(Endianness::Big),
            (take(4usize), u16(Endianness::Big), u16(Endianness::Big)),
        )
        .parse_next(input)?;

        let name_vec =
            v.1.into_iter()
                .map(|t| {
                    let name = MAC_ROMAN.decode(t.0, DecoderTrap::Strict).unwrap();
                    let lo = t.2 as usize;
                    let hi = lo + 12 * (t.1 as usize);
                    let reference = &input[lo..hi];
                    let resources = count(rsrc_reference_parser(rsrc_name_list, rsrc_data), t.1 as usize).parse_next(reference).unwrap().1;
                    ResourceType { name, resources}
                })
                .collect();

        Ok((v.0, name_vec))
    }
}

fn rsrc_map_parser<'a>(
    rsrc_map: &'a [u8],
    rsrc_data: &'a [u8],
) -> IResult<&'a [u8], ResourceFork<'a>> {
    let rest = &rsrc_map[22..];
    let (rest, rsrc_fork_attr) = u16(Endianness::Big).parse_next(rest)?;
    let (rest, rsrc_type_list_offset) = u16(Endianness::Big).parse_next(rest)?;
    assert_eq!(rsrc_type_list_offset, 28);

    let (_, rsrc_name_list_offset) = u16(Endianness::Big).parse_next(rest)?;

    let rsrc_name_list = &rsrc_map[rsrc_name_list_offset as usize..];
    let rsrc_type_list = &rsrc_map[28..];
    let (_, rsrc_types) = rsrc_type_parser(rsrc_name_list, rsrc_data).parse_next(rsrc_type_list)?;

    Ok((
        rest,
        ResourceFork {
            attributes: ResourceForkAttributes::from_bits_retain(rsrc_fork_attr),
            resources: rsrc_types,
        },
    ))
}

pub fn rsrc_parser<'a>(input: &'a [u8]) -> IResult<&'a [u8], ResourceFork<'a>> {
    let header = &input[0..16];
    let (header, rsrc_data_offset) = u32(Endianness::Big).parse_next(header)?;
    let (header, rsrc_map_offset) = u32(Endianness::Big).parse_next(header)?;
    let (header, rsrc_data_length) = u32(Endianness::Big).parse_next(header)?;
    let (_, rsrc_map_length) = u32(Endianness::Big).parse_next(header)?;

    let rsrc_data_lo: usize = rsrc_data_offset as usize;
    let rsrc_data_hi: usize = rsrc_data_lo + (rsrc_data_length as usize);
    let rsrc_map_lo: usize = rsrc_map_offset as usize;
    let rsrc_map_hi: usize = rsrc_map_lo + (rsrc_map_length as usize);

    let resource_data = &input[rsrc_data_lo..rsrc_data_hi];
    let resource_map = &input[rsrc_map_lo..rsrc_map_hi];

    let (_, resource) = rsrc_map_parser(resource_map, resource_data)?;

    Ok((&input[rsrc_map_hi..], resource))
}

#[cfg(test)]
mod test {
    use crate::rsrc_parser;

    #[test]
    fn test_number_resource_types() {
        let buffer = include_bytes!("../sample.rsrc");
        let (_, resources) = rsrc_parser(buffer).unwrap();

        assert_eq!(resources.resources.len(), 2);
    }

    #[test]
    fn test_number_of_entries_per_type() {
        let buffer = include_bytes!("../sample.rsrc");
        let (_, resources) = rsrc_parser(buffer).unwrap();

        assert_eq!(resources.resources[0].resources.len(), 2);
        assert_eq!(resources.resources[1].resources.len(), 2);
    }
}
