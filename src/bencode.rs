use nom::{
	named,
	char,
	character::complete::digit1,
	alt,
	opt,
	map,
	map_res,
	pair,
	take,
	fold_many0,
	many0,
	do_parse,
	preceded,
	recognize,
	delimited,
	terminated,
};

use std::collections::BTreeMap;
use std::convert::From;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
	ParseIncomplete(nom::Needed),
	ParseError(nom::error::ErrorKind),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Error::ParseIncomplete(nom::Needed::Size(v)) => write!(f, "bencode parse requires {} bytes", v),
			Error::ParseIncomplete(nom::Needed::Unknown) => write!(f, "bencode parse requires more data"),
			Error::ParseError(v) => write!(f, "bencode parse error: {:?}", v),
		}
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		None
	}
}

pub type List = Vec<Value>;
pub type Dict = BTreeMap<String, Value>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
	Invalid(Error),
	Int(i64),
	Bytes(Vec<u8>),
	List(List),
	Dict(Dict),
}

impl From<&[u8]> for Value {
	fn from(value: &[u8]) -> Self {
		match bval(value) {
			Ok((_, v)) => v,
			Err(e) => match e {
				nom::Err::Incomplete(needed) => Self::Invalid(Error::ParseIncomplete(needed)),
				nom::Err::Error(e) => Self::Invalid(Error::ParseError(e.code)),
				nom::Err::Failure(e) => Self::Invalid(Error::ParseError(e.code)),
			},
		}
	}
}

impl From<&Value> for Vec<u8> {
	fn from(value: &Value) -> Self {
		let mut output = Vec::new();
		match value {
			Value::Invalid(_) => {},
			Value::Int(v) => {
				output.push(b'i');
				output.extend_from_slice(v.to_string().as_bytes());
				output.push(b'e');
			},
			Value::Bytes(v) => {
				output.extend_from_slice(v.len().to_string().as_bytes());
				output.push(b':');
				output.extend_from_slice(v);
			},
			Value::List(v) => {
				output.push(b'l');
				for item in v {
					output.append(&mut item.into());
				}
				output.push(b'e');
			},
			Value::Dict(v) => {
				output.push(b'd');
				for (key, item) in v {
					output.extend_from_slice(key.len().to_string().as_bytes());
					output.push(b':');
					output.extend_from_slice(key.as_bytes());
					output.append(&mut item.into());
				}
				output.push(b'e');
			},
		};
		output
	}
}

fn to_number<T: FromStr<Err = std::num::ParseIntError>>(input: &[u8]) -> std::io::Result<T> {
	let input_str = String::from_utf8_lossy(input);
	let input_num = input_str.parse::<T>().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
	Ok(input_num)
}

// create parsers for all data types
named!(bint<i64>, preceded!(char!('i'), terminated!(map_res!(recognize!(pair!(opt!(char!('-')), digit1)), to_number::<i64>), char!('e'))));
named!(bbytes<Vec<u8>>, do_parse!(length: map_res!(terminated!(digit1, char!(':')), to_number::<usize>) >> data: take!(length) >> (data.to_vec())));
named!(bstr<String>, map_res!(bbytes, String::from_utf8));
named!(blist<List>, delimited!(char!('l'), many0!(bval), char!('e')));
named!(bdict<Dict>, delimited!(char!('d'), fold_many0!(pair!(bstr, bval), Dict::new(), |mut map: Dict, (k,v)| { map.insert(k,v); map }), char!('e')));

// map parsers to enum
named!(bintval<Value>, map!(bint, Value::Int));
named!(bbytesval<Value>, map!(bbytes, Value::Bytes));
named!(blistval<Value>, map!(blist, Value::List));
named!(bdictval<Value>, map!(bdict, Value::Dict));

// create a single parser for any data type
named!(bval<Value>, alt!(bintval | bbytesval | blistval | bdictval));