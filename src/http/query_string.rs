use std::borrow::Borrow;

use form_urlencoded::byte_serialize;
use percent_encoding::{percent_decode, PercentDecode};

#[inline]
pub fn decode(input: &[u8]) -> Parse<'_> {
    Parse { input }
}

#[derive(Copy, Clone)]
pub struct Parse<'a> {
    input: &'a [u8],
}

impl<'a> Iterator for Parse<'a> {
    type Item = (PercentDecode<'a>, PercentDecode<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.input.is_empty() {
                return None;
            }
            let mut split2 = self.input.splitn(2, |&b| b == b'&');
            let sequence = split2.next().unwrap();
            self.input = split2.next().unwrap_or(&[][..]);
            if sequence.is_empty() {
                continue;
            }
            let mut split2 = sequence.splitn(2, |&b| b == b'=');
            let name = split2.next().unwrap();
            let value = split2.next().unwrap_or(&[][..]);
            return Some((percent_decode(name), percent_decode(value)));
        }
    }
}

pub fn encode<I, K, V>(pairs: I) -> String
where
    I: IntoIterator,
    I::Item: Borrow<(K, V)>,
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut query = String::new();
    let iter = pairs.into_iter();
    for pair in iter {
        let &(ref k, ref v) = pair.borrow();
        write_pair(&mut query, k.as_ref(), v.as_ref());
    }
    query
}

pub fn write_pair(query: &mut String, key: &[u8], value: &[u8]) {
    if !query.is_empty() {
        query.push('&');
    }
    query.extend(byte_serialize(key));
    query.push('=');
    query.extend(byte_serialize(value));
}
