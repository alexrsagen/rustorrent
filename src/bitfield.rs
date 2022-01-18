use crate::error::Error;
use std::ops::{Bound, RangeBounds};

fn bytes_to_bits(bytes: usize) -> usize {
    bytes * 8
}

fn bits_to_bytes(bits: usize) -> usize {
    (bits as f64 / 8.0f64).ceil() as usize
}

fn bitmask_at(bit: usize) -> u8 {
    0b10000000 >> bit
}

fn bitmask_between(start: usize, end: usize) -> u8 {
    (0xFF << start) & !(0xFE << end)
}

fn bits_to_index_bit(bit: usize) -> (usize, usize) {
    let index = (bit as f64 / 8.0f64).floor() as usize;
    (index, bit - bytes_to_bits(index))
}

fn range_to_inclusive_bounds<R: RangeBounds<usize>>(range: R) -> (usize, usize) {
    let start = match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(x) => *x,
        Bound::Excluded(x) => x + 1,
    };
    let end = match range.end_bound() {
        Bound::Unbounded => 0,
        Bound::Included(x) => *x,
        Bound::Excluded(x) => x - 1,
    };
    (start, end)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Bitfield {
    data: Vec<u8>,
    bits: usize,
}

impl Bitfield {
    pub fn new(bits: usize) -> Self {
        let len = bits_to_bytes(bits);
        Self {
            data: vec![0; len],
            bits,
        }
    }

    pub fn try_from_bytes(data: Vec<u8>, bits: usize) -> Result<Self, Error> {
        if data.len() != bits_to_bytes(bits) {
            return Err(Error::ValueLengthInvalid("bitfield data".into()));
        }
        Ok(Self { data, bits })
    }

    pub fn from_bytes(data: Vec<u8>) -> Self {
        let bits = bytes_to_bits(data.len());
        Self { data, bits }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub fn resize(&mut self, bits: usize) -> &mut Self {
        let len = bits_to_bytes(bits);
        self.data.resize(len, 0);
        self.bits = bits;
        self
    }

    pub fn spare_bits_as_byte(&self) -> u8 {
        let spare_bits = bytes_to_bits(self.data.len()) - self.bits;
        self.data[self.data.len() - 1] << spare_bits
    }

    pub fn get(&self, bit: usize) -> bool {
        let (index, bit) = bits_to_index_bit(bit);
        if index >= self.data.len() {
            return false;
        }
        (self.data[index] & bitmask_at(bit)) >> (7 - bit) == 1
    }

    pub fn set_bit(&mut self, bit: usize) -> &mut Self {
        let (index, bit) = bits_to_index_bit(bit);
        self.data[index] |= bitmask_at(bit);
        self
    }

    pub fn clear_bit(&mut self, bit: usize) -> &mut Self {
        let (index, bit) = bits_to_index_bit(bit);
        self.data[index] &= !bitmask_at(bit);
        self
    }

    pub fn set(&mut self, bit: usize, value: bool) -> &mut Self {
        if value {
            self.set_bit(bit)
        } else {
            self.clear_bit(bit)
        }
    }

    fn range_update<R: RangeBounds<usize>, F: Fn(&mut u8, u8)>(
        &mut self,
        range: R,
        update_block: F,
    ) -> &mut Self {
        let (start_bit, end_bit) = range_to_inclusive_bounds(range);
        let (start_index, start_bit) = bits_to_index_bit(start_bit);
        let (end_index, end_bit) = bits_to_index_bit(end_bit);

        for index in start_index..=end_index {
            let index_start_bit = if index == start_index { start_bit } else { 0 };
            let index_end_bit = if index == end_index { end_bit } else { 7 };
            update_block(
                &mut self.data[index],
                bitmask_between(index_start_bit, index_end_bit),
            );
        }

        self
    }

    fn range_eq<R: RangeBounds<usize>>(&self, range: R, val: u8) -> bool {
        let (start_bit, end_bit) = range_to_inclusive_bounds(range);
        let (start_index, start_bit) = bits_to_index_bit(start_bit);
        let (end_index, end_bit) = bits_to_index_bit(end_bit);

        for index in start_index..=end_index {
            let index_start_bit = if index == start_index { start_bit } else { 0 };
            let index_end_bit = if index == end_index { end_bit } else { 7 };
            let bitmask = bitmask_between(index_start_bit, index_end_bit);
            if self.data[index] & bitmask != val & bitmask {
                return false;
            }
        }

        true
    }

    pub fn set_range<R: RangeBounds<usize>>(&mut self, range: R) -> &mut Self {
        self.range_update(range, |block, bitmask| {
            *block |= bitmask;
        })
    }

    pub fn clear_range<R: RangeBounds<usize>>(&mut self, range: R) -> &mut Self {
        self.range_update(range, |block, bitmask| {
            *block &= !bitmask;
        })
    }

    pub fn is_range_set<R: RangeBounds<usize>>(&self, range: R) -> bool {
        self.range_eq(range, u8::MAX)
    }

    pub fn is_range_clear<R: RangeBounds<usize>>(&self, range: R) -> bool {
        self.range_eq(range, u8::MIN)
    }

    pub fn is_all_set(&self) -> bool {
        self.is_range_set(0..self.bits)
    }

    pub fn is_all_clear(&self) -> bool {
        self.is_range_clear(0..self.bits)
    }

    pub fn except(&self, other: &Self) -> Self {
        if other.bits != self.bits {
            return Self::new(0);
        }
        let mut new = Self::new(self.bits);
        for i in 0..self.data.len() {
            new.data[i] = self.data[i] & !other.data[i];
        }
        new
    }
}
