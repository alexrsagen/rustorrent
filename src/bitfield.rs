use crate::error::Error;

use std::ops::{Bound, RangeBounds};
use std::sync::atomic::{AtomicU8, Ordering};

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

#[derive(Debug)]
pub struct Bitfield {
    data: Vec<AtomicU8>,
    bits: usize,
}

impl Clone for Bitfield {
    fn clone(&self) -> Self {
        Self::try_from_bytes(self.to_vec(), self.bits).unwrap()
    }
}

impl PartialEq for Bitfield {
    fn eq(&self, other: &Self) -> bool {
        if self.bits != other.bits {
            return false;
        }

        let (end_index, end_bit) = bits_to_index_bit(self.bits);

        for index in 0..=end_index {
            let index_end_bit = if index == end_index { end_bit } else { 7 };
            let bitmask = bitmask_between(0, index_end_bit);
            let byte = self.data[index].load(Ordering::SeqCst);
            let other_byte = other.data[index].load(Ordering::SeqCst);
            if byte & bitmask != other_byte & bitmask {
                return false;
            }
        }

        true
    }
}

impl Bitfield {
    pub fn new(bits: usize) -> Self {
        let len = bits_to_bytes(bits);
        Self {
            data: std::iter::repeat_with(|| AtomicU8::new(0))
                .take(len)
                .collect(),
            bits,
        }
    }

    pub fn try_from_bytes(data: Vec<u8>, bits: usize) -> Result<Self, Error> {
        if data.len() != bits_to_bytes(bits) {
            return Err(Error::ValueLengthInvalid("bitfield data".into()));
        }
        Ok(Self::from_bytes_unchecked(data))
    }

    pub fn from_bytes_unchecked(data: Vec<u8>) -> Self {
        let bits = bytes_to_bits(data.len());
        Self {
            data: data.into_iter().map(|byte| AtomicU8::new(byte)).collect(),
            bits,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.data
            .iter()
            .map(|byte| byte.load(Ordering::SeqCst))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub fn resize(&mut self, bits: usize) -> &mut Self {
        let len = bits_to_bytes(bits);
        self.data.resize_with(len, || AtomicU8::new(0));
        self.bits = bits;
        self
    }

    pub fn spare_bits_as_byte(&self) -> u8 {
        let spare_bits = bytes_to_bits(self.data.len()) - self.bits;
        let byte = self.data[self.data.len() - 1].load(Ordering::SeqCst);
        byte << spare_bits
    }

    pub fn get(&self, bit: usize) -> bool {
        let (index, bit) = bits_to_index_bit(bit);
        if index >= self.data.len() {
            return false;
        }
        let byte = self.data[index].load(Ordering::SeqCst);
        (byte & bitmask_at(bit)) >> (7 - bit) == 1
    }

    pub fn set_bit(&self, bit: usize) -> &Self {
        let (index, bit) = bits_to_index_bit(bit);
        self.data[index].fetch_or(bitmask_at(bit), Ordering::SeqCst);
        self
    }

    pub fn clear_bit(&self, bit: usize) -> &Self {
        let (index, bit) = bits_to_index_bit(bit);
        self.data[index].fetch_and(!bitmask_at(bit), Ordering::SeqCst);
        self
    }

    pub fn set(&self, bit: usize, value: bool) -> &Self {
        if value {
            self.set_bit(bit)
        } else {
            self.clear_bit(bit)
        }
    }

    fn range_update<R: RangeBounds<usize>, F: Fn(&AtomicU8, u8)>(
        &self,
        range: R,
        update_block: F,
    ) -> &Self {
        let (start_bit, end_bit) = range_to_inclusive_bounds(range);
        let (start_index, start_bit) = bits_to_index_bit(start_bit);
        let (end_index, end_bit) = bits_to_index_bit(end_bit);

        for index in start_index..=end_index {
            let index_start_bit = if index == start_index { start_bit } else { 0 };
            let index_end_bit = if index == end_index { end_bit } else { 7 };
            update_block(
                &self.data[index],
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
            let byte = self.data[index].load(Ordering::SeqCst);
            if byte & bitmask != val & bitmask {
                return false;
            }
        }

        true
    }

    pub fn set_range<R: RangeBounds<usize>>(&self, range: R) -> &Self {
        self.range_update(range, |block, bitmask| {
            block.fetch_or(bitmask, Ordering::SeqCst);
        })
    }

    pub fn clear_range<R: RangeBounds<usize>>(&self, range: R) -> &Self {
        self.range_update(range, |block, bitmask| {
            block.fetch_and(!bitmask, Ordering::SeqCst);
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
        if self.bits != other.bits {
            return Self::new(0);
        }
        let mut new = Self::new(self.bits);
        for i in 0..self.data.len() {
            let byte = self.data[i].load(Ordering::SeqCst);
            let other_byte = other.data[i].load(Ordering::SeqCst);
            new.data[i] = AtomicU8::new(byte & !other_byte);
        }
        new
    }

    pub fn try_overwrite_with(&self, other: &Self) -> Result<(), Error> {
        if self.bits != other.bits {
            return Err(Error::OutOfRange);
        }
        for i in 0..self.data.len() {
            self.data[i].store(other.data[i].load(Ordering::SeqCst), Ordering::SeqCst);
        }
        Ok(())
    }
}
