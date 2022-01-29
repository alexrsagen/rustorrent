use std::iter::Chain;
use std::slice::Iter;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub struct SkipWrapVec<T> {
    buf: Vec<T>,
    start: AtomicUsize,
}

impl<T> SkipWrapVec<T> {
    pub fn set_first_item(&self, n: usize) {
        self.start.store(n, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

impl<T> From<Vec<T>> for SkipWrapVec<T> {
    fn from(buf: Vec<T>) -> Self {
        Self {
            buf,
            start: AtomicUsize::new(0),
        }
    }
}

impl<'a, T> IntoIterator for &'a SkipWrapVec<T> {
    type Item = &'a T;
    type IntoIter = Chain<Iter<'a, T>, Iter<'a, T>>;

    fn into_iter(self) -> Self::IntoIter {
        let start = self.start.load(Ordering::Relaxed);
        let (first, second) = self.buf.split_at(start);
        second.iter().chain(first.iter())
    }
}
