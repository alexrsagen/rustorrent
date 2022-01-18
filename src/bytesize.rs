use std::fmt;
use std::marker::Sized;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum ByteExponent {
    Byte,
    Kilo,
    Mega,
    Giga,
    Tera,
    Peta,
    Exa,
    Zetta,
    Yotta,
}

impl ByteExponent {
    fn value(&self) -> i32 {
        match self {
            Self::Byte => 0,
            Self::Kilo => 1,
            Self::Mega => 2,
            Self::Giga => 3,
            Self::Tera => 4,
            Self::Peta => 5,
            Self::Exa => 6,
            Self::Zetta => 7,
            Self::Yotta => 8,
        }
    }

    fn max(exp: i32) -> Self {
        let exp = exp.abs();
        if exp >= Self::Yotta.value() {
            Self::Yotta
        } else if exp >= Self::Zetta.value() {
            Self::Zetta
        } else if exp >= Self::Exa.value() {
            Self::Exa
        } else if exp >= Self::Peta.value() {
            Self::Peta
        } else if exp >= Self::Tera.value() {
            Self::Tera
        } else if exp >= Self::Giga.value() {
            Self::Giga
        } else if exp >= Self::Mega.value() {
            Self::Mega
        } else if exp >= Self::Kilo.value() {
            Self::Kilo
        } else {
            Self::Byte
        }
    }
}

pub trait ByteSize: fmt::Display + Sized {
    fn base() -> f64;
    fn exp(&self) -> ByteExponent;
    fn num(&self) -> f64;
    fn from_num_exp(num: f64, exp: ByteExponent) -> Self;
    fn unit_name(&self) -> &'static str;

    fn max_exp(num: f64) -> ByteExponent {
        ByteExponent::max((num.ln() / Self::base().ln()).floor() as i32)
    }
    fn to_max_exp(&self) -> Self {
        Self::from_bytes(self.to_bytes())
    }
    fn to_bytes(&self) -> usize {
        (self.num() * Self::unit_base(self.exp())).ceil() as usize
    }
    fn from_bytes(num: usize) -> Self {
        let num = num as f64;
        let exp = Self::max_exp(num);
        Self::from_num_exp(num / Self::unit_base(exp), exp)
    }
    fn unit_base(exp: ByteExponent) -> f64 {
        Self::base().powi(exp.value())
    }
    fn default_fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.num().fract() == 0.0 {
            write!(f, "{:.0} {}", self.num(), self.unit_name())
        } else {
            write!(f, "{:.2} {}", self.num(), self.unit_name())
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct BytesBase2 {
    num: f64,
    exp: ByteExponent,
}

impl ByteSize for BytesBase2 {
    fn base() -> f64 {
        1024.0
    }
    fn exp(&self) -> ByteExponent {
        self.exp
    }
    fn num(&self) -> f64 {
        self.num
    }
    fn from_num_exp(num: f64, exp: ByteExponent) -> Self {
        Self { num, exp }
    }
    fn unit_name(&self) -> &'static str {
        match self.exp {
            ByteExponent::Byte => "B",
            ByteExponent::Kilo => "KiB",
            ByteExponent::Mega => "MiB",
            ByteExponent::Giga => "GiB",
            ByteExponent::Tera => "TiB",
            ByteExponent::Peta => "PiB",
            ByteExponent::Exa => "EiB",
            ByteExponent::Zetta => "ZiB",
            ByteExponent::Yotta => "YiB",
        }
    }
}

impl fmt::Display for BytesBase2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.default_fmt(f)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct BytesBase10 {
    num: f64,
    exp: ByteExponent,
}

impl ByteSize for BytesBase10 {
    fn base() -> f64 {
        1000.0
    }
    fn exp(&self) -> ByteExponent {
        self.exp
    }
    fn num(&self) -> f64 {
        self.num
    }
    fn from_num_exp(num: f64, exp: ByteExponent) -> Self {
        Self { num, exp }
    }
    fn unit_name(&self) -> &'static str {
        match self.exp {
            ByteExponent::Byte => "B",
            ByteExponent::Kilo => "kB",
            ByteExponent::Mega => "MB",
            ByteExponent::Giga => "GB",
            ByteExponent::Tera => "TB",
            ByteExponent::Peta => "PB",
            ByteExponent::Exa => "EB",
            ByteExponent::Zetta => "ZB",
            ByteExponent::Yotta => "YB",
        }
    }
}

impl fmt::Display for BytesBase10 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.default_fmt(f)
    }
}
