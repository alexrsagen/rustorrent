use crate::error::Error;

use std::convert::From;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::string::ToString;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct PortRange {
    pub start: u16,
    pub end: Option<u16>,
}

impl FromStr for PortRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        if parts.is_empty() {
            return Err(Error::NoData);
        }

        let start = match parts[0].parse() {
            Ok(v) => v,
            Err(e) => return Err(Error::PortInvalid(e)),
        };

        let end = if parts.len() > 1 {
            match parts[1].parse() {
                Ok(v) => Some(v),
                Err(e) => return Err(Error::PortInvalid(e)),
            }
        } else {
            None
        };

        Ok(Self { start, end })
    }
}

impl ToString for PortRange {
    fn to_string(&self) -> String {
        if let Some(end) = self.end {
            self.start.to_string() + "-" + &end.to_string()
        } else {
            self.start.to_string()
        }
    }
}

impl From<PortRange> for RangeInclusive<u16> {
    fn from(range: PortRange) -> Self {
        if let Some(end) = range.end {
            range.start..=end
        } else {
            range.start..=range.start
        }
    }
}

impl From<RangeInclusive<u16>> for PortRange {
    fn from(range: RangeInclusive<u16>) -> Self {
        Self {
            start: *range.start(),
            end: Some(*range.end()),
        }
    }
}
