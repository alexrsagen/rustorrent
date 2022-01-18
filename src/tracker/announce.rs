use crate::bencode;
use crate::peer::PeerInfo;
use crate::error::Error;

use std::convert::{TryFrom, TryInto};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Announce {
	pub warning_message: Option<String>,
	pub interval: Duration,
	pub min_interval: Option<Duration>,
	pub tracker_id: Option<String>,
	pub complete: i64, // seeders
	pub incomplete: i64, // leechers
	pub peers: Vec<PeerInfo>,
}

impl TryFrom<bencode::Dict> for Announce {
	type Error = Error;
	fn try_from(mut dict: bencode::Dict) -> Result<Self, Self::Error> {
		let mut warning_message: Option<String> = None;
		let interval: Duration;
		let mut min_interval: Option<Duration> = None;
		let mut tracker_id: Option<String> = None;
		let complete: i64;
		let incomplete: i64;
		let peers: Vec<PeerInfo>;

		if let Some(bencode::Value::Bytes(warning_message_v)) = dict.remove("warning message") {
			if let Ok(warning_message_str) = String::from_utf8(warning_message_v) {
				warning_message = Some(warning_message_str);
			}
		}
		if let Some(bencode::Value::Int(interval_v)) = dict.remove("interval") {
			interval = Duration::from_secs(interval_v as u64);
		} else {
			return Err(Error::ValueTypeMissingOrInvalid("interval".into()));
		}
		if let Some(bencode::Value::Int(min_interval_v)) = dict.remove("min interval") {
			min_interval = Some(Duration::from_secs(min_interval_v as u64));
		}
		if let Some(bencode::Value::Bytes(tracker_id_v)) = dict.remove("tracker id") {
			if let Ok(tracker_id_str) = String::from_utf8(tracker_id_v) {
				tracker_id = Some(tracker_id_str);
			}
		}
		if let Some(bencode::Value::Int(complete_v)) = dict.remove("complete") {
			complete = complete_v;
		} else {
			complete = -1;
		}
		if let Some(bencode::Value::Int(incomplete_v)) = dict.remove("incomplete") {
			incomplete = incomplete_v;
		} else {
			incomplete = -1;
		}
		if let Some(peers_v) = dict.remove("peers") {
			peers = peers_v.try_into()?;
		} else {
			return Err(Error::ValueTypeMissingOrInvalid("peers".into()));
		}

		Ok(Self {
			warning_message,
			interval,
			min_interval,
			tracker_id,
			complete,
			incomplete,
			peers,
		})
	}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AnnounceResponse {
	Failure(String),
	Success(Announce),
}

impl TryFrom<bencode::Dict> for AnnounceResponse {
	type Error = Error;
	fn try_from(mut dict: bencode::Dict) -> Result<Self, Self::Error> {
		if let Some(bencode::Value::Bytes(failure_reason)) = dict.remove("failure reason") {
			return Ok(AnnounceResponse::Failure(String::from_utf8(failure_reason)?));
		}
		Ok(AnnounceResponse::Success(dict.try_into()?))
	}
}

impl TryFrom<bencode::Value> for AnnounceResponse {
	type Error = Error;
	fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
		match value {
			bencode::Value::Dict(dict) => dict.try_into(),
			bencode::Value::Invalid(e) => Err(Error::Bencode(e)),
			_ => Err(Error::ValueTypeMissingOrInvalid("announce".into())),
		}
	}
}

impl TryFrom<&[u8]> for AnnounceResponse {
	type Error = Error;
	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		bencode::Value::from(value).try_into()
	}
}

impl TryFrom<Vec<u8>> for AnnounceResponse {
	type Error = Error;
	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		(&value as &[u8]).try_into()
	}
}

impl From<&AnnounceResponse> for bencode::Dict {
	fn from(value: &AnnounceResponse) -> Self {
		let mut dict = bencode::Dict::new();
		match value {
			AnnounceResponse::Failure(reason) => {
				dict.insert("failure reason".into(), bencode::Value::Bytes(reason.as_bytes().to_vec()));
			},
			AnnounceResponse::Success(announce) => {
				if let Some(warning_message) = &announce.warning_message {
					dict.insert("warning message".into(), bencode::Value::Bytes(warning_message.as_bytes().to_vec()));
				}
				dict.insert("interval".into(), bencode::Value::Int(announce.interval.as_secs() as i64));
				if let Some(min_interval) = announce.min_interval {
					dict.insert("min interval".into(), bencode::Value::Int(min_interval.as_secs() as i64));
				}
				if let Some(tracker_id) = &announce.tracker_id {
					dict.insert("tracker id".into(), bencode::Value::Bytes(tracker_id.as_bytes().to_vec()));
				}
				dict.insert("complete".into(), bencode::Value::Int(announce.complete));
				dict.insert("incomplete".into(), bencode::Value::Int(announce.incomplete));
				dict.insert("peers".into(), (&announce.peers).into());
			},
		};
		dict
	}
}

impl From<&AnnounceResponse> for bencode::Value {
	fn from(value: &AnnounceResponse) -> Self {
		bencode::Value::Dict(value.into())
	}
}