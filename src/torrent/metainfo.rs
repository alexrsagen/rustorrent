use crate::bencode;
use crate::bytesize::{ByteSize, BytesBase2};
use crate::error::Error;

use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

pub type InfoHash = [u8; 20];
pub type PieceHash = [u8; 20];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct File {
    pub path: String,
    pub length: usize,

    // hashes (optional)
    pub md5sum: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub ed2k: Option<[u8; 16]>,
    pub tiger: Option<[u8; 24]>,
    pub crc32: Option<u32>,
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({}", self.path, BytesBase2::from_bytes(self.length))?;
        if let Some(md5sum) = self.md5sum {
            write!(f, ", md5: {:x?}", md5sum)?;
        }
        if let Some(sha1) = self.sha1 {
            write!(f, ", sha1: {:x?}", sha1)?;
        }
        if let Some(ed2k) = self.ed2k {
            write!(f, ", ed2k: {:x?}", ed2k)?;
        }
        if let Some(tiger) = self.tiger {
            write!(f, ", tth: {:x?}", tiger)?;
        }
        if let Some(crc32) = self.crc32 {
            write!(f, ", crc32: {:x?}", crc32)?;
        }
        write!(f, ")")
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dir {
    pub name: String,
    pub files: Vec<File>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Files {
    Single(File),
    Multiple(Dir),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Info {
    pub piece_length: usize,
    pub piece_hashes: Vec<PieceHash>,
    pub private: bool,
    pub files: Files,
}

impl Info {
    pub fn total_size(&self) -> usize {
        match &self.files {
            Files::Single(file) => file.length,
            Files::Multiple(dir) => dir.files.iter().map(|file| file.length).sum(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub info: Info,
    pub info_hash: InfoHash,
    pub announce: Vec<Vec<String>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub encoding: Option<String>,
}

impl PartialEq for Metainfo {
    fn eq(&self, other: &Self) -> bool {
        self.info_hash == other.info_hash
    }
}

impl TryFrom<bencode::Dict> for Metainfo {
    type Error = Error;
    fn try_from(mut dict: bencode::Dict) -> Result<Self, Self::Error> {
        Ok(Self {
            info_hash: match dict.get("info") {
                Some(info_value) => {
                    let info_encoded: Vec<u8> = info_value.into();
                    Some(Sha1::digest(&info_encoded).into())
                }
                _ => None
            }.ok_or(Error::ValueTypeMissingOrInvalid("info".into()))?,
            info: match dict.remove("info") {
                Some(bencode::Value::Dict(mut info)) => Some(Info {
                    piece_length: info.remove("piece length").map(|v| match v {
                        bencode::Value::Int(piece_length_v) => Some(piece_length_v as usize),
                        _ => None
                    }).flatten().ok_or(Error::ValueTypeMissingOrInvalid("piece length".into()))?,
                    piece_hashes: info.remove("pieces").map(|v| match v {
                        bencode::Value::Bytes(pieces_v) => Some(pieces_v
                            .chunks_exact(20)
                            .map(|chunk| chunk.try_into().unwrap())
                            .collect()),
                        _ => None
                    }).flatten().ok_or(Error::ValueTypeMissingOrInvalid("pieces".into()))?,
                    private: if let Some(bencode::Value::Int(private_v)) = info.remove("private") {
                        private_v == 1
                    } else {
                        false
                    },
                    files: if let Some(bencode::Value::List(file_list_v)) = info.remove("files") {
                        Files::Multiple(Dir {
                            name: info.remove("file").map(|v| match v {
                                bencode::Value::Bytes(v) => String::from_utf8(v).ok(),
                                _ => None
                            }).flatten().ok_or(Error::ValueTypeMissingOrInvalid("name".into()))?,
                            files: file_list_v
                                .into_iter()
                                .filter_map(|file_v| match file_v {
                                    bencode::Value::Dict(mut file_dict) => Some(File {
                                        path: file_dict.remove("path").map(|v| match v {
                                            bencode::Value::Bytes(v) => String::from_utf8(v).ok(),
                                            _ => None
                                        }).flatten()?,
                                        length: file_dict.remove("length").map(|v| match v {
                                            bencode::Value::Int(v) => Some(v as usize),
                                            _ => None
                                        }).flatten()?,
                                        md5sum: file_dict.remove("md5sum").map(|v| match v {
                                            bencode::Value::Bytes(v) => {
                                                let mut sum = [0u8; 16];
                                                hex::decode_to_slice(v, &mut sum).map(|_| sum).ok()
                                            }
                                            _ => None
                                        }).flatten(),
                                        sha1: file_dict.remove("sha1").map(|v| match v {
                                            bencode::Value::Bytes(v) => {
                                                let sum: Option<[u8; 20]> = v.try_into().ok();
                                                sum
                                            }
                                            _ => None
                                        }).flatten(),
                                        ed2k: file_dict.remove("ed2k").map(|v| match v {
                                            bencode::Value::Bytes(v) => {
                                                let sum: Option<[u8; 16]> = v.try_into().ok();
                                                sum
                                            }
                                            _ => None
                                        }).flatten(),
                                        tiger: file_dict.remove("tiger").map(|v| match v {
                                            bencode::Value::Bytes(v) => {
                                                let sum: Option<[u8; 24]> = v.try_into().ok();
                                                sum
                                            }
                                            _ => None
                                        }).flatten(),
                                        crc32: file_dict.remove("crc32").map(|v| match v {
                                            bencode::Value::Bytes(v) => {
                                                let mut sum = [0u8; 4];
                                                hex::decode_to_slice(v, &mut sum).map(|_| u32::from_be_bytes(sum)).ok()
                                            }
                                            _ => None
                                        }).flatten(),
                                    }),
                                    _ => None
                                })
                                .collect(),
                        })
                    } else {
                        Files::Single(File {
                            path: info.remove("name").map(|v| match v {
                                bencode::Value::Bytes(v) => String::from_utf8(v).ok(),
                                _ => None
                            }).flatten().ok_or(Error::ValueTypeMissingOrInvalid("name".into()))?,
                            length: info.remove("length").map(|v| match v {
                                bencode::Value::Int(v) => Some(v as usize),
                                _ => None
                            }).flatten().ok_or(Error::ValueTypeMissingOrInvalid("length".into()))?,
                            md5sum: info.remove("md5sum").map(|v| match v {
                                bencode::Value::Bytes(v) => {
                                    let mut sum = [0u8; 16];
                                    hex::decode_to_slice(v, &mut sum).map(|_| sum).ok()
                                }
                                _ => None
                            }).flatten(),
                            sha1: info.remove("sha1").map(|v| match v {
                                bencode::Value::Bytes(v) => {
                                    let sum: Option<[u8; 20]> = v.try_into().ok();
                                    sum
                                }
                                _ => None
                            }).flatten(),
                            ed2k: info.remove("ed2k").map(|v| match v {
                                bencode::Value::Bytes(v) => {
                                    let sum: Option<[u8; 16]> = v.try_into().ok();
                                    sum
                                }
                                _ => None
                            }).flatten(),
                            tiger: info.remove("tiger").map(|v| match v {
                                bencode::Value::Bytes(v) => {
                                    let sum: Option<[u8; 24]> = v.try_into().ok();
                                    sum
                                }
                                _ => None
                            }).flatten(),
                            crc32: info.remove("crc32").map(|v| match v {
                                bencode::Value::Bytes(v) => {
                                    let mut sum = [0u8; 4];
                                    hex::decode_to_slice(v, &mut sum).map(|_| u32::from_be_bytes(sum)).ok()
                                }
                                _ => None
                            }).flatten(),
                        })
                    }
                }),
                _ => None
            }.ok_or(Error::ValueTypeMissingOrInvalid("info".into()))?,
            announce: match dict.remove("announce-list") {
                Some(bencode::Value::List(tier_list)) => {
                    let tier_list: Vec<Vec<String>> = tier_list
                        .into_iter()
                        .map(|announce_list_v| {
                            if let bencode::Value::List(announce_list) = announce_list_v {
                                return announce_list
                                    .into_iter()
                                    .map(|announce_v| {
                                        if let bencode::Value::Bytes(announce) = announce_v {
                                            if let Ok(announce_str) = String::from_utf8(announce) {
                                                return announce_str;
                                            }
                                        }
                                        String::new()
                                    })
                                    .filter(|s| !s.is_empty())
                                    .collect();
                            }
                            vec![]
                        })
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !tier_list.is_empty() {
                        Some(tier_list)
                    } else {
                        None
                    }
                }
                _ => None
            }.or(match dict.remove("announce") {
                Some(bencode::Value::Bytes(announce_v)) => String::from_utf8(announce_v).map(|v| vec![vec![v]]).ok(),
                _ => None
            }).ok_or(Error::ValueTypeMissingOrInvalid("announce".into()))?,
            creation_date: match dict.remove("creation date") {
                Some(bencode::Value::Int(creation_date_v)) => Some(DateTime::<Utc>::from(
                    UNIX_EPOCH + Duration::from_secs(creation_date_v as u64),
                )),
                _ => None
            },
            comment: match dict.remove("comment") {
                Some(bencode::Value::Bytes(comment_v)) => String::from_utf8(comment_v).ok(),
                _ => None
            },
            created_by: match dict.remove("created by") {
                Some(bencode::Value::Bytes(created_by_v)) => String::from_utf8(created_by_v).ok(),
                _ => None
            },
            encoding: match dict.remove("encoding") {
                Some(bencode::Value::Bytes(encoding_v)) => String::from_utf8(encoding_v).ok(),
                _ => None
            },
        })
    }
}

impl TryFrom<bencode::Value> for Metainfo {
    type Error = Error;
    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        match value {
            bencode::Value::Dict(dict) => dict.try_into(),
            bencode::Value::Invalid(e) => Err(Error::Bencode(e)),
            _ => Err(Error::ValueTypeMissingOrInvalid("metainfo".into())),
        }
    }
}

impl TryFrom<&[u8]> for Metainfo {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        bencode::Value::from(value).try_into()
    }
}

impl TryFrom<Vec<u8>> for Metainfo {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        (&value as &[u8]).try_into()
    }
}

impl From<&Metainfo> for bencode::Dict {
    fn from(value: &Metainfo) -> Self {
        let mut dict = bencode::Dict::new();
        let mut info = bencode::Dict::new();
        info.insert(
            "piece length".into(),
            bencode::Value::Int(value.info.piece_length as i64),
        );
        let mut pieces = Vec::new();
        for piece_hash in &value.info.piece_hashes {
            pieces.extend_from_slice(piece_hash);
        }
        info.insert("pieces".into(), bencode::Value::Bytes(pieces));
        if value.info.private {
            info.insert("private".into(), bencode::Value::Int(1));
        }

        match &value.info.files {
            Files::Multiple(dir) => {
                info.insert(
                    "name".into(),
                    bencode::Value::Bytes(dir.name.as_bytes().to_vec()),
                );
                info.insert(
                    "files".into(),
                    bencode::Value::List(
                        dir.files
                            .iter()
                            .map(|file| {
                                let mut file_dict = bencode::Dict::new();
                                file_dict.insert(
                                    "path".into(),
                                    bencode::Value::Bytes(file.path.as_bytes().to_vec()),
                                );
                                file_dict.insert(
                                    "length".into(),
                                    bencode::Value::Int(file.length as i64),
                                );
                                if let Some(md5sum) = file.md5sum {
                                    file_dict.insert(
                                        "md5sum".into(),
                                        bencode::Value::Bytes(md5sum.to_vec()),
                                    );
                                }
                                bencode::Value::Dict(file_dict)
                            })
                            .collect(),
                    ),
                );
            }
            Files::Single(file) => {
                info.insert(
                    "name".into(),
                    bencode::Value::Bytes(file.path.as_bytes().to_vec()),
                );
                info.insert("length".into(), bencode::Value::Int(file.length as i64));
                if let Some(md5sum) = file.md5sum {
                    info.insert("md5sum".into(), bencode::Value::Bytes(hex::encode(md5sum).as_bytes().to_vec()));
                }
                if let Some(sha1) = file.sha1 {
                    info.insert("sha1".into(), bencode::Value::Bytes(sha1.to_vec()));
                }
                if let Some(ed2k) = file.ed2k {
                    info.insert("ed2k".into(), bencode::Value::Bytes(ed2k.to_vec()));
                }
                if let Some(tiger) = file.tiger {
                    info.insert("tiger".into(), bencode::Value::Bytes(tiger.to_vec()));
                }
                if let Some(crc32) = file.crc32 {
                    info.insert("crc32".into(), bencode::Value::Bytes(hex::encode(crc32.to_be_bytes()).as_bytes().to_vec()));
                }
            }
        };

        dict.insert("info".into(), bencode::Value::Dict(info));

        dict.insert(
            "announce".into(),
            bencode::Value::Bytes(value.announce[0][0].as_bytes().to_vec()),
        );
        if value.announce.len() > 1 {
            dict.insert(
                "announce-list".into(),
                bencode::Value::List(
                    value
                        .announce
                        .iter()
                        .map(|tier| {
                            bencode::Value::List(
                                tier.iter()
                                    .map(|announce| {
                                        bencode::Value::Bytes(announce.as_bytes().to_vec())
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
            );
        }

        if let Some(creation_date) = value.creation_date {
            dict.insert(
                "creation date".into(),
                bencode::Value::Int(creation_date.timestamp()),
            );
        }

        if let Some(comment) = &value.comment {
            dict.insert(
                "comment".into(),
                bencode::Value::Bytes(comment.as_bytes().to_vec()),
            );
        }

        if let Some(created_by) = &value.created_by {
            dict.insert(
                "created by".into(),
                bencode::Value::Bytes(created_by.as_bytes().to_vec()),
            );
        }

        if let Some(encoding) = &value.encoding {
            dict.insert(
                "encoding".into(),
                bencode::Value::Bytes(encoding.as_bytes().to_vec()),
            );
        }

        dict
    }
}

impl From<&Metainfo> for bencode::Value {
    fn from(value: &Metainfo) -> Self {
        bencode::Value::Dict(value.into())
    }
}
