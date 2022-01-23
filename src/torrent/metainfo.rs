use crate::bencode;
use crate::bytesize::{ByteSize, BytesBase2};
use crate::error::Error;

use chrono::{DateTime, Utc};
use sha1::{Digest, Sha1};

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::time::{Duration, UNIX_EPOCH};

pub type PieceHash = [u8; 20];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct File {
    pub path: String,
    pub length: usize,
    pub md5sum: Option<[u8; 16]>,
}

impl fmt::Display for File {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.md5sum {
            Some(md5sum) => write!(
                f,
                "{} ({}, md5sum: {:x?})",
                self.path,
                BytesBase2::from_bytes(self.length),
                md5sum
            ),
            None => write!(f, "{} ({})", self.path, BytesBase2::from_bytes(self.length)),
        }
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
    pub info_hash: [u8; 20],
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
        // parse info
        let info_hash: [u8; 20];
        let piece_length: usize;
        let piece_hashes: Vec<PieceHash>;
        let private: bool;
        let files: Files;

        if let Some(info_value) = dict.remove("info") {
            let info_encoded: Vec<u8> = (&info_value).into();
            info_hash = Sha1::digest(&info_encoded).into();

            if let bencode::Value::Dict(mut info) = info_value {
                if let Some(bencode::Value::Int(piece_length_v)) = info.remove("piece length") {
                    piece_length = piece_length_v as usize;
                } else {
                    return Err(Error::ValueTypeMissingOrInvalid("piece length".into()));
                }
                if let Some(bencode::Value::Bytes(pieces_v)) = info.remove("pieces") {
                    piece_hashes = pieces_v
                        .chunks_exact(20)
                        .map(|chunk| chunk.try_into().unwrap())
                        .collect();
                } else {
                    return Err(Error::ValueTypeMissingOrInvalid("pieces".into()));
                }
                if let Some(bencode::Value::Int(private_v)) = info.remove("private") {
                    private = private_v == 1;
                } else {
                    private = false;
                }

                // determine "multiple file" or "single file" mode
                if let Some(bencode::Value::List(file_list_v)) = info.remove("files") {
                    let name: String;
                    let file_list: Vec<File>;

                    if let Some(bencode::Value::Bytes(name_v)) = info.remove("name") {
                        name = String::from_utf8(name_v)?;
                    } else {
                        return Err(Error::ValueTypeMissingOrInvalid("name".into()));
                    }

                    file_list = file_list_v
                        .into_iter()
                        .filter_map(|file_v| {
                            if let bencode::Value::Dict(mut file_dict) = file_v {
                                let path: String;
                                let length: usize;
                                let mut md5sum: Option<[u8; 16]> = None;

                                if let Some(bencode::Value::Bytes(path_v)) =
                                    file_dict.remove("path")
                                {
                                    if let Ok(path_str) = String::from_utf8(path_v) {
                                        path = path_str;
                                    } else {
                                        return None;
                                    }
                                } else {
                                    return None;
                                }
                                if let Some(bencode::Value::Int(length_v)) =
                                    file_dict.remove("length")
                                {
                                    length = length_v as usize;
                                } else {
                                    return None;
                                }
                                if let Some(bencode::Value::Bytes(md5sum_v)) =
                                    file_dict.remove("md5sum")
                                {
                                    if let Ok(md5sum_v) = hex::decode(md5sum_v) {
                                        if let Ok(md5sum_arr) = md5sum_v.try_into() {
                                            md5sum = Some(md5sum_arr);
                                        }
                                    }
                                }

                                return Some(File {
                                    path,
                                    length,
                                    md5sum,
                                });
                            }
                            None
                        })
                        .collect();

                    files = Files::Multiple(Dir {
                        name,
                        files: file_list,
                    });
                } else {
                    let path: String;
                    let length: usize;
                    let mut md5sum: Option<[u8; 16]> = None;

                    if let Some(bencode::Value::Bytes(path_vec)) = info.remove("name") {
                        path = String::from_utf8(path_vec)?;
                    } else {
                        return Err(Error::ValueTypeMissingOrInvalid("name".into()));
                    }
                    if let Some(bencode::Value::Int(length_v)) = info.remove("length") {
                        length = length_v as usize;
                    } else {
                        return Err(Error::ValueTypeMissingOrInvalid("length".into()));
                    }
                    if let Some(bencode::Value::Bytes(md5sum_vec)) = info.remove("md5sum") {
                        if let Ok(md5sum_vec) = hex::decode(md5sum_vec) {
                            if let Ok(md5sum_arr) = md5sum_vec.try_into() {
                                md5sum = Some(md5sum_arr);
                            }
                        }
                    }

                    files = Files::Single(File {
                        path,
                        length,
                        md5sum,
                    });
                }
            } else {
                return Err(Error::ValueTypeMissingOrInvalid("into".into()));
            }
        } else {
            return Err(Error::ValueTypeMissingOrInvalid("into".into()));
        }

        // parse metainfo
        let mut announce: Vec<Vec<String>> = Vec::new();
        let mut creation_date: Option<DateTime<Utc>> = None;
        let mut comment: Option<String> = None;
        let mut created_by: Option<String> = None;
        let mut encoding: Option<String> = None;

        // parse announce list / announce
        if let Some(bencode::Value::List(tier_list)) = dict.remove("announce-list") {
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
                announce = tier_list;
            }
        }
        if announce.is_empty() {
            if let Some(bencode::Value::Bytes(announce_v)) = dict.remove("announce") {
                announce = vec![vec![String::from_utf8(announce_v)?]];
            } else {
                return Err(Error::ValueTypeMissingOrInvalid("announce".into()));
            }
        }

        // parse creation date
        if let Some(bencode::Value::Int(creation_date_v)) = dict.remove("creation date") {
            creation_date = Some(DateTime::<Utc>::from(
                UNIX_EPOCH + Duration::from_secs(creation_date_v as u64),
            ));
        }

        // parse comment
        if let Some(bencode::Value::Bytes(comment_v)) = dict.remove("comment") {
            if let Ok(comment_str) = String::from_utf8(comment_v) {
                comment = Some(comment_str);
            }
        }

        // parse created by
        if let Some(bencode::Value::Bytes(created_by_v)) = dict.remove("created by") {
            if let Ok(created_by_str) = String::from_utf8(created_by_v) {
                created_by = Some(created_by_str);
            }
        }

        // parse encoding
        if let Some(bencode::Value::Bytes(encoding_v)) = dict.remove("encoding") {
            if let Ok(encoding_str) = String::from_utf8(encoding_v) {
                encoding = Some(encoding_str);
            }
        }

        Ok(Self {
            info: Info {
                piece_length,
                piece_hashes,
                private,
                files,
            },
            info_hash,
            announce,
            creation_date,
            comment,
            created_by,
            encoding,
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
                    info.insert("md5sum".into(), bencode::Value::Bytes(md5sum.to_vec()));
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
