use crate::bitfield::Bitfield;
use crate::error::Error;
use crate::peer::proto::{PieceBlock, Request};
use crate::peer::Peer;

use chrono::{DateTime, Utc};
use crossbeam_utils::atomic::AtomicCell;
use futures::StreamExt;
use rand::seq::SliceRandom;
use rand::Rng;
use sha1::{Digest, Sha1};
use tokio::fs;
use tokio::sync::{Mutex, RwLock};

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub fn get_block_count(piece_size: usize, block_size: usize) -> usize {
    (block_size as f64 / piece_size as f64).ceil() as usize
}

pub fn get_block_begin(block_size: usize, block_index: usize) -> usize {
    block_index * block_size
}

pub fn get_block_size(
    piece_size: usize,
    block_size: usize,
    block_index: usize,
) -> Result<usize, Error> {
    let block_count = get_block_count(piece_size, block_size);
    if block_index >= block_count {
        return Err(Error::OutOfRange);
    }
    if block_index == block_count - 1 {
        Ok(block_size - ((block_count * block_size) - piece_size))
    } else {
        Ok(block_size)
    }
}

pub fn get_block_index(
    piece_size: usize,
    block_size: usize,
    begin: usize,
    length: usize,
) -> Result<usize, Error> {
    if begin + length >= piece_size {
        return Err(Error::OutOfRange);
    }
    let block_count = get_block_count(piece_size, block_size);
    let block_index = ((begin as f64 / piece_size as f64) * block_count as f64).floor() as usize;
    if length != get_block_size(piece_size, block_size, block_index)? {
        return Err(Error::OutOfRange);
    }
    if begin != get_block_begin(block_size, block_index) {
        return Err(Error::OutOfRange);
    }
    Ok(block_index)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PickMode {
    /// random first piece mode
    ///
    /// used when we don't know piece availability yet,
    /// to get the first piece as fast as possible.
    Random,

    /// rarest-first mode
    ///
    /// used normally, to ensure no piece becomes less available than others.
    ///
    /// picks a block from the rarest piece.
    /// if there is a partial piece with the highest rarity, picks the partial one.
    /// if there are multiple pieces with the same rarity, picks a random one.
    RarestFirst,

    /// endgame mode
    ///
    /// used when all the remaining blocks are being requested (pipelined),
    /// to get the last piece as fast as possible.
    ///
    /// broadcasts requests for all remaining blocks to all active peers.
    EndGame,
}

#[derive(Debug, Clone)]
pub struct PieceBlockRequest {
    #[allow(unused)]
    picked_at: DateTime<Utc>,
    request: Request,
    peer: Arc<Peer>,
}

impl PartialEq for PieceBlockRequest {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PieceBlockState {
    Open,
    Requested(PieceBlockRequest),
    Finished,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PieceState {
    Empty,
    Partial,
    Complete,
}

pub type Pieces = Vec<Arc<Piece>>;

#[derive(Debug)]
pub struct PieceStore {
    block_size: usize,
    pieces: Pieces,
    pieces_by_priority: RwLock<Vec<Vec<usize>>>,
    pick_mode: AtomicCell<PickMode>,
}

impl PieceStore {
    // TODO: add from_disk method, pointing to a target directory

    pub fn new(piece_count: usize, piece_size: usize, block_size: usize) -> Self {
        // random first piece
        let mut piece_indexes_shuffled: Vec<usize> = (0..piece_count).collect();
        piece_indexes_shuffled.shuffle(&mut rand::thread_rng());

        Self {
            block_size,
            pieces: (0..piece_count)
                .map(|_| Arc::new(Piece::new(piece_size, block_size)))
                .collect(),
            pieces_by_priority: RwLock::new(vec![piece_indexes_shuffled]),
            pick_mode: AtomicCell::new(PickMode::Random),
        }
    }

    // called once we have a complete piece and every time piece availability
    // changes (only if we have a complete piece)
    pub async fn update_priority(&self) {
        let mut pieces_by_priority = self.pieces_by_priority.write().await;
        pieces_by_priority.clear();

        // get pieces as (index, priority)
        let mut piece_priority: Vec<(usize, usize)> = futures::stream::iter(self.pieces.iter())
            .enumerate()
            .filter_map(|(i, piece)| async move {
                if piece.state.load() != PieceState::Complete {
                    Some((i, piece.priority()))
                } else {
                    None
                }
            })
            .collect()
            .await;
        if piece_priority.is_empty() {
            return;
        }
        piece_priority.sort_by(|&(_, a), &(_, b)| a.cmp(&b));

        // group piece indexes into buckets sorted by priority,
        // randomizing order in each bucket (pieces with same priority).
        let mut rng = rand::thread_rng();
        let mut cur_priority = 0;
        let mut cur_group: Vec<usize> = Vec::new();
        for (piece_index, priority) in piece_priority {
            if priority != cur_priority && !cur_group.is_empty() {
                cur_group.shuffle(&mut rng);
                pieces_by_priority.push(cur_group);
                cur_group = Vec::new();
            }
            cur_priority = priority;
            cur_group.push(piece_index);
        }
        if !cur_group.is_empty() {
            cur_group.shuffle(&mut rng);
            pieces_by_priority.push(cur_group);
        }
    }

    // called when a peer bitfield is received (Message::Bitfield) or
    // updated (Message::Have)
    pub async fn increase_availability(&self, bitfield: &Bitfield) -> Result<(), Error> {
        if bitfield.len() != self.pieces.len() {
            return Err(Error::OutOfRange);
        }
        let mut modified = false;
        for piece_index in 0..bitfield.len() {
            if bitfield.get(piece_index) {
                self.pieces[piece_index]
                    .availability
                    .fetch_add(1, Ordering::SeqCst);
                modified = true;
            }
        }
        if modified && self.pick_mode.load() != PickMode::Random {
            self.update_priority().await;
        }
        Ok(())
    }

    // called when a peer disconnects
    pub async fn decrease_availability(&self, bitfield: &Bitfield) -> Result<(), Error> {
        if bitfield.len() != self.pieces.len() {
            return Err(Error::OutOfRange);
        }
        let mut modified = false;
        for piece_index in 0..bitfield.len() {
            if bitfield.get(piece_index) {
                self.pieces[piece_index]
                    .availability
                    .fetch_sub(1, Ordering::SeqCst);
                modified = true;
            }
        }
        if modified && self.pick_mode.load() != PickMode::Random {
            self.update_priority().await;
        }
        Ok(())
    }

    pub async fn write_block(&self, peer: &Peer, block: PieceBlock) -> Result<(), Error> {
        let piece_index = block.index as usize;
        if piece_index >= self.pieces.len() {
            return Err(Error::OutOfRange);
        }
        let piece = &self.pieces[piece_index];
        piece.write_block(peer, block, self.block_size).await?;
        // check for complete (verified) piece
        if piece.state.load() == PieceState::Complete {
            // update pick mode
            self.pick_mode.store(PickMode::RarestFirst);
            // update piece priority
            self.update_priority().await;
        }
        Ok(())
    }

    pub fn as_bitfield(&self) -> Bitfield {
        let mut bitfield = Bitfield::new(self.pieces.len());
        for (i, piece) in self.pieces.iter().enumerate() {
            bitfield.set(i, piece.state.load() == PieceState::Complete);
        }
        bitfield
    }

    pub async fn pick_block(&self, peer: Arc<Peer>) -> Option<PieceBlockRequest> {
        // get peer bitfield
        let peer_bitfield_guard = peer.bitfield.read().await;
        if peer_bitfield_guard.is_none() {
            return None;
        }
        let peer_bitfield = peer_bitfield_guard.as_ref().unwrap();
        let piece_size = peer.torrent.metainfo.info.piece_length;

        // pick first available piece in highest priority bucket.
        // since each bucket has a random order, the piece will be random.
        let pieces_by_priority = self.pieces_by_priority.read().await;
        for bucket in pieces_by_priority.iter() {
            for piece_index in bucket {
                // skip piece if peer does not have it
                if !peer_bitfield.get(*piece_index) {
                    continue;
                }

                // find all the open blocks of the piece
                let mut blocks = self.pieces[*piece_index].blocks.lock().await;
                let open_blocks: Vec<usize> = blocks
                    .iter()
                    .enumerate()
                    .filter(|&(_, block)| *block == PieceBlockState::Open)
                    .map(|(i, _)| i)
                    .collect();
                if open_blocks.is_empty() {
                    continue;
                }

                // get a random open block
                let block_index = rand::thread_rng().gen_range(0..open_blocks.len());
                let block_begin = get_block_begin(self.block_size, block_index);
                let block_size = get_block_size(piece_size, self.block_size, block_index).unwrap();

                // since we have decided on a piece/block,
                // we no longer need a reference to the peer bitfield
                // todo: dropping ref does nothing, we should not drop things manually.
                std::mem::drop(peer_bitfield);
                std::mem::drop(peer_bitfield_guard);

                let req = PieceBlockRequest {
                    picked_at: Utc::now(),
                    request: Request {
                        index: *piece_index as u32,
                        begin: block_begin as u32,
                        length: block_size as u32,
                    },
                    peer,
                };

                // update block state
                blocks[block_index] = PieceBlockState::Requested(req.clone());
                return Some(req);
            }
        }

        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PieceLocation {
    Memory,
    Disk,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PieceData {
    location: PieceLocation,
    buffer: Option<Vec<u8>>,
}

impl Default for PieceData {
    fn default() -> Self {
        Self {
            location: PieceLocation::Memory,
            buffer: Default::default(),
        }
    }
}

impl PieceData {
    pub fn new() -> Self {
        Self {
            location: PieceLocation::Memory,
            buffer: None,
        }
    }

    pub fn with_capacity(size: usize) -> Self {
        Self {
            location: PieceLocation::Memory,
            buffer: Some(vec![0; size]),
        }
    }

    fn buffer_mut(&mut self, size: usize) -> &mut Vec<u8> {
        if self.buffer.is_some() {
            self.buffer.as_mut().unwrap().resize(size, 0);
        } else {
            self.buffer = Some(vec![0; size]);
        }
        self.buffer.as_mut().unwrap()
    }

    pub fn buffer(&self) -> Option<&[u8]> {
        self.buffer.as_deref()
    }

    /// Loads piece data to memory from disk.
    ///
    /// This function makes no guarantees about piece data validity, therefore
    /// verify should always be called after loading from disk.
    pub async fn load(&mut self, path: impl AsRef<Path>) -> Result<Option<&[u8]>, Error> {
        // load from disk, update location
        if self.location == PieceLocation::Memory {
            // already stored in memory
            return Ok(self.buffer());
        }
        self.location = PieceLocation::Memory;
        self.buffer = Some(fs::read(path).await?);
        Ok(self.buffer())
    }

    /// Stores piece data in memory to disk.
    ///
    /// Remember to always verify the piece before storing it to disk.
    pub async fn store(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        if self.location == PieceLocation::Disk {
            // already stored on disk
            return Ok(());
        }
        if let Some(buffer) = &self.buffer {
            // write to disk, update location
            fs::write(path, &buffer).await?;
            self.location = PieceLocation::Disk;
            self.buffer = None;
            return Ok(());
        }
        Err(Error::NoData)
    }

    pub fn verify(&self, hash: &[u8; 20]) -> bool {
        if let Some(buffer) = self.buffer() {
            let buffer_hash: [u8; 20] = Sha1::digest(buffer).into();
            return buffer_hash.eq(hash);
        }
        false
    }
}

#[derive(Debug)]
pub struct Piece {
    data: RwLock<PieceData>,
    state: AtomicCell<PieceState>,
    blocks: Mutex<Vec<PieceBlockState>>,
    availability: AtomicUsize,
}

impl Piece {
    // TODO: add from_disk method, pointing to a target directory

    pub fn new(piece_size: usize, block_size: usize) -> Self {
        Self {
            state: AtomicCell::new(PieceState::Empty),
            data: RwLock::new(PieceData::new()),
            blocks: Mutex::new(vec![
                PieceBlockState::Open;
                get_block_count(piece_size, block_size)
            ]),
            availability: AtomicUsize::new(0),
        }
    }

    pub fn with_capacity(piece_size: usize, block_size: usize) -> Self {
        Self {
            state: AtomicCell::new(PieceState::Empty),
            data: RwLock::new(PieceData::with_capacity(piece_size)),
            blocks: Mutex::new(vec![
                PieceBlockState::Open;
                get_block_count(piece_size, block_size)
            ]),
            availability: AtomicUsize::new(0),
        }
    }

    /// lower retval = higher priority
    pub fn priority(&self) -> usize {
        let not_partial = if self.state.load() == PieceState::Partial {
            0
        } else {
            1
        };
        self.availability.load(Ordering::SeqCst) * 2 + not_partial
    }

    /// retval = a complete piece was assembled and verified
    async fn write_block(
        &self,
        peer: &Peer,
        block: PieceBlock,
        block_size: usize,
    ) -> Result<(), Error> {
        let piece_index = block.index as usize;
        if piece_index >= peer.torrent.metainfo.info.piece_hashes.len() {
            return Err(Error::InvalidPieceBlockMessage {
                piece_index: 0,
                block_index: 0,
            });
        }

        let piece_size = peer.torrent.metainfo.info.piece_length;
        let piece_hash = &peer.torrent.metainfo.info.piece_hashes[piece_index];

        let block_begin = block.begin as usize;
        let block_end = block_begin + block.data.len();
        let block_index = get_block_index(piece_size, block_size, block_begin, block.data.len())
            .map_err(|_| Error::InvalidPieceBlockMessage {
                piece_index,
                block_index: 0,
            })?;

        // get block state
        let mut blocks = self.blocks.lock().await;
        if let PieceBlockState::Requested(req) = &blocks[block_index] {
            if !peer.eq(&req.peer) {
                return Err(Error::UnsolicitedPieceBlockMessage {
                    piece_index,
                    block_index,
                });
            }
            if req.request.index != block.index {
                return Err(Error::InvalidPieceBlockMessage {
                    piece_index,
                    block_index,
                });
            }
            if req.request.begin != block.begin {
                return Err(Error::InvalidPieceBlockMessage {
                    piece_index,
                    block_index,
                });
            }
        } else {
            return Err(Error::UnsolicitedPieceBlockMessage {
                piece_index,
                block_index,
            });
        }

        // write data to buffer
        let mut data = self.data.write().await;
        if data.location != PieceLocation::Memory {
            return Err(Error::NoData);
        }
        data.buffer_mut(piece_size)
            .splice(block_begin..block_end, block.data);

        // update block state
        blocks[block_index] = PieceBlockState::Finished;

        // check if all blocks are finished
        let all_blocks_finished = blocks
            .iter()
            .all(|block| *block == PieceBlockState::Finished);
        if all_blocks_finished {
            // verify piece
            if !data.verify(piece_hash) {
                // reset piece buffer
                for item in data.buffer_mut(piece_size) {
                    *item = 0;
                }
                // reset piece block state
                for block in blocks.iter_mut() {
                    *block = PieceBlockState::Open;
                }
                // reset piece state
                self.state.store(PieceState::Empty);
                // return error
                return Err(Error::PieceHashInvalid { piece_index });
            }
            // update piece state
            self.state.store(PieceState::Complete);
            Ok(())
        } else {
            // update piece state
            self.state.store(PieceState::Partial);
            Ok(())
        }
    }
}
