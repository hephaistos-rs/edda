//! Builds git pack files by hand: walks the object graph from a set of
//! "want" object IDs using `gix::Repository`'s plain object lookup, then
//! serializes every reachable object into the pack binary format directly.
//!
//! Deliberately not using `gix-pack`'s `data::output` pipeline — that's
//! built for gitoxide's own multi-threaded tooling (it wants a `Find` trait
//! impl, thread/interrupt configuration, a count→entry→bytes pipeline). This
//! walks the graph and writes bytes directly instead: no delta compression,
//! every object stored whole. Larger on the wire than real git's packs, but
//! a fraction of the surface area to get right, and correctness comes first.

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::Path;

use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use gix::ObjectId;
use gix_object::Kind;

use crate::GitError;

/// Walks every object reachable from `wants` (commits, their trees, and
/// everything those trees reference) and serializes them into a pack.
#[tracing::instrument(name = "git.build_pack", skip_all, err, fields(wants = wants.len()))]
pub fn build_pack(repo: &gix::Repository, wants: &[ObjectId]) -> Result<Vec<u8>, GitError> {
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut queue: VecDeque<ObjectId> = wants.iter().copied().collect();
    let mut objects: Vec<(Kind, Vec<u8>)> = Vec::new();

    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let object = repo
            .find_object(id)
            .map_err(|err| GitError::Git(err.to_string()))?;

        match object.kind {
            Kind::Commit => {
                let commit = gix_object::CommitRef::from_bytes(&object.data, gix_hash::Kind::Sha1)
                    .map_err(|err| GitError::Git(err.to_string()))?;
                queue.push_back(commit.tree());
                queue.extend(commit.parents());
            }
            Kind::Tree => {
                let tree = gix_object::TreeRef::from_bytes(&object.data, gix_hash::Kind::Sha1)
                    .map_err(|err| GitError::Git(err.to_string()))?;
                queue.extend(tree.entries.iter().map(|entry| entry.oid.to_owned()));
            }
            Kind::Blob | Kind::Tag => {}
        }

        objects.push((object.kind, object.data.clone()));
    }

    serialize_pack(&objects)
}

fn serialize_pack(objects: &[(Kind, Vec<u8>)]) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes()); // pack format version
    out.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    for (kind, data) in objects {
        write_pack_object(&mut out, *kind, data)?;
    }

    // Pack files end with a SHA-1 checksum of everything written so far.
    let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
    hasher.update(&out);
    let checksum = hasher
        .try_finalize()
        .map_err(|err| GitError::Git(err.to_string()))?;
    out.extend_from_slice(checksum.as_slice());

    Ok(out)
}

fn pack_type_code(kind: Kind) -> u8 {
    match kind {
        Kind::Commit => 1,
        Kind::Tree => 2,
        Kind::Blob => 3,
        Kind::Tag => 4,
    }
}

/// One pack object: a variable-length header (type + uncompressed size,
/// 4 bits in the first byte then 7 bits per continuation byte, high bit as
/// the continuation flag) followed by the object's zlib-deflated raw bytes.
fn write_pack_object(out: &mut Vec<u8>, kind: Kind, data: &[u8]) -> Result<(), GitError> {
    let type_code = pack_type_code(kind);
    let mut size = data.len();

    let mut first = (type_code << 4) | (size as u8 & 0x0f);
    size >>= 4;
    if size > 0 {
        first |= 0x80;
    }
    out.push(first);

    while size > 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    out.extend_from_slice(&encoder.finish()?);
    Ok(())
}

fn kind_from_code(code: u8) -> Result<Kind, GitError> {
    match code {
        1 => Ok(Kind::Commit),
        2 => Ok(Kind::Tree),
        3 => Ok(Kind::Blob),
        4 => Ok(Kind::Tag),
        other => Err(GitError::Git(format!(
            "unsupported pack object type {other}"
        ))),
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Commit => "commit",
        Kind::Tree => "tree",
        Kind::Blob => "blob",
        Kind::Tag => "tag",
    }
}

/// An object's id is the hash of its loose-object form (`"<type> <size>\0"`
/// header plus raw content) — not stored anywhere, always derived. Needed
/// both to name loose objects on disk and to resolve `REF_DELTA` bases.
fn object_id(kind: Kind, data: &[u8]) -> Result<ObjectId, GitError> {
    let header = format!("{} {}\0", kind_name(kind), data.len());
    let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
    hasher.update(header.as_bytes());
    hasher.update(data);
    hasher
        .try_finalize()
        .map_err(|err| GitError::Git(err.to_string()))
}

/// One fully-resolved object read out of an incoming pack (deltas already
/// applied against their base).
pub struct ParsedObject {
    pub id: ObjectId,
    pub kind: Kind,
    pub data: Vec<u8>,
}

/// Parses an incoming pack — the reverse of `build_pack` and then some: real
/// `git push` clients delta-compress non-trivial pushes by default, so this
/// resolves both delta kinds, not just plain objects. `REF_DELTA` bases may
/// be objects already in the repo from before this push, hence `repo`.
#[tracing::instrument(name = "git.parse_pack", skip_all, err, fields(bytes = data.len()))]
pub fn parse_pack(repo: &gix::Repository, data: &[u8]) -> Result<Vec<ParsedObject>, GitError> {
    if data.len() < 12 || &data[0..4] != b"PACK" {
        return Err(GitError::Git(
            "not a valid pack: missing PACK header".to_string(),
        ));
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(GitError::Git(format!("unsupported pack version {version}")));
    }
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;

    let mut pos = 12;
    // (offset this entry's header started at, id, kind, fully-resolved data)
    let mut resolved: Vec<(usize, ObjectId, Kind, Vec<u8>)> = Vec::with_capacity(count);

    for _ in 0..count {
        let entry_offset = pos;
        let (type_code, size, header_len) = read_object_header(&data[pos..])?;
        pos += header_len;

        let (kind, resolved_data) = match type_code {
            1..=4 => {
                let kind = kind_from_code(type_code)?;
                let (decompressed, consumed) = inflate(&data[pos..], size)?;
                pos += consumed;
                (kind, decompressed)
            }
            6 => {
                // OFS_DELTA: base is `back_offset` bytes earlier in this
                // same pack, named by its own header's starting position.
                let (back_offset, offset_len) = read_offset_delta(&data[pos..])?;
                pos += offset_len;
                let base_offset = entry_offset.checked_sub(back_offset).ok_or_else(|| {
                    GitError::Git("OFS_DELTA offset points before the pack start".to_string())
                })?;
                let (delta, consumed) = inflate(&data[pos..], size)?;
                pos += consumed;

                let (_, _, base_kind, base_data) = resolved
                    .iter()
                    .find(|(offset, ..)| *offset == base_offset)
                    .ok_or_else(|| GitError::Git("OFS_DELTA base not found in pack".to_string()))?;
                (*base_kind, apply_delta(base_data, &delta)?)
            }
            7 => {
                // REF_DELTA: base named directly by its object id, which may
                // be an object earlier in this pack or already in the repo.
                if pos + 20 > data.len() {
                    return Err(GitError::Git("truncated REF_DELTA base id".to_string()));
                }
                let base_bytes: [u8; 20] = data[pos..pos + 20].try_into().unwrap();
                let base_id = ObjectId::from(base_bytes);
                pos += 20;
                let (delta, consumed) = inflate(&data[pos..], size)?;
                pos += consumed;

                let (base_kind, base_data) =
                    match resolved.iter().find(|(_, id, ..)| *id == base_id) {
                        Some((_, _, kind, data)) => (*kind, data.clone()),
                        None => {
                            let object = repo
                                .find_object(base_id)
                                .map_err(|err| GitError::Git(err.to_string()))?;
                            (object.kind, object.data.clone())
                        }
                    };
                (base_kind, apply_delta(&base_data, &delta)?)
            }
            other => {
                return Err(GitError::Git(format!(
                    "unsupported pack entry type {other}"
                )))
            }
        };

        let id = object_id(kind, &resolved_data)?;
        resolved.push((entry_offset, id, kind, resolved_data));
    }

    Ok(resolved
        .into_iter()
        .map(|(_, id, kind, data)| ParsedObject { id, kind, data })
        .collect())
}

/// Reads the variable-length (type, size) header shared by every pack
/// entry, object or delta alike. Returns (type_code, uncompressed size of
/// this entry's own payload, bytes consumed).
fn read_object_header(data: &[u8]) -> Result<(u8, usize, usize), GitError> {
    if data.is_empty() {
        return Err(GitError::Git(
            "truncated pack: expected an object header".to_string(),
        ));
    }
    let mut pos = 0;
    let first = data[pos];
    pos += 1;
    let type_code = (first >> 4) & 0x07;
    let mut size = (first & 0x0f) as usize;
    let mut shift = 4;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            return Err(GitError::Git("truncated pack: object header".to_string()));
        }
        byte = data[pos];
        pos += 1;
        size |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
    }
    Ok((type_code, size, pos))
}

/// `OFS_DELTA`'s back-offset uses its own varint encoding — distinct from
/// the size varint above: each continuation byte adds 1 before shifting in,
/// so every representable offset has exactly one encoding.
fn read_offset_delta(data: &[u8]) -> Result<(usize, usize), GitError> {
    if data.is_empty() {
        return Err(GitError::Git(
            "truncated pack: OFS_DELTA offset".to_string(),
        ));
    }
    let mut pos = 0;
    let mut byte = data[pos];
    pos += 1;
    let mut offset = (byte & 0x7f) as usize;
    while byte & 0x80 != 0 {
        if pos >= data.len() {
            return Err(GitError::Git(
                "truncated pack: OFS_DELTA offset".to_string(),
            ));
        }
        byte = data[pos];
        pos += 1;
        offset += 1;
        offset = (offset << 7) | (byte & 0x7f) as usize;
    }
    Ok((offset, pos))
}

/// Inflates one zlib stream starting at `data[0]`, sized from the pack
/// entry's own header (`expected_size`). Returns the decompressed bytes and
/// how many *input* bytes the stream consumed, so the caller can resume
/// parsing right after it — pack entries carry no explicit compressed-length
/// field, so this is the only way to find the next entry.
fn inflate(data: &[u8], expected_size: usize) -> Result<(Vec<u8>, usize), GitError> {
    let mut decompress = Decompress::new(true);
    let mut output = Vec::with_capacity(expected_size);
    let status = decompress
        .decompress_vec(data, &mut output, FlushDecompress::Finish)
        .map_err(|err| GitError::Git(format!("zlib error: {err}")))?;
    if status != Status::StreamEnd || output.len() != expected_size {
        return Err(GitError::Git(
            "zlib stream did not decode to the expected size".to_string(),
        ));
    }
    Ok((output, decompress.total_in() as usize))
}

/// Applies a git pack delta: a base-size varint, a target-size varint, then
/// a stream of instructions. A high-bit-set byte is a COPY (offset and size
/// into `base`, each of the offset's 4 bytes / size's 3 bytes present only
/// if its own flag bit is set, little-endian); a high-bit-clear nonzero byte
/// is an INSERT of that many literal bytes from the delta stream itself.
fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, GitError> {
    let mut pos = 0;
    let (base_size, consumed) = read_delta_size(delta)?;
    pos += consumed;
    if base_size != base.len() {
        return Err(GitError::Git("delta base size mismatch".to_string()));
    }
    let (target_size, consumed) = read_delta_size(&delta[pos..])?;
    pos += consumed;

    let mut out = Vec::with_capacity(target_size);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;

        if op & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    offset |= (*delta.get(pos).ok_or_else(truncated_delta)? as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    size |= (*delta.get(pos).ok_or_else(truncated_delta)? as usize) << (8 * i);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .ok_or_else(|| GitError::Git("delta copy overflow".to_string()))?;
            let chunk = base
                .get(offset..end)
                .ok_or_else(|| GitError::Git("delta copy out of range".to_string()))?;
            out.extend_from_slice(chunk);
        } else if op != 0 {
            let size = op as usize;
            let chunk = delta.get(pos..pos + size).ok_or_else(truncated_delta)?;
            out.extend_from_slice(chunk);
            pos += size;
        } else {
            return Err(GitError::Git("invalid delta opcode 0".to_string()));
        }
    }

    if out.len() != target_size {
        return Err(GitError::Git("delta result size mismatch".to_string()));
    }
    Ok(out)
}

fn truncated_delta() -> GitError {
    GitError::Git("truncated delta instruction".to_string())
}

fn read_delta_size(data: &[u8]) -> Result<(usize, usize), GitError> {
    let mut pos = 0;
    let mut size = 0usize;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(pos)
            .ok_or_else(|| GitError::Git("truncated delta size".to_string()))?;
        pos += 1;
        size |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((size, pos))
}

/// Writes one object into the repo's loose-object store
/// (`.git/objects/<first 2 hex chars>/<remaining 38>`), matching real git's
/// own layout — chosen over `gix::Repository::write_object` because that
/// wants a structured, typed object rather than the raw type+bytes this
/// module already works in throughout. A no-op if the object already
/// exists, which is the common case for anything the push didn't change.
pub fn write_loose_object(git_dir: &Path, kind: Kind, data: &[u8]) -> Result<ObjectId, GitError> {
    let id = object_id(kind, data)?;
    let hex = id.to_string();
    let (dir_part, file_part) = hex.split_at(2);
    let object_dir = git_dir.join("objects").join(dir_part);
    let object_path = object_dir.join(file_part);

    if object_path.exists() {
        return Ok(id);
    }
    std::fs::create_dir_all(&object_dir)?;

    let header = format!("{} {}\0", kind_name(kind), data.len());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(header.as_bytes())?;
    encoder.write_all(data)?;
    std::fs::write(&object_path, encoder.finish()?)?;

    Ok(id)
}
