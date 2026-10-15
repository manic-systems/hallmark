//! The Nix Archive (NAR) format.
//!
//! Three layers are available, lowest first:
//!
//! - raw framing helpers ([`file_nar_header`], [`file_nar_trailer`],
//!   [`write_file_nar`]) and [`copy`], which forwards exactly one well-formed
//!   NAR;
//! - a streaming writer built from handles ([`open`], [`Node`], [`Directory`])
//!   that serializes file bodies straight from any reader, and a streaming
//!   reader driven by a [`Visitor`] ([`read`]);
//! - an in-memory [`Entry`] tree with [`write_nar`] and [`read_nar`] for when
//!   holding the whole archive is acceptable.
//!
//! A NAR is a stream of length-prefixed byte tokens, each padded with zeros to
//! a multiple of eight bytes. The grammar is
//! `nix-archive-1 <node>`, where a node is
//! `( type regular [executable ""] contents <bytes> )`,
//! `( type symlink target <bytes> )`, or
//! `( type directory (entry ( name <bytes> node <node> ))* )` with entries
//! sorted by name.

use std::{
  collections::BTreeMap,
  io::{self, Read, Write},
};

const MAX_TOKEN: usize = 4096;

fn invalid(msg: impl Into<String>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn pad_len(len: u64) -> usize {
  usize::try_from(len.wrapping_neg() % 8).unwrap_or(0)
}

fn push_token(out: &mut Vec<u8>, token: &[u8]) {
  out.extend_from_slice(&(token.len() as u64).to_le_bytes());
  out.extend_from_slice(token);
  out.resize(out.len() + (8 - token.len() % 8) % 8, 0);
}

/// NAR bytes preceding the content of a single regular file of `len` bytes.
#[must_use]
pub fn file_nar_header(len: u64) -> Vec<u8> {
  let mut out = Vec::with_capacity(96);
  for token in ["nix-archive-1", "(", "type", "regular", "contents"] {
    push_token(&mut out, token.as_bytes());
  }
  out.extend_from_slice(&len.to_le_bytes());
  out
}

/// NAR bytes following the content of a single regular file of `len` bytes.
#[must_use]
pub fn file_nar_trailer(len: u64) -> Vec<u8> {
  let mut out = vec![0; pad_len(len)];
  push_token(&mut out, b")");
  out
}

/// Write `contents` as a single non-executable regular file NAR.
///
/// # Errors
///
/// Propagates write errors from `w`.
pub fn write_file_nar<W: Write + ?Sized>(
  w: &mut W,
  contents: &[u8],
) -> io::Result<()> {
  let len = contents.len() as u64;
  w.write_all(&file_nar_header(len))?;
  w.write_all(contents)?;
  w.write_all(&file_nar_trailer(len))
}

fn read_u64<R: Read + ?Sized>(r: &mut R) -> io::Result<u64> {
  let mut buf = [0_u8; 8];
  r.read_exact(&mut buf)?;
  Ok(u64::from_le_bytes(buf))
}

fn write_u64<W: Write + ?Sized>(w: &mut W, n: u64) -> io::Result<()> {
  w.write_all(&n.to_le_bytes())
}

fn token<R, W>(r: &mut R, w: &mut W) -> io::Result<Vec<u8>>
where
  R: Read + ?Sized,
  W: Write + ?Sized,
{
  let len = usize::try_from(read_u64(r)?).unwrap_or(usize::MAX);
  if len > MAX_TOKEN {
    return Err(invalid("malformed NAR: oversized token"));
  }
  let mut buf = vec![0_u8; len];
  r.read_exact(&mut buf)?;
  let pad = (8 - len % 8) % 8;
  let mut padding = [0_u8; 8];
  r.read_exact(&mut padding[..pad])?;
  if padding[..pad].iter().any(|&b| b != 0) {
    return Err(invalid("malformed NAR: non-zero padding"));
  }
  write_u64(w, len as u64)?;
  w.write_all(&buf)?;
  w.write_all(&padding[..pad])?;
  Ok(buf)
}

fn expect<R, W>(r: &mut R, w: &mut W, want: &str) -> io::Result<()>
where
  R: Read + ?Sized,
  W: Write + ?Sized,
{
  let tok = token(r, w)?;
  if tok == want.as_bytes() {
    Ok(())
  } else {
    Err(invalid(format!(
      "malformed NAR: expected {want:?}, got {:?}",
      String::from_utf8_lossy(&tok)
    )))
  }
}

fn contents<R, W>(r: &mut R, w: &mut W) -> io::Result<()>
where
  R: Read + ?Sized,
  W: Write + ?Sized,
{
  let len = read_u64(r)?;
  write_u64(w, len)?;
  let copied = io::copy(&mut r.take(len), w)?;
  if copied != len {
    return Err(io::ErrorKind::UnexpectedEof.into());
  }
  let pad = pad_len(len);
  let mut padding = [0_u8; 8];
  r.read_exact(&mut padding[..pad])?;
  if padding[..pad].iter().any(|&b| b != 0) {
    return Err(invalid("malformed NAR: non-zero padding"));
  }
  w.write_all(&padding[..pad])
}

/// Copy exactly one NAR from `r` to `w`, parsing it to find where it ends.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR or on I/O errors.
pub fn copy<R, W>(r: &mut R, w: &mut W) -> io::Result<()>
where
  R: Read + ?Sized,
  W: Write + ?Sized,
{
  enum Next {
    Node,
    NodeDone,
    DirEntry,
  }

  expect(r, w, "nix-archive-1")?;
  let mut depth = 0_usize;
  let mut next = Next::Node;
  loop {
    next = match next {
      Next::Node => {
        expect(r, w, "(")?;
        expect(r, w, "type")?;
        match token(r, w)?.as_slice() {
          b"regular" => {
            let mut tok = token(r, w)?;
            if tok == b"executable" {
              expect(r, w, "")?;
              tok = token(r, w)?;
            }
            if tok != b"contents" {
              return Err(invalid("malformed NAR: expected \"contents\""));
            }
            contents(r, w)?;
            expect(r, w, ")")?;
            Next::NodeDone
          },
          b"symlink" => {
            expect(r, w, "target")?;
            token(r, w)?;
            expect(r, w, ")")?;
            Next::NodeDone
          },
          b"directory" => {
            depth += 1;
            Next::DirEntry
          },
          other => {
            return Err(invalid(format!(
              "malformed NAR: unknown node type {:?}",
              String::from_utf8_lossy(other)
            )));
          },
        }
      },
      Next::NodeDone => {
        if depth == 0 {
          return Ok(());
        }
        expect(r, w, ")")?;
        Next::DirEntry
      },
      Next::DirEntry => {
        match token(r, w)?.as_slice() {
          b"entry" => {
            expect(r, w, "(")?;
            expect(r, w, "name")?;
            token(r, w)?;
            expect(r, w, "node")?;
            Next::Node
          },
          b")" => {
            depth -= 1;
            Next::NodeDone
          },
          _ => {
            return Err(invalid("malformed NAR: expected \"entry\" or \")\""));
          },
        }
      },
    };
  }
}

const MAGIC: &str = "nix-archive-1";

const MAX_DEPTH: usize = 10_000;

fn write_padded_token<W: Write + ?Sized>(
  w: &mut W,
  token: &[u8],
) -> io::Result<()> {
  write_u64(w, token.len() as u64)?;
  w.write_all(token)?;
  let pad = (8 - token.len() % 8) % 8;
  w.write_all(&[0_u8; 8][..pad])
}

/// Begin a NAR on `w`, returning the handle for its single root node.
///
/// Writing exactly one node (via [`Node::file`], [`Node::symlink`], or a
/// [`Node::directory`] closed with [`Directory::close`]) produces a complete
/// archive.
///
/// # Errors
///
/// Propagates write errors from `w`.
pub fn open<W: Write + ?Sized>(w: &mut W) -> io::Result<Node<'_, W>> {
  write_padded_token(w, MAGIC.as_bytes())?;
  Ok(Node { w })
}

/// A handle for writing one NAR node (a file, symlink, or directory).
pub struct Node<'a, W: Write + ?Sized> {
  w: &'a mut W,
}

impl<'a, W: Write + ?Sized> Node<'a, W> {
  /// Write this node as a symlink pointing at `target`.
  ///
  /// # Errors
  ///
  /// Propagates write errors from the underlying writer.
  pub fn symlink(self, target: &[u8]) -> io::Result<()> {
    write_padded_token(self.w, b"(")?;
    write_padded_token(self.w, b"type")?;
    write_padded_token(self.w, b"symlink")?;
    write_padded_token(self.w, b"target")?;
    write_padded_token(self.w, target)?;
    write_padded_token(self.w, b")")
  }

  /// Write this node as a regular file of `size` bytes streamed from `body`.
  ///
  /// `size` must be known in advance because it is framed before the content;
  /// exactly that many bytes are copied from `body`.
  ///
  /// # Errors
  ///
  /// Propagates I/O errors, and fails with [`io::ErrorKind::UnexpectedEof`]
  /// if `body` yields fewer than `size` bytes.
  pub fn file(
    self,
    executable: bool,
    size: u64,
    body: &mut dyn Read,
  ) -> io::Result<()> {
    write_padded_token(self.w, b"(")?;
    write_padded_token(self.w, b"type")?;
    write_padded_token(self.w, b"regular")?;
    if executable {
      write_padded_token(self.w, b"executable")?;
      write_padded_token(self.w, b"")?;
    }
    write_padded_token(self.w, b"contents")?;
    write_u64(self.w, size)?;
    let copied = io::copy(&mut body.take(size), self.w)?;
    if copied != size {
      return Err(io::ErrorKind::UnexpectedEof.into());
    }
    self.w.write_all(&[0_u8; 8][..pad_len(size)])?;
    write_padded_token(self.w, b")")
  }

  /// Begin a directory node; add entries, then call [`Directory::close`].
  ///
  /// # Errors
  ///
  /// Propagates write errors from the underlying writer.
  pub fn directory(self) -> io::Result<Directory<'a, W>> {
    write_padded_token(self.w, b"(")?;
    write_padded_token(self.w, b"type")?;
    write_padded_token(self.w, b"directory")?;
    Ok(Directory {
      w:          self.w,
      last:       None,
      open_entry: false,
    })
  }
}

/// A handle for writing the entries of a directory node.
pub struct Directory<'a, W: Write + ?Sized> {
  w:          &'a mut W,
  last:       Option<Vec<u8>>,
  open_entry: bool,
}

impl<W: Write + ?Sized> Directory<'_, W> {
  /// Begin an entry named `name`; the returned handle writes its node.
  ///
  /// Names must be supplied in strictly ascending byte order to match the
  /// canonical NAR ordering a reader expects.
  ///
  /// # Errors
  ///
  /// Fails with [`io::ErrorKind::InvalidInput`] if `name` is empty, contains
  /// `/` or a NUL byte, or does not sort strictly after the previous entry.
  pub fn entry(&mut self, name: &[u8]) -> io::Result<Node<'_, W>> {
    if name.is_empty() || name.contains(&b'/') || name.contains(&0) {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid NAR entry name",
      ));
    }
    if self.last.as_deref().is_some_and(|last| name <= last) {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "NAR directory entries must be sorted and unique",
      ));
    }
    if self.open_entry {
      write_padded_token(self.w, b")")?;
    }
    write_padded_token(self.w, b"entry")?;
    write_padded_token(self.w, b"(")?;
    write_padded_token(self.w, b"name")?;
    write_padded_token(self.w, name)?;
    write_padded_token(self.w, b"node")?;
    self.last = Some(name.to_vec());
    self.open_entry = true;
    Ok(Node { w: &mut *self.w })
  }

  /// Finish the directory node.
  ///
  /// # Errors
  ///
  /// Propagates write errors from the underlying writer.
  pub fn close(self) -> io::Result<()> {
    if self.open_entry {
      write_padded_token(self.w, b")")?;
    }
    write_padded_token(self.w, b")")
  }
}

/// An in-memory NAR node, for building or inspecting whole archives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
  /// A regular file.
  File {
    /// Whether the executable bit is set.
    executable: bool,
    /// The raw file contents.
    contents:   Vec<u8>,
  },
  /// A symbolic link.
  Symlink {
    /// The raw link target.
    target: Vec<u8>,
  },
  /// A directory, mapping each entry name to its child node. The map keeps
  /// names in the sorted order a NAR requires.
  Directory(BTreeMap<Vec<u8>, Entry>),
}

/// Serialize an [`Entry`] tree as a complete NAR to `w`.
///
/// # Errors
///
/// Propagates write errors from `w`.
pub fn write_nar<W: Write + ?Sized>(
  w: &mut W,
  entry: &Entry,
) -> io::Result<()> {
  write_node(open(w)?, entry)
}

fn write_node<W: Write + ?Sized>(
  node: Node<'_, W>,
  entry: &Entry,
) -> io::Result<()> {
  match entry {
    Entry::File {
      executable,
      contents,
    } => {
      node.file(*executable, contents.len() as u64, &mut contents.as_slice())
    },
    Entry::Symlink { target } => node.symlink(target),
    Entry::Directory(entries) => {
      let mut dir = node.directory()?;
      for (name, child) in entries {
        let child_node = dir.entry(name)?;
        write_node(child_node, child)?;
      }
      dir.close()
    },
  }
}

/// Receives the nodes of a NAR as [`read`] walks it.
///
/// Every method has a default no-op body, so an implementation overrides only
/// the events it needs.
pub trait Visitor {
  /// A regular file. `body` yields exactly its byte count; whatever the
  /// visitor leaves unread is drained by the reader before the walk
  /// continues.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn visit_file(
    &mut self,
    _executable: bool,
    _size: u64,
    _body: &mut dyn Read,
  ) -> io::Result<()> {
    Ok(())
  }

  /// A symlink and its raw target bytes.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn visit_symlink(&mut self, _target: &[u8]) -> io::Result<()> {
    Ok(())
  }

  /// The start of a directory node.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn enter_directory(&mut self) -> io::Result<()> {
    Ok(())
  }

  /// The name of the next entry in the current directory; its node is
  /// reported by the calls that follow.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn visit_entry(&mut self, _name: &[u8]) -> io::Result<()> {
    Ok(())
  }

  /// The end of the current directory node.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn leave_directory(&mut self) -> io::Result<()> {
    Ok(())
  }
}

fn read_padded_token<R: Read + ?Sized>(r: &mut R) -> io::Result<Vec<u8>> {
  let len = usize::try_from(read_u64(r)?).unwrap_or(usize::MAX);
  if len > MAX_TOKEN {
    return Err(invalid("malformed NAR: oversized token"));
  }
  let mut buf = vec![0_u8; len];
  r.read_exact(&mut buf)?;
  let pad = (8 - len % 8) % 8;
  let mut padding = [0_u8; 8];
  r.read_exact(&mut padding[..pad])?;
  if padding[..pad].iter().any(|&b| b != 0) {
    return Err(invalid("malformed NAR: non-zero padding"));
  }
  Ok(buf)
}

fn expect_token<R: Read + ?Sized>(r: &mut R, want: &str) -> io::Result<()> {
  let tok = read_padded_token(r)?;
  if tok == want.as_bytes() {
    Ok(())
  } else {
    Err(invalid(format!(
      "malformed NAR: expected {want:?}, got {:?}",
      String::from_utf8_lossy(&tok)
    )))
  }
}

fn read_padding<R: Read + ?Sized>(r: &mut R, len: u64) -> io::Result<()> {
  let pad = pad_len(len);
  let mut padding = [0_u8; 8];
  r.read_exact(&mut padding[..pad])?;
  if padding[..pad].iter().any(|&b| b != 0) {
    return Err(invalid("malformed NAR: non-zero padding"));
  }
  Ok(())
}

/// Walk a NAR from `r`, reporting each node to `visitor`.
///
/// File bodies are streamed, so arbitrarily large archives can be processed
/// without buffering them.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR, on I/O errors, or if
/// `visitor` returns an error.
pub fn read<R: Read + ?Sized, V: Visitor>(
  r: &mut R,
  visitor: &mut V,
) -> io::Result<()> {
  expect_token(r, MAGIC)?;
  read_node(r, visitor, 0)
}

fn read_node<R: Read + ?Sized, V: Visitor>(
  r: &mut R,
  visitor: &mut V,
  depth: usize,
) -> io::Result<()> {
  if depth > MAX_DEPTH {
    return Err(invalid("malformed NAR: nesting too deep"));
  }
  expect_token(r, "(")?;
  expect_token(r, "type")?;
  match read_padded_token(r)?.as_slice() {
    b"regular" => {
      let mut tok = read_padded_token(r)?;
      let executable = tok == b"executable";
      if executable {
        expect_token(r, "")?;
        tok = read_padded_token(r)?;
      }
      if tok != b"contents" {
        return Err(invalid("malformed NAR: expected \"contents\""));
      }
      let size = read_u64(r)?;
      {
        let mut body = (&mut *r).take(size);
        visitor.visit_file(executable, size, &mut body)?;
        io::copy(&mut body, &mut io::sink())?;
        if body.limit() != 0 {
          return Err(io::ErrorKind::UnexpectedEof.into());
        }
      }
      read_padding(r, size)?;
      expect_token(r, ")")?;
    },
    b"symlink" => {
      expect_token(r, "target")?;
      let target = read_padded_token(r)?;
      visitor.visit_symlink(&target)?;
      expect_token(r, ")")?;
    },
    b"directory" => {
      visitor.enter_directory()?;
      loop {
        match read_padded_token(r)?.as_slice() {
          b"entry" => {
            expect_token(r, "(")?;
            expect_token(r, "name")?;
            let name = read_padded_token(r)?;
            expect_token(r, "node")?;
            visitor.visit_entry(&name)?;
            read_node(r, visitor, depth + 1)?;
            expect_token(r, ")")?;
          },
          b")" => break,
          _ => {
            return Err(invalid("malformed NAR: expected \"entry\" or \")\""));
          },
        }
      }
      visitor.leave_directory()?;
    },
    other => {
      return Err(invalid(format!(
        "malformed NAR: unknown node type {:?}",
        String::from_utf8_lossy(other)
      )));
    },
  }
  Ok(())
}

#[derive(Default)]
struct TreeBuilder {
  stack: Vec<Frame>,
  root:  Option<Entry>,
}

struct Frame {
  map:     BTreeMap<Vec<u8>, Entry>,
  pending: Option<Vec<u8>>,
}

impl TreeBuilder {
  fn place(&mut self, entry: Entry) {
    if let Some(frame) = self.stack.last_mut() {
      if let Some(name) = frame.pending.take() {
        frame.map.insert(name, entry);
      }
    } else {
      self.root = Some(entry);
    }
  }
}

impl Visitor for TreeBuilder {
  fn visit_file(
    &mut self,
    executable: bool,
    _size: u64,
    body: &mut dyn Read,
  ) -> io::Result<()> {
    let mut contents = Vec::new();
    body.read_to_end(&mut contents)?;
    self.place(Entry::File {
      executable,
      contents,
    });
    Ok(())
  }

  fn visit_symlink(&mut self, target: &[u8]) -> io::Result<()> {
    self.place(Entry::Symlink {
      target: target.to_vec(),
    });
    Ok(())
  }

  fn enter_directory(&mut self) -> io::Result<()> {
    self.stack.push(Frame {
      map:     BTreeMap::new(),
      pending: None,
    });
    Ok(())
  }

  fn visit_entry(&mut self, name: &[u8]) -> io::Result<()> {
    if let Some(frame) = self.stack.last_mut() {
      frame.pending = Some(name.to_vec());
    }
    Ok(())
  }

  fn leave_directory(&mut self) -> io::Result<()> {
    if let Some(frame) = self.stack.pop() {
      self.place(Entry::Directory(frame.map));
    }
    Ok(())
  }
}

/// Parse a whole NAR from `r` into an [`Entry`] tree.
///
/// File contents are buffered in memory; use [`read`] with a [`Visitor`] to
/// stream large archives instead.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR or on I/O errors.
pub fn read_nar<R: Read + ?Sized>(r: &mut R) -> io::Result<Entry> {
  let mut builder = TreeBuilder::default();
  read(r, &mut builder)?;
  builder
    .root
    .ok_or_else(|| invalid("malformed NAR: no root node"))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn single_file_roundtrip() {
    let mut nar = Vec::new();
    write_file_nar(&mut nar, b"hello").unwrap();
    let mut out = Vec::new();
    copy(&mut nar.as_slice(), &mut out).unwrap();
    assert_eq!(out, nar);
  }

  #[test]
  fn copies_exactly_one_nar() {
    let mut nar = Vec::new();
    write_file_nar(&mut nar, b"12345678").unwrap();
    let mut input = nar.clone();
    input.extend_from_slice(b"trailing");
    let mut r = input.as_slice();
    let mut out = Vec::new();
    copy(&mut r, &mut out).unwrap();
    assert_eq!(out, nar);
    assert_eq!(r, b"trailing");
  }

  #[test]
  fn truncated_nar_fails() {
    let mut nar = Vec::new();
    write_file_nar(&mut nar, b"hello world\n").unwrap();
    let mut out = Vec::new();
    assert!(copy(&mut &nar[..nar.len() - 4], &mut out).is_err());
  }

  fn sample_tree() -> Entry {
    let mut sub = BTreeMap::new();
    sub.insert(b"f".to_vec(), Entry::File {
      executable: false,
      contents:   b"abc".to_vec(),
    });
    let mut root = BTreeMap::new();
    root.insert(b"exe".to_vec(), Entry::File {
      executable: true,
      contents:   b"#!/bin/sh".to_vec(),
    });
    root.insert(b"link".to_vec(), Entry::Symlink {
      target: b"exe".to_vec(),
    });
    root.insert(b"sub".to_vec(), Entry::Directory(sub));
    Entry::Directory(root)
  }

  #[test]
  fn tree_write_read_roundtrip() {
    let tree = sample_tree();
    let mut nar = Vec::new();
    write_nar(&mut nar, &tree).unwrap();
    assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), tree);
  }

  #[test]
  fn writer_output_is_one_well_formed_nar() {
    let mut nar = Vec::new();
    write_nar(&mut nar, &sample_tree()).unwrap();
    let mut input = nar.clone();
    input.extend_from_slice(b"trailing");
    let mut r = input.as_slice();
    let mut copied = Vec::new();
    copy(&mut r, &mut copied).unwrap();
    assert_eq!(copied, nar);
    assert_eq!(r, b"trailing");
  }

  #[test]
  fn tree_file_framing_matches_primitive() {
    let mut via_tree = Vec::new();
    write_nar(&mut via_tree, &Entry::File {
      executable: false,
      contents:   b"hello".to_vec(),
    })
    .unwrap();
    let mut via_primitive = Vec::new();
    write_file_nar(&mut via_primitive, b"hello").unwrap();
    assert_eq!(via_tree, via_primitive);
  }

  #[test]
  fn executable_bit_survives_roundtrip() {
    for executable in [false, true] {
      let entry = Entry::File {
        executable,
        contents: b"x".to_vec(),
      };
      let mut nar = Vec::new();
      write_nar(&mut nar, &entry).unwrap();
      assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), entry);
    }
  }

  #[test]
  fn empty_file_roundtrip() {
    let entry = Entry::File {
      executable: false,
      contents:   Vec::new(),
    };
    let mut nar = Vec::new();
    write_nar(&mut nar, &entry).unwrap();
    assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), entry);
  }

  #[test]
  fn symlink_roundtrip() {
    let entry = Entry::Symlink {
      target: b"../elsewhere".to_vec(),
    };
    let mut nar = Vec::new();
    write_nar(&mut nar, &entry).unwrap();
    assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), entry);
  }

  #[test]
  fn out_of_order_entry_rejected() {
    let mut nar = Vec::new();
    let node = open(&mut nar).unwrap();
    let mut dir = node.directory().unwrap();
    dir
      .entry(b"b")
      .unwrap()
      .file(false, 0, &mut io::empty())
      .unwrap();
    match dir.entry(b"a") {
      Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
      Ok(_) => panic!("expected out-of-order entry to be rejected"),
    }
  }

  #[test]
  fn invalid_entry_name_rejected() {
    let mut nar = Vec::new();
    let node = open(&mut nar).unwrap();
    let mut dir = node.directory().unwrap();
    for bad in [&b"a/b"[..], b"", &b"a\0b"[..]] {
      match dir.entry(bad) {
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
        Ok(_) => panic!("expected invalid name to be rejected"),
      }
    }
  }

  #[test]
  fn reads_primitive_file_nar() {
    let mut nar = Vec::new();
    write_file_nar(&mut nar, b"payload").unwrap();
    assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), Entry::File {
      executable: false,
      contents:   b"payload".to_vec(),
    });
  }

  #[test]
  fn truncated_tree_nar_fails() {
    let mut nar = Vec::new();
    write_nar(&mut nar, &sample_tree()).unwrap();
    assert!(read_nar(&mut &nar[..nar.len() - 16]).is_err());
  }
}
