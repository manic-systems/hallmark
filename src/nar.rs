//! The Nix Archive (NAR) format.
//!
//! The API comes in three layers, lowest first.
//!
//! - Raw framing helpers ([`file_nar_header`], [`file_nar_trailer`],
//!   [`write_file_nar`]) and [`copy`], which forwards exactly one well-formed
//!   NAR.
//! - A streaming writer built from handles ([`open`], [`Node`], [`Directory`])
//!   that serializes file bodies straight from any reader, [`dump`] which
//!   archives a filesystem tree through it, and a streaming reader driven by a
//!   [`Visitor`] ([`read`]).
//! - An in-memory [`Entry`] tree with [`write_nar`] and [`read_nar`] for when
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
  io::{
    self,
    Read,
    Write,
  },
  path::PathBuf,
};
#[cfg(unix)]
use std::{
  ffi::OsStr,
  fs::{
    self,
    File,
  },
  path::Path,
};

use flub::Error;

const MAX_TOKEN: usize = 4096;

/// A NAR could not be read or written because of its structure.
///
/// Public functions in this module return [`io::Error`], so a caller that
/// wants to branch on the cause downcasts [`io::Error::get_ref`] to this type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NarError {
  /// A token longer than the format allows.
  #[error("malformed NAR: oversized token")]
  OversizedToken,
  /// Padding bytes that are not all zero.
  #[error("malformed NAR: non-zero padding")]
  NonZeroPadding,
  /// A token other than the one the grammar requires at this point.
  #[error("malformed NAR: expected {expected:?}, got {:?}", String::from_utf8_lossy(.got))]
  UnexpectedToken {
    /// What the grammar allows here.
    expected: &'static str,
    /// The token that was found.
    got:      Vec<u8>,
  },
  /// A node whose `type` is not `regular`, `symlink`, or `directory`.
  #[error("malformed NAR: unknown node type {:?}", String::from_utf8_lossy(.0))]
  UnknownNodeType(Vec<u8>),
  /// Directories nested deeper than the reader accepts.
  #[error("malformed NAR: nesting too deep")]
  NestingTooDeep,
  /// An archive that produced no root node.
  #[error("malformed NAR: no root node")]
  NoRootNode,
  /// A directory entry name that is empty or contains `/` or a NUL byte.
  #[error("invalid NAR entry name")]
  InvalidEntryName,
  /// Directory entries that are not strictly ascending by name.
  #[error("NAR directory entries must be sorted and unique")]
  UnsortedEntries,
  /// A path that is neither a regular file, a directory, nor a symlink.
  #[error("{}: not a regular file, directory or symlink", .0.display())]
  UnsupportedFileType(PathBuf),
}

impl NarError {
  const fn kind(&self) -> io::ErrorKind {
    match *self {
      Self::OversizedToken
      | Self::NonZeroPadding
      | Self::UnexpectedToken { .. }
      | Self::UnknownNodeType(_)
      | Self::NestingTooDeep
      | Self::NoRootNode => io::ErrorKind::InvalidData,
      Self::InvalidEntryName | Self::UnsortedEntries | Self::UnsupportedFileType(_) => {
        io::ErrorKind::InvalidInput
      },
    }
  }
}

impl From<NarError> for io::Error {
  fn from(err: NarError) -> Self {
    Self::new(err.kind(), err)
  }
}

fn pad_len(len: u64) -> usize {
  usize::try_from(len.wrapping_neg() % 8).unwrap_or(0)
}

fn push_token(out: &mut Vec<u8>, token: &[u8]) {
  out.extend_from_slice(&(token.len() as u64).to_le_bytes());
  out.extend_from_slice(token);
  out.resize(out.len() + pad_len(token.len() as u64), 0);
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
pub fn write_file_nar<W>(w: &mut W, contents: &[u8]) -> io::Result<()>
where
  W: Write + ?Sized,
{
  let len = contents.len() as u64;
  w.write_all(&file_nar_header(len))?;
  w.write_all(contents)?;
  w.write_all(&file_nar_trailer(len))
}

trait NarRead: Read {
  fn read_u64(&mut self) -> io::Result<u64> {
    let mut buf = [0_u8; 8];
    self.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
  }

  fn read_padding(&mut self, len: u64) -> io::Result<()> {
    let pad = pad_len(len);
    let mut padding = [0_u8; 8];
    self.read_exact(&mut padding[..pad])?;
    if padding[..pad].iter().any(|&byte| byte != 0) {
      return Err(NarError::NonZeroPadding.into());
    }
    Ok(())
  }

  fn read_padded_token(&mut self) -> io::Result<Vec<u8>> {
    let len = self.read_u64()?;
    let size = usize::try_from(len)
      .ok()
      .filter(|&size| size <= MAX_TOKEN)
      .ok_or(NarError::OversizedToken)?;

    let mut token = vec![0_u8; size];
    self.read_exact(&mut token)?;
    self.read_padding(len)?;
    Ok(token)
  }

  fn expect_token(&mut self, want: &'static str) -> io::Result<()> {
    let got = self.read_padded_token()?;
    if got == want.as_bytes() {
      return Ok(());
    }
    Err(
      NarError::UnexpectedToken {
        expected: want,
        got,
      }
      .into(),
    )
  }

  fn copy_token<W>(&mut self, writer: &mut W) -> io::Result<Vec<u8>>
  where
    W: Write + ?Sized,
  {
    let token = self.read_padded_token()?;
    writer.write_padded_token(&token)?;
    Ok(token)
  }

  fn copy_expect<W>(&mut self, writer: &mut W, want: &'static str) -> io::Result<()>
  where
    W: Write + ?Sized,
  {
    let got = self.copy_token(writer)?;
    if got == want.as_bytes() {
      return Ok(());
    }
    Err(
      NarError::UnexpectedToken {
        expected: want,
        got,
      }
      .into(),
    )
  }

  fn copy_contents<W>(&mut self, writer: &mut W) -> io::Result<()>
  where
    W: Write + ?Sized,
  {
    let len = self.read_u64()?;
    writer.write_u64(len)?;

    let copied = io::copy(&mut (&mut *self).take(len), writer)?;
    if copied != len {
      return Err(io::ErrorKind::UnexpectedEof.into());
    }

    self.read_padding(len)?;
    writer.write_all(&[0_u8; 8][..pad_len(len)])
  }
}

impl<R: Read + ?Sized> NarRead for R {}

trait NarWrite: Write {
  fn write_u64(&mut self, n: u64) -> io::Result<()> {
    self.write_all(&n.to_le_bytes())
  }

  fn write_padded_token(&mut self, token: &[u8]) -> io::Result<()> {
    let len = token.len() as u64;
    self.write_u64(len)?;
    self.write_all(token)?;
    self.write_all(&[0_u8; 8][..pad_len(len)])
  }
}

impl<W: Write + ?Sized> NarWrite for W {}

/// Copy exactly one NAR from `r` to `w`, parsing it to find where it ends.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR or on I/O errors.
pub fn copy<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
  R: Read + ?Sized,
  W: Write + ?Sized,
{
  enum Next {
    Node,
    NodeDone,
    DirEntry,
  }

  reader.copy_expect(writer, "nix-archive-1")?;
  let mut depth = 0_usize;
  let mut next = Next::Node;
  loop {
    next = match next {
      Next::Node => {
        reader.copy_expect(writer, "(")?;
        reader.copy_expect(writer, "type")?;
        match reader.copy_token(writer)?.as_slice() {
          b"regular" => {
            let mut tok = reader.copy_token(writer)?;
            if tok == b"executable" {
              reader.copy_expect(writer, "")?;
              tok = reader.copy_token(writer)?;
            }
            if tok != b"contents" {
              return Err(
                NarError::UnexpectedToken {
                  expected: "contents",
                  got:      tok,
                }
                .into(),
              );
            }
            reader.copy_contents(writer)?;
            reader.copy_expect(writer, ")")?;
            Next::NodeDone
          },
          b"symlink" => {
            reader.copy_expect(writer, "target")?;
            reader.copy_token(writer)?;
            reader.copy_expect(writer, ")")?;
            Next::NodeDone
          },
          b"directory" => {
            depth += 1;
            Next::DirEntry
          },
          other => return Err(NarError::UnknownNodeType(other.to_vec()).into()),
        }
      },
      Next::NodeDone => {
        if depth == 0 {
          return Ok(());
        }
        reader.copy_expect(writer, ")")?;
        Next::DirEntry
      },
      Next::DirEntry => {
        match reader.copy_token(writer)?.as_slice() {
          b"entry" => {
            reader.copy_expect(writer, "(")?;
            reader.copy_expect(writer, "name")?;
            reader.copy_token(writer)?;
            reader.copy_expect(writer, "node")?;
            Next::Node
          },
          b")" => {
            depth -= 1;
            Next::NodeDone
          },
          other => {
            return Err(
              NarError::UnexpectedToken {
                expected: "entry or )",
                got:      other.to_vec(),
              }
              .into(),
            );
          },
        }
      },
    };
  }
}

const MAGIC: &str = "nix-archive-1";

const MAX_DEPTH: usize = 10_000;

/// Begin a NAR on `w`, returning the handle for its single root node.
///
/// Writing exactly one node (via [`Node::file`], [`Node::symlink`], or a
/// [`Node::directory`] closed with [`Directory::close`]) produces a complete
/// archive.
///
/// # Errors
///
/// Propagates write errors from `w`.
pub fn open<W>(w: &mut W) -> io::Result<Node<'_, W>>
where
  W: Write + ?Sized,
{
  w.write_padded_token(MAGIC.as_bytes())?;
  Ok(Node { w })
}

/// A handle for writing one NAR node (a file, symlink, or directory).
pub struct Node<'writer, W: Write + ?Sized> {
  w: &'writer mut W,
}

impl<'writer, W: Write + ?Sized> Node<'writer, W> {
  /// Write this node as a symlink pointing at `target`.
  ///
  /// # Errors
  ///
  /// Propagates write errors from the underlying writer.
  pub fn symlink(self, target: &[u8]) -> io::Result<()> {
    self.w.write_padded_token(b"(")?;
    self.w.write_padded_token(b"type")?;
    self.w.write_padded_token(b"symlink")?;
    self.w.write_padded_token(b"target")?;
    self.w.write_padded_token(target)?;
    self.w.write_padded_token(b")")
  }

  /// Write this node as a regular file of `size` bytes streamed from `body`.
  ///
  /// `size` must be known in advance because it is framed before the content.
  /// Exactly that many bytes are copied from `body`.
  ///
  /// # Errors
  ///
  /// Propagates I/O errors, and fails with [`io::ErrorKind::UnexpectedEof`]
  /// if `body` yields fewer than `size` bytes.
  pub fn file(self, executable: bool, size: u64, body: &mut dyn Read) -> io::Result<()> {
    self.w.write_padded_token(b"(")?;
    self.w.write_padded_token(b"type")?;
    self.w.write_padded_token(b"regular")?;
    if executable {
      self.w.write_padded_token(b"executable")?;
      self.w.write_padded_token(b"")?;
    }
    self.w.write_padded_token(b"contents")?;
    self.w.write_u64(size)?;
    let copied = io::copy(&mut body.take(size), self.w)?;
    if copied != size {
      return Err(io::ErrorKind::UnexpectedEof.into());
    }
    self.w.write_all(&[0_u8; 8][..pad_len(size)])?;
    self.w.write_padded_token(b")")
  }

  /// Begin a directory node. Add entries, then call [`Directory::close`].
  ///
  /// # Errors
  ///
  /// Propagates write errors from the underlying writer.
  pub fn directory(self) -> io::Result<Directory<'writer, W>> {
    self.w.write_padded_token(b"(")?;
    self.w.write_padded_token(b"type")?;
    self.w.write_padded_token(b"directory")?;
    Ok(Directory {
      w:          self.w,
      last:       None,
      open_entry: false,
    })
  }
}

/// A handle for writing the entries of a directory node.
pub struct Directory<'writer, W: Write + ?Sized> {
  w:          &'writer mut W,
  last:       Option<Vec<u8>>,
  open_entry: bool,
}

impl<W: Write + ?Sized> Directory<'_, W> {
  /// Begin an entry named `name`, returning the handle that writes its node.
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
      return Err(NarError::InvalidEntryName.into());
    }
    if self.last.as_deref().is_some_and(|last| name <= last) {
      return Err(NarError::UnsortedEntries.into());
    }
    if self.open_entry {
      self.w.write_padded_token(b")")?;
    }
    self.w.write_padded_token(b"entry")?;
    self.w.write_padded_token(b"(")?;
    self.w.write_padded_token(b"name")?;
    self.w.write_padded_token(name)?;
    self.w.write_padded_token(b"node")?;
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
      self.w.write_padded_token(b")")?;
    }
    self.w.write_padded_token(b")")
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
  Directory(BTreeMap<Vec<u8>, Self>),
}

/// Serialize an [`Entry`] tree as a complete NAR to `w`.
///
/// # Errors
///
/// Propagates write errors from `w`.
pub fn write_nar<W>(w: &mut W, entry: &Entry) -> io::Result<()>
where
  W: Write + ?Sized,
{
  write_node(open(w)?, entry)
}

fn write_node<W>(node: Node<'_, W>, entry: &Entry) -> io::Result<()>
where
  W: Write + ?Sized,
{
  match *entry {
    Entry::File {
      executable,
      ref contents,
    } => node.file(executable, contents.len() as u64, &mut contents.as_slice()),
    Entry::Symlink { ref target } => node.symlink(target),
    Entry::Directory(ref entries) => {
      let mut dir = node.directory()?;
      for (name, child) in entries {
        let child_node = dir.entry(name)?;
        write_node(child_node, child)?;
      }
      dir.close()
    },
  }
}

/// Serialize the filesystem tree rooted at `path` as a complete NAR to `w`.
///
/// File bodies are streamed, so trees of any size are archived without
/// buffering them. As in Nix, symlinks (including `path` itself) are archived
/// rather than followed, and a file is executable when its owner-execute bit
/// is set.
///
/// # Errors
///
/// Fails on I/O errors, naming the path that could not be read, and with
/// [`io::ErrorKind::InvalidInput`] for anything other than a regular file,
/// directory or symlink.
#[cfg(unix)]
pub fn dump<W>(w: &mut W, path: &Path) -> io::Result<()>
where
  W: Write + ?Sized,
{
  dump_node(open(w)?, path)
}

#[cfg(unix)]
#[expect(
  clippy::filetype_is_file,
  reason = "symlinks and directories return earlier, so this rejects only special files"
)]
fn dump_node<W>(node: Node<'_, W>, path: &Path) -> io::Result<()>
where
  W: Write + ?Sized,
{
  use std::os::unix::{
    ffi::{
      OsStrExt as _,
      OsStringExt as _,
    },
    fs::PermissionsExt as _,
  };

  let with_path = |err: io::Error| io::Error::new(err.kind(), format!("{}: {err}", path.display()));
  let file_type = fs::symlink_metadata(path).map_err(with_path)?.file_type();

  if file_type.is_symlink() {
    let target = fs::read_link(path).map_err(with_path)?;
    return node.symlink(target.as_os_str().as_bytes());
  }

  if file_type.is_dir() {
    let mut names = fs::read_dir(path)
      .map_err(with_path)?
      .map(|entry| entry.map(|dir_entry| dir_entry.file_name().into_vec()))
      .collect::<io::Result<Vec<_>>>()
      .map_err(with_path)?;
    names.sort_unstable();

    let mut dir = node.directory()?;
    for name in names {
      dump_node(dir.entry(&name)?, &path.join(OsStr::from_bytes(&name)))?;
    }
    return dir.close();
  }

  if !file_type.is_file() {
    return Err(NarError::UnsupportedFileType(path.to_path_buf()).into());
  }

  let mut file = File::open(path).map_err(with_path)?;
  let metadata = file.metadata().map_err(with_path)?;
  let executable = metadata.permissions().mode() & 0o100 != 0;
  node.file(executable, metadata.len(), &mut file)
}

/// Receives the nodes of a NAR as [`read`] walks it.
///
/// Every method has a default no-op body, so an implementation overrides only
/// the events it needs.
pub trait Visitor {
  /// A regular file. `body` yields exactly its byte count, and whatever the
  /// visitor leaves unread is drained by the reader before the walk
  /// continues.
  ///
  /// # Errors
  ///
  /// Any error returned aborts the walk and surfaces from [`read`].
  fn visit_file(&mut self, _executable: bool, _size: u64, _body: &mut dyn Read) -> io::Result<()> {
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

  /// The name of the next entry in the current directory. The calls that
  /// follow report its node.
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

/// Walk a NAR from `r`, reporting each node to `visitor`.
///
/// File bodies are streamed, so arbitrarily large archives can be processed
/// without buffering them.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR, on I/O errors, or if
/// `visitor` returns an error.
pub fn read<R, V>(reader: &mut R, visitor: &mut V) -> io::Result<()>
where
  R: Read + ?Sized,
  V: Visitor,
{
  reader.expect_token(MAGIC)?;
  read_node(reader, visitor, 0)
}

fn read_node<R, V>(reader: &mut R, visitor: &mut V, depth: usize) -> io::Result<()>
where
  R: Read + ?Sized,
  V: Visitor,
{
  if depth > MAX_DEPTH {
    return Err(NarError::NestingTooDeep.into());
  }

  reader.expect_token("(")?;
  reader.expect_token("type")?;

  match reader.read_padded_token()?.as_slice() {
    b"regular" => {
      read_regular(reader, visitor)?;
      reader.expect_token(")")
    },
    b"symlink" => {
      reader.expect_token("target")?;
      visitor.visit_symlink(&reader.read_padded_token()?)?;
      reader.expect_token(")")
    },
    b"directory" => read_directory(reader, visitor, depth),
    other => Err(NarError::UnknownNodeType(other.to_vec()).into()),
  }
}

fn read_regular<R, V>(reader: &mut R, visitor: &mut V) -> io::Result<()>
where
  R: Read + ?Sized,
  V: Visitor,
{
  let mut tok = reader.read_padded_token()?;
  let executable = tok == b"executable";
  if executable {
    reader.expect_token("")?;
    tok = reader.read_padded_token()?;
  }
  if tok != b"contents" {
    return Err(
      NarError::UnexpectedToken {
        expected: "contents",
        got:      tok,
      }
      .into(),
    );
  }

  let size = reader.read_u64()?;
  let mut body = (&mut *reader).take(size);
  visitor.visit_file(executable, size, &mut body)?;
  io::copy(&mut body, &mut io::sink())?;
  if body.limit() != 0 {
    return Err(io::ErrorKind::UnexpectedEof.into());
  }

  reader.read_padding(size)
}

fn read_directory<R, V>(reader: &mut R, visitor: &mut V, depth: usize) -> io::Result<()>
where
  R: Read + ?Sized,
  V: Visitor,
{
  visitor.enter_directory()?;
  loop {
    match reader.read_padded_token()?.as_slice() {
      b"entry" => {},
      b")" => return visitor.leave_directory(),
      other => {
        return Err(
          NarError::UnexpectedToken {
            expected: "entry or )",
            got:      other.to_vec(),
          }
          .into(),
        );
      },
    }

    reader.expect_token("(")?;
    reader.expect_token("name")?;
    let name = reader.read_padded_token()?;
    reader.expect_token("node")?;

    visitor.visit_entry(&name)?;
    read_node(reader, visitor, depth + 1)?;
    reader.expect_token(")")?;
  }
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
  fn visit_file(&mut self, executable: bool, _size: u64, body: &mut dyn Read) -> io::Result<()> {
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
/// File contents are buffered in memory. Use [`read`] with a [`Visitor`] to
/// stream large archives instead.
///
/// # Errors
///
/// Fails if the input is not a well-formed NAR or on I/O errors.
pub fn read_nar<R>(reader: &mut R) -> io::Result<Entry>
where
  R: Read + ?Sized,
{
  let mut builder = TreeBuilder::default();
  read(reader, &mut builder)?;
  builder.root.ok_or_else(|| NarError::NoRootNode.into())
}

#[cfg(test)]
mod tests {
  #[cfg(unix)] use std::os::unix::fs::symlink;
  #[cfg(unix)] use std::os::unix::net::UnixListener;

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
    let mut reader = input.as_slice();
    let mut out = Vec::new();
    copy(&mut reader, &mut out).unwrap();
    assert_eq!(out, nar);
    assert_eq!(reader, b"trailing");
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
    let mut reader = input.as_slice();
    let mut copied = Vec::new();
    copy(&mut reader, &mut copied).unwrap();
    assert_eq!(copied, nar);
    assert_eq!(reader, b"trailing");
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
      Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
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
        Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
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
    read_nar(&mut &nar[..nar.len() - 16]).unwrap_err();
  }

  #[cfg(unix)]
  #[test]
  fn dump_matches_tree_writer() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    fs::write(path.join("exe"), "#!/bin/sh").unwrap();
    fs::set_permissions(path.join("exe"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("exe", path.join("link")).unwrap();
    fs::DirBuilder::new().create(path.join("sub")).unwrap();
    fs::write(path.join("sub/f"), "abc").unwrap();

    let mut dumped = Vec::new();
    dump(&mut dumped, path).unwrap();
    let mut expected = Vec::new();
    write_nar(&mut expected, &sample_tree()).unwrap();
    assert_eq!(dumped, expected);
  }

  #[cfg(unix)]
  #[test]
  fn dump_sorts_entries_by_bytes() {
    let root = tempfile::tempdir().unwrap();
    for name in ["b", "a", "B", "_"] {
      fs::write(root.path().join(name), name).unwrap();
    }
    let mut nar = Vec::new();
    dump(&mut nar, root.path()).unwrap();
    let Entry::Directory(entries) = read_nar(&mut nar.as_slice()).unwrap() else {
      panic!("expected a directory");
    };
    let names: Vec<_> = entries.keys().map(Vec::as_slice).collect();
    assert_eq!(names, [&b"B"[..], b"_", b"a", b"b"]);
  }

  #[cfg(unix)]
  #[test]
  fn dump_archives_root_symlink_and_empty_directory() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("link");
    symlink("/nonexistent", &link).unwrap();
    let mut nar = Vec::new();
    dump(&mut nar, &link).unwrap();
    assert_eq!(read_nar(&mut nar.as_slice()).unwrap(), Entry::Symlink {
      target: b"/nonexistent".to_vec(),
    });

    let empty = root.path().join("empty");
    fs::DirBuilder::new().create(&empty).unwrap();
    nar.clear();
    dump(&mut nar, &empty).unwrap();
    assert_eq!(
      read_nar(&mut nar.as_slice()).unwrap(),
      Entry::Directory(BTreeMap::new())
    );
  }

  #[cfg(unix)]
  #[test]
  fn dump_rejects_special_files() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    let err = dump(&mut Vec::new(), &socket).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
  }

  #[cfg(unix)]
  #[test]
  fn dump_names_missing_path() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let err = dump(&mut Vec::new(), &missing).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(err.to_string().contains(&*missing.to_string_lossy()));
  }
}
