# fuser Crate Reference

A reference for the `fuser` Rust crate -- a pure-Rust library for implementing FUSE (Filesystem in
Userspace) filesystems. Unlike binding-based approaches, `fuser` is a complete rewrite of the
libfuse C library that leverages Rust's type system and safety guarantees. Originally forked from the
`fuse` crate.

**Latest stable version:** 0.17.0 (released 2026-02-14)
**Minimum Rust version:** 1.85 (edition 2024)
**License:** MIT

---

## Table of Contents

1. [Cargo.toml Dependency](#1-cargotoml-dependency)
2. [The Filesystem Trait](#2-the-filesystem-trait)
3. [Key Types](#3-key-types)
4. [Reply Types](#4-reply-types)
5. [Request](#5-request)
6. [Flags](#6-flags)
7. [Session and Mount](#7-session-and-mount)
8. [Inode Conventions](#8-inode-conventions)
9. [TTL and Caching Behavior](#9-ttl-and-caching-behavior)
10. [Minimal Single-File Filesystem Example](#10-minimal-single-file-filesystem-example)
11. [Static Musl Binaries](#11-static-musl-binaries)
12. [Sources](#12-sources)

---

## 1. Cargo.toml Dependency

With libfuse (default -- requires `libfuse3-dev` / `fuse-devel` and `pkg-config` at build time):

```toml
[dependencies]
fuser = "0.17"
```

Without libfuse (pure Rust on Linux -- requires root or `CAP_SYS_ADMIN` at runtime):

```toml
[dependencies]
fuser = { version = "0.17", default-features = false }
```

### Feature flags

| Feature | Description |
|---------|-------------|
| `libfuse` | Link to libfuse for mount/umount (off by default as of 0.17) |
| `libfuse2` | Specifically use libfuse2 |
| `libfuse3` | Specifically use libfuse3 |
| `serializable` | Add `serde` support to types |
| `experimental` | Async filesystem support via `async-trait` + `tokio` |
| `macfuse-4-compat` | macOS compatibility layer |

---

## 2. The Filesystem Trait

All methods have default implementations that return `ENOSYS` (function not implemented). You only
need to implement the methods your filesystem requires.

### Lifecycle

```rust
fn init(&mut self, req: &Request, config: &mut KernelConfig) -> Result<()>
```
Called on mount. Use `config` to negotiate capabilities (max_readahead, max_write, etc.).

```rust
fn destroy(&mut self)
```
Called on unmount. Clean up resources.

### Lookup and Attributes

```rust
fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry)
```
Look up a directory entry by name and return its attributes + generation. This is the main
entry point for path resolution. The kernel calls this to translate path components into inodes.

```rust
fn forget(&self, req: &Request, ino: INodeNo, nlookup: u64)
```
Forget about an inode. The `nlookup` parameter indicates the number of lookups to forget.

```rust
fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr)
```
Get file attributes (equivalent to `stat(2)`). Called frequently -- the kernel caches the result
for the duration of the TTL returned in the reply.

```rust
fn setattr(
    &self, req: &Request, ino: INodeNo,
    mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>,
    atime: Option<TimeOrNow>, mtime: Option<TimeOrNow>, ctime: Option<SystemTime>,
    fh: Option<FileHandle>,
    crtime: Option<SystemTime>,   // macOS only
    chgtime: Option<SystemTime>,  // macOS only
    bkuptime: Option<SystemTime>, // macOS only
    flags: Option<BsdFileFlags>,  // macOS only
    reply: ReplyAttr,
)
```
Set file attributes. Only the `Some` fields should be changed.

### File Operations

```rust
fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen)
```
Open a file. Return a file handle and `FopenFlags` (e.g., `FOPEN_DIRECT_IO`). The default
implementation succeeds with `fh=0` and no flags.

```rust
fn read(
    &self, req: &Request, ino: INodeNo, fh: FileHandle, offset: u64,
    size: u32, flags: OpenFlags, lock_owner: Option<LockOwner>,
    reply: ReplyData,
)
```
Read data. Return up to `size` bytes starting at `offset`.

```rust
fn write(
    &self, req: &Request, ino: INodeNo, fh: FileHandle, offset: u64,
    data: &[u8], write_flags: WriteFlags, flags: OpenFlags,
    lock_owner: Option<LockOwner>,
    reply: ReplyWrite,
)
```
Write data. Return the number of bytes written.

```rust
fn flush(&self, req: &Request, ino: INodeNo, fh: FileHandle,
         lock_owner: LockOwner, reply: ReplyEmpty)
```
Called on each `close(2)` of a file descriptor (may be called multiple times for dup'd fds).
This is where you should flush any buffered data. Not the same as `fsync`.

```rust
fn fsync(&self, req: &Request, ino: INodeNo, fh: FileHandle,
         datasync: bool, reply: ReplyEmpty)
```
Synchronize file contents. If `datasync` is true, only flush data, not metadata.

```rust
fn release(
    &self, req: &Request, ino: INodeNo, fh: FileHandle,
    flags: OpenFlags, lock_owner: Option<LockOwner>,
    flush: bool, reply: ReplyEmpty,
)
```
Release an open file. Called once when the last file descriptor for this open is closed.
The `flush` flag indicates whether the kernel wants a final flush.

### Directory Operations

```rust
fn opendir(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen)
```
Open a directory. Return a file handle. The default implementation succeeds with `fh=0`.

```rust
fn readdir(
    &self, req: &Request, ino: INodeNo, fh: FileHandle,
    offset: u64, reply: ReplyDirectory,
)
```
Read directory entries. Use `reply.add()` to add entries. The `offset` parameter is an opaque
cookie from the previous `add()` call -- use it to resume listing. Always include `.` and `..`.

```rust
fn readdirplus(
    &self, req: &Request, ino: INodeNo, fh: FileHandle,
    offset: u64, reply: ReplyDirectoryPlus,
)
```
Enhanced readdir that also returns file attributes (combines readdir + lookup).

```rust
fn releasedir(&self, req: &Request, ino: INodeNo, fh: FileHandle,
              flags: OpenFlags, reply: ReplyEmpty)
```
Release an open directory handle.

### Filesystem Info

```rust
fn statfs(&self, req: &Request, ino: INodeNo, reply: ReplyStatfs)
```
Get filesystem statistics. The default returns zeroes. For a simple filesystem, provide
reasonable values for `bsize`, `blocks`, `namelen`, etc.

### Other Methods

These are less commonly needed but available in the trait:

```rust
fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData)
fn mknod(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32,
         umask: u32, rdev: u32, reply: ReplyEntry)
fn mkdir(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32,
         umask: u32, reply: ReplyEntry)
fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty)
fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty)
fn symlink(&self, req: &Request, parent: INodeNo, link_name: &OsStr,
           target: &Path, reply: ReplyEntry)
fn rename(&self, req: &Request, parent: INodeNo, name: &OsStr, newparent: INodeNo,
          newname: &OsStr, flags: RenameFlags, reply: ReplyEmpty)
fn link(&self, req: &Request, ino: INodeNo, newparent: INodeNo,
        newname: &OsStr, reply: ReplyEntry)
fn create(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32,
          umask: u32, flags: i32, reply: ReplyCreate)
fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty)
fn batch_forget(&self, req: &Request, nodes: &[ForgetOne])
fn fsyncdir(&self, req: &Request, ino: INodeNo, fh: FileHandle,
            datasync: bool, reply: ReplyEmpty)
fn setxattr(&self, req: &Request, ino: INodeNo, name: &OsStr,
            value: &[u8], flags: i32, position: u32, reply: ReplyEmpty)
fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr,
            size: u32, reply: ReplyXattr)
fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr)
fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty)
fn getlk(&self, req: &Request, ino: INodeNo, fh: FileHandle,
         lock_owner: LockOwner, start: u64, end: u64, typ: i32,
         pid: u32, reply: ReplyLock)
fn setlk(&self, req: &Request, ino: INodeNo, fh: FileHandle,
         lock_owner: LockOwner, start: u64, end: u64, typ: i32,
         pid: u32, sleep: bool, reply: ReplyEmpty)
fn bmap(&self, req: &Request, ino: INodeNo, blocksize: u32,
        idx: u64, reply: ReplyBmap)
fn ioctl(&self, req: &Request, ino: INodeNo, fh: FileHandle, flags: IoctlFlags,
         cmd: u32, in_data: &[u8], out_size: u32, reply: ReplyIoctl)
fn poll(&self, req: &Request, ino: INodeNo, fh: FileHandle, ph: PollNotifier,
        events: PollEvents, flags: PollFlags, reply: ReplyPoll)
fn fallocate(&self, req: &Request, ino: INodeNo, fh: FileHandle,
             offset: u64, length: u64, mode: i32, reply: ReplyEmpty)
fn lseek(&self, req: &Request, ino: INodeNo, fh: FileHandle,
         offset: i64, whence: i32, reply: ReplyLseek)
fn copy_file_range(
    &self, req: &Request, ino_in: INodeNo, fh_in: FileHandle,
    offset_in: u64, ino_out: INodeNo, fh_out: FileHandle,
    offset_out: u64, len: u64, flags: CopyFileRangeFlags,
    reply: ReplyWrite,
)
```

---

## 3. Key Types

### FileAttr

Represents file metadata (returned by `getattr`, `lookup`, etc.):

```rust
pub struct FileAttr {
    pub ino: INodeNo,       // Inode number
    pub size: u64,          // Size in bytes
    pub blocks: u64,        // Size in 512-byte blocks
    pub atime: SystemTime,  // Last access time
    pub mtime: SystemTime,  // Last modification time
    pub ctime: SystemTime,  // Last metadata change time
    pub crtime: SystemTime, // Creation time (macOS only)
    pub kind: FileType,     // File type (directory, regular, etc.)
    pub perm: u16,          // Permission bits (e.g., 0o644)
    pub nlink: u32,         // Number of hard links
    pub uid: u32,           // Owner user ID
    pub gid: u32,           // Owner group ID
    pub rdev: u32,          // Device ID (for device files)
    pub blksize: u32,       // Block size for I/O (use 4096 if unsure)
    pub flags: u32,         // BSD flags (macOS only, see chflags(2))
}
```

Implements `Clone`, `Copy`, `Debug`, `Eq`, `PartialEq`.

### FileType

```rust
pub enum FileType {
    NamedPipe,    // S_IFIFO
    CharDevice,   // S_IFCHR
    BlockDevice,  // S_IFBLK
    Directory,    // S_IFDIR
    RegularFile,  // S_IFREG
    Symlink,      // S_IFLNK
    Socket,       // S_IFSOCK
}
```

### Newtype Wrappers

| Type | Wraps | Purpose |
|------|-------|---------|
| `INodeNo` | `u64` | Inode number |
| `Generation` | `u64` | Inode generation (for NFS-style handle reuse detection) |
| `FileHandle` | `u64` | Opaque file handle returned by `open`/`opendir` |
| `LockOwner` | `u64` | Lock owner identifier |
| `RequestId` | `u64` | Unique kernel request ID |

### TimeOrNow

```rust
pub enum TimeOrNow {
    SpecificTime(SystemTime),
    Now,
}
```

Used in `setattr` for atime/mtime -- the caller can request "set to this time" or "set to now".

### KernelConfig

Passed to `init()` to negotiate capabilities with the kernel:

```rust
// Key methods:
config.set_max_readahead(bytes: u32)
config.set_max_write(bytes: u32)
config.set_max_background(count: u16)
config.set_congestion_threshold(threshold: u16)
config.set_max_stack_depth(depth: u32) // hard max = 2
config.set_time_granularity(ns: Duration) // must be power of 10
config.capabilities() -> InitFlags
config.add_capabilities(flags: InitFlags) -> Result<(), InitFlags>
```

---

## 4. Reply Types

Every filesystem method receives a reply object. You **must** call exactly one method on it
(either the success method or `error()`). Dropping a reply without calling a method will panic
in debug builds.

### ReplyEntry

Used by: `lookup`, `mknod`, `mkdir`, `symlink`, `link`

```rust
reply.entry(ttl: &Duration, attr: &FileAttr, generation: Generation)
reply.error(err: Errno)
```

### ReplyAttr

Used by: `getattr`, `setattr`

```rust
reply.attr(ttl: &Duration, attr: &FileAttr)
reply.error(err: Errno)
```

### ReplyData

Used by: `read`, `readlink`

```rust
reply.data(data: &[u8])
reply.error(err: Errno)
```

### ReplyWrite

Used by: `write`, `copy_file_range`

```rust
reply.written(size: u32)
reply.error(err: Errno)
```

### ReplyOpen

Used by: `open`, `opendir`

```rust
reply.opened(fh: FileHandle, flags: FopenFlags)
reply.error(err: Errno)
```

### ReplyDirectory

Used by: `readdir`

```rust
// Returns true if buffer is full (stop adding entries).
// offset is an opaque cookie the kernel passes back to resume listing.
reply.add<T: AsRef<OsStr>>(ino: INodeNo, offset: u64, kind: FileType, name: T) -> bool
reply.ok()
reply.error(err: Errno)
```

### ReplyStatfs

Used by: `statfs`

```rust
reply.statfs(
    blocks: u64,   // total data blocks in filesystem
    bfree: u64,    // free blocks
    bavail: u64,   // free blocks available to non-root
    files: u64,    // total file nodes
    ffree: u64,    // free file nodes
    bsize: u32,    // block size
    namelen: u32,  // maximum filename length
    frsize: u32,   // fragment size
)
reply.error(err: Errno)
```

### ReplyEmpty

Used by: `flush`, `fsync`, `release`, `releasedir`, `unlink`, `rmdir`, `rename`,
`setxattr`, `removexattr`, `access`, `fsyncdir`, `setlk`

```rust
reply.ok()
reply.error(err: Errno)
```

### Other Reply Types

| Type | Used by | Success method |
|------|---------|----------------|
| `ReplyCreate` | `create` | `created(ttl, attr, generation, fh, flags)` |
| `ReplyLock` | `getlk` | `locked(start, end, typ, pid)` |
| `ReplyBmap` | `bmap` | `bmap(block)` |
| `ReplyXattr` | `getxattr`, `listxattr` | `size(size)` or `data(data)` |
| `ReplyLseek` | `lseek` | `offset(offset)` |
| `ReplyIoctl` | `ioctl` | `ioctl(result, data)` |
| `ReplyDirectoryPlus` | `readdirplus` | `add(...)` / `ok()` |
| `ReplyPoll` | `poll` | `poll(revents)` |

---

## 5. Request

The `Request` struct is passed to every filesystem method and provides caller context:

```rust
req.unique() -> RequestId  // Unique request ID
req.uid() -> u32           // Calling user's UID
req.gid() -> u32           // Calling user's GID
req.pid() -> u32           // Calling process PID
```

Useful for permission checks (compare `req.uid()` against the file's `uid`).

---

## 6. Flags

### FopenFlags (returned in open reply)

| Flag | Description |
|------|-------------|
| `FOPEN_DIRECT_IO` | Bypass page cache for this file. Every read/write goes to the filesystem. Essential for files whose content changes externally or that should not be cached. |
| `FOPEN_KEEP_CACHE` | Do not invalidate data cache on open. |
| `FOPEN_NONSEEKABLE` | The file is not seekable. |
| `FOPEN_CACHE_DIR` | Allow caching this directory. |
| `FOPEN_STREAM` | The file is stream-like (no file position). |
| `FOPEN_NOFLUSH` | Kernel skips sending `flush` on close. |
| `FOPEN_PARALLEL_DIRECT_WRITES` | Allow concurrent direct-IO writes. |
| `FOPEN_PASSTHROUGH` | The file is backed by a real fd (passthrough mode). |

Usage:

```rust
fn open(&self, _req: &Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
    reply.opened(FileHandle::from(0), FopenFlags::FOPEN_DIRECT_IO);
}
```

### MountOption

| Variant | Description |
|---------|-------------|
| `FSName(String)` | Source name in mtab |
| `Subtype(String)` | Filesystem subtype in mtab |
| `CUSTOM(String)` | Pass-through for arbitrary mount options |
| `AllowOther` | Allow all users to access the filesystem |
| `AllowRoot` | Allow root to access the filesystem |
| `AutoUnmount` | Auto-unmount when mounting process exits (requires `AllowOther` or `AllowRoot`) |
| `DefaultPermissions` | Enable permission checking in the kernel |
| `Dev` / `NoDev` | Enable/disable device files |
| `Suid` / `NoSuid` | Honor/ignore set-user-id bits |
| `RO` / `RW` | Read-only / read-write |
| `Exec` / `NoExec` | Allow/disallow execution |
| `Atime` / `NoAtime` | Update/skip inode access time |
| `DirSync` | Synchronous directory modifications |
| `Sync` / `Async` | Synchronous / asynchronous I/O |

---

## 7. Session and Mount

### Blocking mount (simplest)

```rust
use fuser::{mount2, Filesystem};

fn main() {
    let fs = MyFilesystem::new();
    let config = fuser::Config {
        mount_options: vec![
            fuser::MountOption::RW,
            fuser::MountOption::FSName("myfs".to_string()),
            fuser::MountOption::AllowRoot,
        ],
        ..Default::default()
    };
    // Blocks until the filesystem is unmounted (e.g., via `fusermount3 -u /mnt/point`
    // or the process receiving SIGTERM).
    mount2(fs, "/mnt/point", &config).unwrap();
}
```

`mount2` signature:

```rust
pub fn mount2<FS: Filesystem, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &Config,
) -> Result<()>
```

### Background mount (non-blocking)

```rust
use fuser::spawn_mount2;

let config = fuser::Config {
    mount_options: vec![fuser::MountOption::RW],
    ..Default::default()
};
// Returns immediately. Filesystem runs in a background thread.
// Dropping `session` unmounts the filesystem.
let session = spawn_mount2(fs, "/mnt/point", &config).unwrap();

// ... do other work ...

// Explicit unmount (or just drop `session`):
drop(session);
```

`spawn_mount2` signature:

```rust
pub fn spawn_mount2<'a, FS: Filesystem + Send + 'static + 'a, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &Config,
) -> Result<BackgroundSession>
```

### Using Session directly

```rust
use fuser::Session;

let config = fuser::Config {
    mount_options: vec![fuser::MountOption::RW],
    ..Default::default()
};
let mut session = Session::new(fs, "/mnt/point", &config)?;

// Blocking event loop:
session.run()?;

// Or spawn a background thread:
let bg = session.spawn()?;
// bg.unmount_callable() returns a handle safe to use from signal handlers.
```

### Multi-threaded event loop

```rust
let config = fuser::Config {
    n_threads: Some(4),    // 4 event loop threads
    clone_fd: true,        // Use FUSE_DEV_IOC_CLONE for per-thread fds (Linux 4.5+)
    ..Default::default()
};
```

### Mounting without fusermount3 (direct /dev/fuse)

Build without the `libfuse` feature:

```toml
[dependencies]
fuser = { version = "0.17", default-features = false }
```

This removes the dependency on `libfuse3` / `fusermount3`. The crate opens `/dev/fuse` directly
and performs the `mount(2)` syscall itself. **Requires root or `CAP_SYS_ADMIN`** at runtime.

The FUSE **kernel module** (`fuse.ko`) must still be loaded. This only removes the userspace
C library dependency.

### Unmounting

- From outside: `fusermount3 -u /mnt/point` or `umount /mnt/point`
- Programmatically: `session.unmount()` or drop the `BackgroundSession`
- From a signal handler: use `session.unmount_callable()` to get a thread-safe unmount handle

---

## 8. Inode Conventions

- **Inode 1** (`FUSE_ROOT_ID`) is always the root directory of the filesystem. The kernel begins
  all path resolution here.
- Inode 0 is reserved and must not be used.
- Inodes are `u64` values wrapped in the `INodeNo` newtype.
- For a single-file filesystem, a common convention is:
  - Inode 1 = root directory (`/`)
  - Inode 2 = the single file

The kernel calls `lookup(parent=1, name="filename")` to resolve the file. Your `lookup` must
return a `FileAttr` with `ino: INodeNo::from(2)` and the correct `generation`.

---

## 9. TTL and Caching Behavior

The kernel caches the results of `lookup` (entry) and `getattr` (attributes) for the duration of
the TTL you return in the reply:

```rust
// In lookup:
reply.entry(&Duration::from_secs(1), &attr, Generation::from(0));
//           ^^^^^^^^^^^^^^^^^^^^^^^^
//           Entry TTL: how long the kernel caches the inode-to-name mapping

// In getattr:
reply.attr(&Duration::from_secs(1), &attr);
//          ^^^^^^^^^^^^^^^^^^^^^^^^
//          Attr TTL: how long the kernel caches the file attributes
```

**Guidance:**

| TTL | When to use |
|-----|------------|
| `Duration::ZERO` | Content changes unpredictably (e.g., backed by external data). Forces the kernel to re-query on every access. |
| `Duration::from_secs(1)` | Moderate caching. Good default for most cases. |
| `Duration::from_secs(3600)` or higher | Static content that never changes. |

**FOPEN_DIRECT_IO** further controls caching at the data level: when set, the kernel does not
cache file data in the page cache and every `read()`/`write()` goes directly to the filesystem.
This is independent of the attribute/entry TTL.

For a single-file filesystem wrapping encrypted data, use `Duration::ZERO` for TTL and
`FOPEN_DIRECT_IO` to ensure all reads and writes are always forwarded.

---

## 10. Minimal Single-File Filesystem Example

A read-only filesystem that exposes a single file `/hello.txt` containing `"Hello, FUSE!\n"`:

```rust
use fuser::{
    Config, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, ReplyOpen, ReplyStatfs, Request,
    mount2, FopenFlags, INodeNo, FileHandle, Generation, OpenFlags,
};
use std::ffi::OsStr;
use std::time::{Duration, SystemTime};

const ROOT_INO: INodeNo = INodeNo::from_raw(1);
const FILE_INO: INodeNo = INodeNo::from_raw(2);
const FILE_NAME: &str = "hello.txt";
const FILE_CONTENT: &[u8] = b"Hello, FUSE!\n";
const TTL: Duration = Duration::from_secs(1);

struct HelloFS;

impl HelloFS {
    fn root_attr(&self) -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_attr(&self) -> FileAttr {
        FileAttr {
            ino: FILE_INO,
            size: FILE_CONTENT.len() as u64,
            blocks: 1,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for HelloFS {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name == FILE_NAME {
            reply.entry(&TTL, &self.file_attr(), Generation::from(0));
        } else {
            reply.error(Errno::from(libc::ENOENT));
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino {
            ROOT_INO => reply.attr(&TTL, &self.root_attr()),
            FILE_INO => reply.attr(&TTL, &self.file_attr()),
            _ => reply.error(Errno::from(libc::ENOENT)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino == FILE_INO {
            // DIRECT_IO bypasses kernel page cache
            reply.opened(FileHandle::from(0), FopenFlags::FOPEN_DIRECT_IO);
        } else {
            reply.error(Errno::from(libc::EISDIR));
        }
    }

    fn read(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle,
        offset: u64, size: u32, _flags: OpenFlags, _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino == FILE_INO {
            let data = FILE_CONTENT;
            let start = offset as usize;
            if start >= data.len() {
                reply.data(&[]);
            } else {
                let end = std::cmp::min(start + size as usize, data.len());
                reply.data(&data[start..end]);
            }
        } else {
            reply.error(Errno::from(libc::ENOENT));
        }
    }

    fn readdir(
        &self, _req: &Request, ino: INodeNo, _fh: FileHandle,
        offset: u64, mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(Errno::from(libc::ENOTDIR));
            return;
        }

        let entries: Vec<(INodeNo, FileType, &str)> = vec![
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (FILE_INO, FileType::RegularFile, FILE_NAME),
        ];

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            // offset is i+1 so the kernel knows where to resume
            if reply.add(ino, (i + 1) as u64, kind, name) {
                break; // buffer full
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(
            1,    // blocks
            0,    // bfree
            0,    // bavail
            1,    // files
            0,    // ffree
            4096, // bsize
            255,  // namelen
            4096, // frsize
        );
    }
}

fn main() {
    let mountpoint = std::env::args().nth(1).expect("Usage: hellofs <mountpoint>");
    let config = Config {
        mount_options: vec![
            MountOption::RO,
            MountOption::FSName("hellofs".to_string()),
            MountOption::DefaultPermissions,
        ],
        ..Default::default()
    };
    mount2(HelloFS, &mountpoint, &config).unwrap();
}
```

**Usage:**

```bash
mkdir -p /tmp/mnt
cargo run -- /tmp/mnt &
cat /tmp/mnt/hello.txt     # prints "Hello, FUSE!"
ls -la /tmp/mnt/           # shows hello.txt
fusermount3 -u /tmp/mnt    # unmount
```

---

## 11. Static Musl Binaries

### Building a fully static binary

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Key considerations

1. **Disable the `libfuse` feature.** The default `libfuse` feature links to `libfuse3.so`
   dynamically, which breaks static linking. Use:

   ```toml
   [dependencies]
   fuser = { version = "0.17", default-features = false }
   ```

   This makes `fuser` pure Rust on Linux (no C library dependency for FUSE). The binary will
   open `/dev/fuse` directly and call `mount(2)` itself, requiring root.

2. **musl and `crt-static`.** The musl target statically links the C runtime by default
   (`+crt-static`). This is what you want for a single self-contained binary.

3. **No `pkg-config` needed.** Without `libfuse`, there is no C library to discover, so
   `pkg-config` is not required at build time.

4. **Known issue: duplicate symbols with `staticlib` crate type.** If you are building a
   `staticlib` (`.a`) rather than a binary, musl symbols may be included in the archive and
   conflict with the host libc. This is a general Rust+musl issue, not specific to `fuser`.
   For normal binary targets this is not a problem.

5. **Cross-compilation.** For cross-compiling to musl from a glibc host, use a musl toolchain
   (e.g., `musl-tools` on Debian) or a Docker-based builder like `rust-musl-builder`.

6. **Runtime requirement.** Even with a fully static binary, the target system must have the
   FUSE kernel module loaded (`modprobe fuse`) and `/dev/fuse` available.

---

## 12. Sources

- [fuser crate on docs.rs](https://docs.rs/fuser/latest/fuser/)
- [fuser Filesystem trait](https://docs.rs/fuser/latest/fuser/trait.Filesystem.html)
- [fuser FileAttr struct](https://docs.rs/fuser/latest/fuser/struct.FileAttr.html)
- [fuser FileType enum](https://docs.rs/fuser/latest/fuser/enum.FileType.html)
- [fuser MountOption enum](https://docs.rs/fuser/latest/fuser/enum.MountOption.html)
- [fuser FopenFlags](https://docs.rs/fuser/latest/fuser/struct.FopenFlags.html)
- [fuser Session struct](https://docs.rs/fuser/latest/fuser/struct.Session.html)
- [fuser Config struct](https://docs.rs/fuser/latest/fuser/struct.Config.html)
- [fuser KernelConfig struct](https://docs.rs/fuser/latest/fuser/struct.KernelConfig.html)
- [fuser mount2 function](https://docs.rs/fuser/latest/fuser/fn.mount2.html)
- [fuser spawn_mount2 function](https://docs.rs/fuser/latest/fuser/fn.spawn_mount2.html)
- [GitHub: cberner/fuser](https://github.com/cberner/fuser)
- [GitHub: fuser Cargo.toml](https://github.com/cberner/fuser/blob/master/Cargo.toml)
- [GitHub: fuser examples/simple.rs](https://github.com/cberner/fuser/blob/master/examples/simple.rs)
- [Rust musl static linking issues](https://github.com/rust-lang/rust/issues/82193)
