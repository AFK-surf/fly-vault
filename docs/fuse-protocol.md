# Linux FUSE Kernel Protocol Reference

A reference for implementing FUSE directly via `/dev/fuse` in Rust, without libfuse.
Targeted at a minimal single-file filesystem (e.g., a virtual file wrapping another file with
block-level encryption).

**Protocol version covered:** FUSE 7.x (kernel ABI defined in `include/uapi/linux/fuse.h`)

---

## Table of Contents

1. [Overview of /dev/fuse](#1-overview-of-devfuse)
2. [Session Initialization](#2-session-initialization)
3. [Message Format](#3-message-format)
4. [Required Opcodes](#4-required-opcodes)
5. [The fuse_attr Structure](#5-the-fuse_attr-structure)
6. [Root Inode Handling](#6-root-inode-handling)
7. [Mount Options](#7-mount-options)
8. [Error Handling](#8-error-handling)
9. [Sources](#9-sources)

---

## 1. Overview of /dev/fuse

FUSE (Filesystem in Userspace) is a client-server protocol. The Linux kernel is the **client**
and the userspace daemon is the **server**. Communication happens over the `/dev/fuse` character
device.

The protocol works as follows:

1. The daemon opens `/dev/fuse` to obtain a file descriptor.
2. The file descriptor is passed to `mount(2)` via the `fd=N` option.
3. The kernel sends requests by making them available to `read(2)` on the fd.
4. The daemon processes each request and sends a reply via `write(2)` on the same fd.

Each file descriptor is associated with exactly one FUSE connection. Opening `/dev/fuse`
a second time creates a separate, independent connection.

**Key rules:**

- Each request **must be read in a single `read(2)` call** -- the kernel writes complete
  messages atomically.
- Each reply **must be written in a single `write(2)` call**.
- Use **unbuffered I/O** only. Never use stdio or buffered wrappers.
- The read buffer should be at least `FUSE_MIN_READ_BUFFER` (8192) bytes. A practical
  minimum is `max_write + 4096` (to accommodate headers). 132 KiB is a safe default.

**Main loop pattern:**

```
loop {
    let n = read(fuse_fd, &mut buf)?;       // blocks until kernel sends a request
    let header = parse_fuse_in_header(&buf);
    match header.opcode {
        FUSE_INIT    => handle_init(...),
        FUSE_LOOKUP  => handle_lookup(...),
        FUSE_GETATTR => handle_getattr(...),
        // ...
        FUSE_DESTROY => break,               // clean shutdown
        _            => reply_error(ENOSYS),  // unsupported opcode
    }
}
```

---

## 2. Session Initialization

### 2.1 Opening /dev/fuse

```rust
let fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
```

This returns the control file descriptor used for all subsequent protocol messages.

### 2.2 Mounting

There are two approaches:

**A. Direct `mount(2)` syscall (requires root or user namespace):**

```rust
mount(
    "myfs",                          // source (arbitrary name)
    "/mnt/point",                    // target (mountpoint)
    "fuse.myfs",                     // filesystemtype: "fuse" or "fuse.<subtype>"
    0,                               // mountflags
    "fd=3,rootmode=40000,user_id=1000,group_id=1000"  // data (options)
);
```

Required mount data options:
- `fd=N` -- the `/dev/fuse` file descriptor number
- `rootmode=M` -- file mode of root inode in octal (040000 for a directory = `S_IFDIR`)
- `user_id=N` -- UID of the mount owner
- `group_id=N` -- GID of the mount owner

**B. Via fusermount helper (unprivileged):**

1. Create a `socketpair(AF_UNIX, SOCK_STREAM)` producing `(fd0, fd1)`.
2. Fork/exec `fusermount` with env var `_FUSE_COMMFD=<fd0>` and args like
   `fusermount /mnt/point`.
3. Receive the `/dev/fuse` fd from `fd1` via `recvmsg(2)` with `SCM_RIGHTS`.
4. Close both socket fds.

### 2.3 FUSE_INIT Handshake

Immediately after mounting, the kernel sends a `FUSE_INIT` request. This **must** be the
first message handled.

**Request (kernel -> daemon):**

```
fuse_in_header { opcode: FUSE_INIT (26), nodeid: 0, ... }
+
fuse_init_in {
    major:         u32,    // kernel's FUSE major version (7)
    minor:         u32,    // kernel's FUSE minor version
    max_readahead: u32,    // max readahead the kernel wants
    flags:         u32,    // capability flags the kernel supports (low 32 bits)
    flags2:        u32,    // capability flags the kernel supports (high 32 bits, v7.36+)
    unused:        [u32; 11],
}
```

**Response (daemon -> kernel):**

```
fuse_out_header { len: ..., error: 0, unique: <from request> }
+
fuse_init_out {
    major:                u32,    // daemon's major version (must be 7)
    minor:                u32,    // daemon's minor version (<= kernel's minor)
    max_readahead:        u32,    // negotiated max readahead (<= kernel's value)
    flags:                u32,    // accepted capability flags (low 32 bits)
    max_background:       u16,    // max background requests (0 = kernel default)
    congestion_threshold: u16,    // congestion threshold (0 = kernel default)
    max_write:            u32,    // max bytes per WRITE request
    time_gran:            u32,    // timestamp granularity in nanoseconds (v7.23+)
    max_pages:            u16,    // max pages per request (v7.28+)
    map_alignment:        u16,    // DAX alignment (v7.28+)
    flags2:               u32,    // accepted capability flags (high 32 bits, v7.36+)
    max_stack_depth:      u32,    // (v7.41+)
    request_timeout:      u16,    // seconds, 0 = no timeout (v7.42+)
    unused:               [u16; 11],
}
```

**Version negotiation rules:**

- If `kernel_major != 7`, the daemon cannot proceed. Reply with just `major = FUSE_KERNEL_VERSION`
  (a truncated response containing only the u32 major field) and disconnect.
- The daemon should reply with `major = 7` and `minor = min(kernel_minor, daemon_minor)`.
- The reply size can be truncated to match the minor version. Fields introduced in later
  versions can be omitted if the negotiated minor is earlier.

**Minimal INIT for a simple filesystem:**

```rust
// Minimal init reply
fuse_init_out {
    major: 7,
    minor: 31,           // a reasonable baseline; supports most features
    max_readahead: 65536,
    flags: 0,            // no special capabilities needed for minimal fs
    max_background: 0,
    congestion_threshold: 0,
    max_write: 65536,    // or 131072 (128 KiB) for better performance
    time_gran: 1,        // nanosecond precision
    // remaining fields zero
}
```

**Commonly relevant FUSE_INIT capability flags:**

| Flag | Value | Description |
|------|-------|-------------|
| `FUSE_ASYNC_READ` | `1 << 0` | Allow multiple pending read requests |
| `FUSE_BIG_WRITES` | `1 << 5` | Allow writes > 4 KiB (always enable for v7.x) |
| `FUSE_DO_READDIRPLUS` | `1 << 13` | Kernel may send FUSE_READDIRPLUS |
| `FUSE_READDIRPLUS_AUTO` | `1 << 14` | Kernel uses adaptive READDIR/READDIRPLUS |
| `FUSE_ASYNC_DIO` | `1 << 15` | Allow async direct I/O |
| `FUSE_WRITEBACK_CACHE` | `1 << 16` | Enable writeback cache for writes |
| `FUSE_NO_OPEN_SUPPORT` | `1 << 17` | Kernel won't send FUSE_OPEN (return ENOSYS) |
| `FUSE_NO_OPENDIR_SUPPORT` | `1 << 24` | Kernel won't send FUSE_OPENDIR |
| `FUSE_EXPLICIT_INVAL_DATA` | `1 << 25` | Only invalidate cached data when told to |
| `FUSE_MAX_PAGES` | `1 << 22` | `max_pages` field in init_out is valid |

---

## 3. Message Format

### 3.1 fuse_in_header (Request Header) -- 40 bytes

Every request from the kernel starts with this fixed-size header.

```c
struct fuse_in_header {
    uint32_t len;            // offset  0: total message length (header + body)
    uint32_t opcode;         // offset  4: FUSE operation code
    uint64_t unique;         // offset  8: unique request ID (must echo in reply)
    uint64_t nodeid;         // offset 16: inode / node ID (0 for FUSE_INIT)
    uint32_t uid;            // offset 24: caller's UID
    uint32_t gid;            // offset 28: caller's GID
    uint32_t pid;            // offset 32: caller's PID
    uint16_t total_extlen;   // offset 36: extension length in 8-byte units (v7.38+)
    uint16_t padding;        // offset 38: padding to 40 bytes
};
```

**Total size: 40 bytes.**

In protocol versions before 7.38, the last 4 bytes were a single `uint32_t padding`.
The split into `total_extlen` + `padding` is backward compatible (old kernels sent zero).

### 3.2 fuse_out_header (Response Header) -- 16 bytes

Every response from the daemon starts with this header.

```c
struct fuse_out_header {
    uint32_t len;     // offset  0: total response length (header + body)
    int32_t  error;   // offset  4: 0 for success, negative errno on error
    uint64_t unique;  // offset  8: must match the request's unique field
};
```

**Total size: 16 bytes.**

### 3.3 Reading Requests

```rust
let mut buf = [0u8; 132 * 1024]; // 132 KiB buffer
let n = read(fuse_fd, &mut buf)?;
// buf[0..40]  -> fuse_in_header
// buf[40..n]  -> opcode-specific body (may be empty)
```

- `read(2)` returns exactly one complete message.
- If the buffer is too small, `read(2)` returns `EIO`.
- If the filesystem is unmounted, `read(2)` returns `ENODEV`.

### 3.4 Writing Responses

```rust
// Success response with body:
let response = [out_header_bytes, body_bytes].concat();
write(fuse_fd, &response)?;

// Error response (header only, no body):
let out_header = fuse_out_header {
    len: 16,                // just the header
    error: -libc::ENOENT,  // negative errno
    unique: request_unique,
};
write(fuse_fd, &out_header)?;
```

- For error responses, `len` is always 16 (just the header). **Never include a body
  in an error response.**
- The `unique` field **must** match the request. Mismatched unique values cause `EINVAL`.

### 3.5 Opcodes That Require No Reply

These opcodes must **not** receive a reply:

| Opcode | Value | Notes |
|--------|-------|-------|
| `FUSE_FORGET` | 2 | Decrements lookup count; fire-and-forget |
| `FUSE_BATCH_FORGET` | 42 | Batch version of FORGET |

`FUSE_DESTROY` (38) also technically does not require a reply (the kernel does not wait
for one), but replying is harmless.

---

## 4. Required Opcodes

For a minimal single-file filesystem, you need to handle these opcodes. All unhandled
opcodes should get an error reply with `error = -ENOSYS`.

### 4.1 FUSE_INIT (opcode 26)

See [Section 2.3](#23-fuse_init-handshake) above.

### 4.2 FUSE_LOOKUP (opcode 1)

Resolves a filename within a directory to a node ID and attributes.

**Request body:** A null-terminated filename (no path separators). The `nodeid` in
`fuse_in_header` is the **parent directory**.

```
[fuse_in_header]  nodeid = parent directory's node ID
[name\0]          null-terminated filename, e.g. "secret.img\0"
```

There is no fixed struct for the request body -- it is just a C string.

**Response body:** `fuse_entry_out` (see below).

```c
struct fuse_entry_out {       // 128 bytes total (40 + 88 for fuse_attr)
    uint64_t nodeid;          // offset  0: assigned node ID for this entry
    uint64_t generation;      // offset  8: inode generation (for NFS-like revalidation)
    uint64_t entry_valid;     // offset 16: entry cache timeout (seconds)
    uint64_t attr_valid;      // offset 24: attribute cache timeout (seconds)
    uint32_t entry_valid_nsec;// offset 32: entry cache timeout (nanoseconds part)
    uint32_t attr_valid_nsec; // offset 36: attribute cache timeout (nanoseconds part)
    struct fuse_attr attr;    // offset 40: file attributes (88 bytes)
};
```

**Total response:** 16 (header) + 128 (entry_out) = **144 bytes** (with v7.9+ fuse_attr).

**Semantics:**

- Each successful LOOKUP increments the kernel's **lookup count** for that node.
  The kernel later sends `FUSE_FORGET` to decrement it.
- Returning `nodeid = 0` signals a **negative lookup** (cacheable "does not exist").
- The `generation` field must be unique per (nodeid reuse). If you never reuse node IDs,
  generation can always be 0.
- For a single-file filesystem: the root directory (inode 1) will receive LOOKUP for
  the virtual filename. Reply with inode 2 (or any non-1 value) and the file's attributes.
  Reply with `error = -ENOENT` for any other name.

### 4.3 FUSE_FORGET (opcode 2)

Decrements the kernel's lookup reference count for a node. **No reply.**

**Request body:**

```c
struct fuse_forget_in {
    uint64_t nlookup;   // number of lookups to forget
};
```

You must track lookup counts if you dynamically allocate node state. For a static
single-file filesystem (fixed inodes 1 and 2), you can safely ignore the count but
still must not send a reply.

### 4.4 FUSE_GETATTR (opcode 3)

Returns file/directory attributes for a given node.

**Request body:**

```c
struct fuse_getattr_in {
    uint32_t getattr_flags;   // FUSE_GETATTR_FH if fh is valid
    uint32_t dummy;
    uint64_t fh;              // file handle (only if FUSE_GETATTR_FH set)
};
```

`getattr_flags` bit 0 (`FUSE_GETATTR_FH = 1`): if set, `fh` contains a valid file handle
from a prior OPEN.

**Response body:**

```c
struct fuse_attr_out {
    uint64_t attr_valid;       // offset  0: attribute cache timeout (seconds)
    uint32_t attr_valid_nsec;  // offset  8: cache timeout (nanoseconds part)
    uint32_t dummy;            // offset 12: padding
    struct fuse_attr attr;     // offset 16: the attributes (88 bytes)
};
```

**Total response:** 16 (header) + 104 (attr_out) = **120 bytes**.

**For a single-file filesystem:**

- `nodeid == 1` -> return directory attributes (`mode = S_IFDIR | 0755`, `nlink = 2`)
- `nodeid == 2` -> return file attributes (`mode = S_IFREG | 0644`, `size = file_size`)

### 4.5 FUSE_OPEN (opcode 14)

Opens a file. The kernel sends this when a process calls `open(2)` on a file
in the FUSE mount.

**Request body:**

```c
struct fuse_open_in {
    uint32_t flags;       // open(2) flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
    uint32_t open_flags;  // FUSE-specific open flags (v7.12+)
};
```

The `flags` field contains the standard `open(2)` flags. The daemon should check
these for access permissions (unless `default_permissions` mount option is used).

**Response body:**

```c
struct fuse_open_out {
    uint64_t fh;          // file handle (opaque, stored by kernel, sent in future ops)
    uint32_t open_flags;  // FOPEN_* flags (see below)
    int32_t  backing_id;  // for passthrough mode (v7.38+), otherwise padding/zero
};
```

**Total response:** 16 (header) + 16 (open_out) = **32 bytes**.

**FOPEN flags** (set in `open_flags` of the response):

| Flag | Value | Description |
|------|-------|-------------|
| `FOPEN_DIRECT_IO` | `1 << 0` | Bypass page cache; every read/write goes to daemon |
| `FOPEN_KEEP_CACHE` | `1 << 1` | Don't invalidate page cache on open |
| `FOPEN_NONSEEKABLE` | `1 << 2` | File is not seekable |
| `FOPEN_CACHE_DIR` | `1 << 3` | Allow caching directory contents |
| `FOPEN_STREAM` | `1 << 4` | No file position (like a pipe) |
| `FOPEN_NOFLUSH` | `1 << 5` | Don't flush data cache on close |
| `FOPEN_PARALLEL_DIRECT_WRITES` | `1 << 6` | Allow concurrent direct writes |
| `FOPEN_PASSTHROUGH` | `1 << 7` | Passthrough read/write to backing file |

**For an encryption layer:** Use `FOPEN_DIRECT_IO` to bypass the kernel page cache.
This ensures every read/write is forwarded to the daemon, which is essential when
the daemon transforms data (encryption/decryption). Without this flag, the kernel
may serve stale cached plaintext.

### 4.6 FUSE_READ (opcode 15)

Reads data from an open file.

**Request body:**

```c
struct fuse_read_in {
    uint64_t fh;          // file handle from OPEN
    uint64_t offset;      // byte offset to read from
    uint32_t size;        // number of bytes requested
    uint32_t read_flags;  // read-specific flags
    uint64_t lock_owner;  // lock owner (if applicable)
    uint32_t flags;       // open(2) flags
    uint32_t padding;
};
```

**Total: 40 bytes.**

**Response body:** The raw bytes of file data (up to `size` bytes). The response length
is the `fuse_out_header` (16 bytes) + actual data bytes returned.

```
[fuse_out_header]  len = 16 + actual_bytes_read, error = 0
[data bytes]       the file content (may be shorter than requested)
```

- Returning fewer bytes than requested signals EOF (like `read(2)` semantics).
- Returning 0 bytes (just the header with `len = 16`) signals EOF at the given offset.

### 4.7 FUSE_WRITE (opcode 16)

Writes data to an open file.

**Request body:**

```c
struct fuse_write_in {
    uint64_t fh;          // file handle from OPEN
    uint64_t offset;      // byte offset to write at
    uint32_t size;        // number of bytes to write
    uint32_t write_flags; // FUSE_WRITE_CACHE (1): writeback cache write
    uint64_t lock_owner;  // lock owner (if applicable)
    uint32_t flags;       // open(2) flags
    uint32_t padding;
};
// Immediately followed by `size` bytes of write data.
```

**Total header: 40 bytes**, then `size` bytes of data.

The write data starts at offset 80 in the overall message buffer (40 bytes `fuse_in_header`
+ 40 bytes `fuse_write_in`).

**Response body:**

```c
struct fuse_write_out {
    uint32_t size;     // number of bytes actually written
    uint32_t padding;
};
```

**Total response:** 16 (header) + 8 (write_out) = **24 bytes**.

### 4.8 FUSE_RELEASE (opcode 18)

Called when the last file descriptor referring to a file handle is closed.

**Request body:**

```c
struct fuse_release_in {
    uint64_t fh;             // file handle to release
    uint32_t flags;          // open(2) flags
    uint32_t release_flags;  // FUSE_RELEASE_FLUSH (1) if flush is needed
    uint64_t lock_owner;     // lock owner
};
```

**Response:** Empty body (just `fuse_out_header` with `error = 0`, `len = 16`).

The kernel guarantees exactly one RELEASE for every OPEN, even if the process crashes.

### 4.9 FUSE_FLUSH (opcode 25)

Called on every `close(2)`, which may happen multiple times if the fd was `dup(2)`'d.
(RELEASE is called only after the last close.)

**Request body:**

```c
struct fuse_flush_in {
    uint64_t fh;          // file handle
    uint32_t unused;
    uint32_t padding;
    uint64_t lock_owner;
};
```

**Response:** Empty body (just `fuse_out_header` with `error = 0`, `len = 16`).

For a simple filesystem, FLUSH can just return success. Errors from FLUSH are returned
to the `close(2)` caller.

### 4.10 FUSE_FSYNC (opcode 20)

Flushes dirty data/metadata to stable storage.

**Request body:**

```c
struct fuse_fsync_in {
    uint64_t fh;            // file handle
    uint32_t fsync_flags;   // bit 0: FUSE_FSYNC_FDATASYNC (data-only sync)
    uint32_t padding;
};
```

**Response:** Empty body (just `fuse_out_header` with `error = 0`, `len = 16`).

If `fsync_flags & 1` is set, only data (not metadata) needs to be synced (like
`fdatasync(2)`).

### 4.11 FUSE_OPENDIR (opcode 27)

Opens a directory for reading. Uses the same structures as FUSE_OPEN.

**Request body:** `fuse_open_in` (same as FUSE_OPEN).

**Response body:** `fuse_open_out` (same as FUSE_OPEN).

For a single-file filesystem, return `fh = 0` and `open_flags = 0`.

If you return `-ENOSYS` and the kernel supports `FUSE_NO_OPENDIR_SUPPORT`, the
kernel will stop sending OPENDIR/RELEASEDIR and cache readdir results.

### 4.12 FUSE_READDIR (opcode 28)

Lists directory entries.

**Request body:** `fuse_read_in` (same as FUSE_READ).

The `offset` field is an opaque cookie. On the first call it is 0. For subsequent
calls, it is the `off` value from the last `fuse_dirent` entry returned.

**Response body:** A packed sequence of `fuse_dirent` entries:

```c
struct fuse_dirent {
    uint64_t ino;       // inode number
    uint64_t off;       // offset cookie for next readdir call
    uint32_t namelen;   // length of name (without null terminator)
    uint32_t type;      // file type (DT_REG, DT_DIR, etc.) -- upper 4 bits of mode >> 12
    char     name[];    // filename (NOT null-terminated, length = namelen)
    // Padded to 8-byte boundary
};
```

**Alignment:** Each entry is padded to an 8-byte boundary:

```c
#define FUSE_NAME_OFFSET    24   // offsetof(fuse_dirent, name)
#define FUSE_DIRENT_ALIGN(x)  (((x) + 7) & ~7)
#define FUSE_DIRENT_SIZE(d)   FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)
```

Entries are packed sequentially in the response buffer. The total data length must
not exceed the `size` field from `fuse_read_in`. Returning 0 bytes signals end of
directory.

**Example for a single-file filesystem (root dir contains ".", "..", "secret.img"):**

```
Entry 1: ino=1,  off=1, type=DT_DIR, name="."
Entry 2: ino=1,  off=2, type=DT_DIR, name=".."
Entry 3: ino=2,  off=3, type=DT_REG, name="secret.img"
```

### 4.13 FUSE_READDIRPLUS (opcode 44)

Enhanced readdir that also returns full attributes (avoids subsequent LOOKUP/GETATTR
calls). Only sent if `FUSE_DO_READDIRPLUS` or `FUSE_READDIRPLUS_AUTO` is negotiated
in INIT.

**Request body:** `fuse_read_in` (same as READDIR).

**Response body:** A packed sequence of `fuse_direntplus` entries:

```c
struct fuse_direntplus {
    struct fuse_entry_out entry_out;  // full entry (128 bytes, same as LOOKUP response)
    struct fuse_dirent    dirent;     // directory entry (variable length)
};
```

**Alignment:**

```c
#define FUSE_NAME_OFFSET_DIRENTPLUS  offsetof(struct fuse_direntplus, dirent.name)
#define FUSE_DIRENTPLUS_SIZE(d)      FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)
```

Each `fuse_direntplus` increments the lookup count for that node (like LOOKUP).
To skip an entry (e.g., "." and ".."), set `entry_out.nodeid = 0` and the kernel
will not cache it.

If you don't want to support READDIRPLUS, either don't negotiate the flag in INIT
or return `-ENOSYS`.

### 4.14 FUSE_RELEASEDIR (opcode 29)

Called when the directory handle is closed. Uses `fuse_release_in` (same as FUSE_RELEASE).

**Response:** Empty body (just `fuse_out_header` with `error = 0`, `len = 16`).

### 4.15 FUSE_STATFS (opcode 17)

Returns filesystem statistics (called by `statfs(2)` / `df`).

**Request body:** Empty (no body after `fuse_in_header`).

**Response body:**

```c
struct fuse_statfs_out {
    struct fuse_kstatfs st;
};

struct fuse_kstatfs {
    uint64_t blocks;      // offset  0: total data blocks
    uint64_t bfree;       // offset  8: free blocks
    uint64_t bavail;      // offset 16: free blocks for unprivileged users
    uint64_t files;       // offset 24: total inodes
    uint64_t ffree;       // offset 32: free inodes
    uint32_t bsize;       // offset 40: filesystem block size
    uint32_t namelen;     // offset 44: maximum filename length
    uint32_t frsize;      // offset 48: fragment size (set equal to bsize)
    uint32_t padding;     // offset 52: padding
    uint32_t spare[6];    // offset 56: reserved (zero-fill)
};
```

**Total: 80 bytes** for `fuse_kstatfs`, so response is 16 + 80 = **96 bytes**.

**Tip:** Set `frsize = bsize` to avoid incorrect `df` output. All kernel filesystems
do this.

**Minimal example:**

```rust
fuse_kstatfs {
    blocks: 1,
    bfree: 0,
    bavail: 0,
    files: 2,     // root dir + 1 file
    ffree: 0,
    bsize: 4096,
    namelen: 255,
    frsize: 4096,
    padding: 0,
    spare: [0; 6],
}
```

### 4.16 FUSE_DESTROY (opcode 38)

Sent when the filesystem is unmounted. The daemon should clean up. No reply is
required (but replying is harmless).

### 4.17 FUSE_ACCESS (opcode 34)

Permission check. If you don't want to handle this, return `-ENOSYS` and the kernel
will stop sending it (falling back to mode-based checks if `default_permissions` is set).

### 4.18 FUSE_SETATTR (opcode 4)

Set file attributes (chmod, chown, truncate, utimes). For a read-write encrypted file,
you may need to handle at least truncate (`valid & FATTR_SIZE`).

**Request body:**

```c
struct fuse_setattr_in {
    uint32_t valid;        // bitmask of which fields to set
    uint32_t padding;
    uint64_t fh;           // file handle (if FATTR_FH set)
    uint64_t size;         // new size (if FATTR_SIZE set)
    uint64_t lock_owner;   // unused
    uint64_t atime;        // new atime (if FATTR_ATIME set)
    uint64_t mtime;        // new mtime (if FATTR_MTIME set)
    uint64_t ctime;        // new ctime (if FATTR_CTIME set)
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;         // new mode (if FATTR_MODE set)
    uint32_t unused4;
    uint32_t uid;          // new uid (if FATTR_UID set)
    uint32_t gid;          // new gid (if FATTR_GID set)
    uint32_t unused5;
};
```

**Response:** `fuse_attr_out` (same as GETATTR).

**FATTR valid bits:**

| Bit | Value | Field |
|-----|-------|-------|
| `FATTR_MODE` | `1 << 0` | mode |
| `FATTR_UID` | `1 << 1` | uid |
| `FATTR_GID` | `1 << 2` | gid |
| `FATTR_SIZE` | `1 << 3` | size (truncate) |
| `FATTR_ATIME` | `1 << 4` | atime |
| `FATTR_MTIME` | `1 << 5` | mtime |
| `FATTR_FH` | `1 << 6` | fh is valid |
| `FATTR_ATIME_NOW` | `1 << 7` | set atime to now |
| `FATTR_MTIME_NOW` | `1 << 8` | set mtime to now |
| `FATTR_LOCKOWNER` | `1 << 9` | lock_owner is valid |
| `FATTR_CTIME` | `1 << 10` | ctime |

---

## 5. The fuse_attr Structure

This structure carries file metadata and is embedded in `fuse_attr_out`, `fuse_entry_out`,
and `fuse_direntplus`.

```c
struct fuse_attr {            // 88 bytes total
    uint64_t ino;             // offset  0: inode number
    uint64_t size;            // offset  8: file size in bytes
    uint64_t blocks;          // offset 16: number of 512-byte blocks
    uint64_t atime;           // offset 24: access time (seconds since epoch)
    uint64_t mtime;           // offset 32: modification time (seconds)
    uint64_t ctime;           // offset 40: change time (seconds)
    uint32_t atimensec;       // offset 48: atime nanoseconds
    uint32_t mtimensec;       // offset 52: mtime nanoseconds
    uint32_t ctimensec;       // offset 56: ctime nanoseconds
    uint32_t mode;            // offset 60: file type and permissions
    uint32_t nlink;           // offset 64: number of hard links
    uint32_t uid;             // offset 68: owner UID
    uint32_t gid;             // offset 72: owner GID
    uint32_t rdev;            // offset 76: device ID (for device files)
    uint32_t blksize;         // offset 80: preferred I/O block size (v7.9+)
    uint32_t flags;           // offset 84: per-inode flags (v7.9+)
};
```

**Total size: 88 bytes** (since protocol v7.9; earlier versions were 80 bytes without
`blksize` and `flags`).

**Key mode values:**

| Constant | Octal | Description |
|----------|-------|-------------|
| `S_IFDIR` | `0o040000` | Directory |
| `S_IFREG` | `0o100000` | Regular file |
| `S_IFLNK` | `0o120000` | Symbolic link |

Permissions are OR'd in: e.g., `S_IFDIR | 0o755` for a world-readable directory,
`S_IFREG | 0o644` for a regular file.

**nlink conventions:**

- Directories: `nlink = 2` (self "." + parent ".."). Add 1 for each subdirectory.
- Regular files: `nlink = 1`.

**blocks calculation:**

```rust
let blocks = (size + 511) / 512;  // number of 512-byte blocks
```

---

## 6. Root Inode Handling

The root directory always has **node ID 1** (`FUSE_ROOT_ID`). This is hardcoded in
the kernel and cannot be changed.

The kernel will never send `FUSE_LOOKUP` for the root inode itself -- it already knows
node 1 is the root. Instead, it sends `FUSE_GETATTR` with `nodeid = 1` to get the root's
attributes.

**Root directory attributes:**

```rust
fuse_attr {
    ino: 1,
    size: 0,                    // or 4096 (some implementations use block size)
    blocks: 0,
    atime: now, mtime: now, ctime: now,
    atimensec: 0, mtimensec: 0, ctimensec: 0,
    mode: S_IFDIR | 0o755,     // 0o040755
    nlink: 2,                   // "." and ".."
    uid: mount_uid,
    gid: mount_gid,
    rdev: 0,
    blksize: 4096,
    flags: 0,
}
```

**Typical request flow when a user does `cat /mnt/fuse/secret.img`:**

1. Kernel sends `FUSE_GETATTR(nodeid=1)` -- daemon returns root directory attrs
2. Kernel sends `FUSE_LOOKUP(nodeid=1, name="secret.img")` -- daemon returns entry with nodeid=2
3. Kernel sends `FUSE_OPEN(nodeid=2)` -- daemon returns file handle
4. Kernel sends `FUSE_READ(nodeid=2, fh=..., offset=0, size=...)` -- daemon returns data
5. (possibly more READs for large files)
6. Kernel sends `FUSE_FLUSH(nodeid=2)` -- daemon returns success
7. Kernel sends `FUSE_RELEASE(nodeid=2)` -- daemon returns success

---

## 7. Mount Options

### 7.1 Kernel Mount Options (passed in `mount(2)` data string)

| Option | Description |
|--------|-------------|
| `fd=N` | `/dev/fuse` file descriptor **(required)** |
| `rootmode=M` | Root inode mode in octal, e.g., `40000` for `S_IFDIR` **(required)** |
| `user_id=N` | Mount owner UID **(required)** |
| `group_id=N` | Mount owner GID **(required)** |
| `default_permissions` | Enable kernel permission checking based on file mode |
| `allow_other` | Allow access by users other than mount owner |
| `max_read=N` | Max size of read requests (default: unlimited, capped at 128 KiB) |
| `blksize=N` | Block size for fuseblk mounts (default: 512) |

### 7.2 Per-Open Flags (via FUSE_OPEN response)

| Flag | Effect |
|------|--------|
| `FOPEN_DIRECT_IO` | Bypass page cache completely. Every I/O hits the daemon. Essential for encryption. |
| `FOPEN_KEEP_CACHE` | Don't invalidate cached data when file is opened. |
| `FOPEN_NONSEEKABLE` | Mark file as non-seekable (pipe-like). |

### 7.3 Recommendations for an Encryption Layer

- Use `default_permissions` to let the kernel handle permission checks.
- Use `FOPEN_DIRECT_IO` in every OPEN response to ensure all reads/writes go through
  the daemon for encryption/decryption.
- Set `max_write` to a multiple of your encryption block size in FUSE_INIT.
- Consider `allow_other` if the encrypted mount needs to be accessed by other users.

---

## 8. Error Handling

### 8.1 Error Response Format

To return an error, send only the `fuse_out_header` with the `error` field set to
a **negative errno value** and `len = 16`:

```c
struct fuse_out_header {
    uint32_t len;     // always 16 for error responses
    int32_t  error;   // negative errno, e.g., -ENOENT = -2
    uint64_t unique;  // from the request
};
```

**Never include a body in an error response.**

### 8.2 Common errno Values

| errno | Value | When to use |
|-------|-------|-------------|
| `ENOSYS` | -38 | Opcode not implemented (kernel may stop sending it) |
| `ENOENT` | -2 | File not found (LOOKUP for unknown name) |
| `EIO` | -5 | I/O error (encryption/decryption failure, backing file error) |
| `EACCES` | -13 | Permission denied |
| `ENOTDIR` | -20 | Not a directory (LOOKUP on a file node) |
| `EISDIR` | -21 | Is a directory (OPEN on a directory with FUSE_OPEN) |
| `EINVAL` | -22 | Invalid argument |
| `ENOSPC` | -28 | No space left on device |
| `EROFS` | -30 | Read-only filesystem |
| `ENOTEMPTY`| -39 | Directory not empty |

### 8.3 Special ENOSYS Behavior

Returning `ENOSYS` for certain opcodes has special meaning -- the kernel treats it
as "this operation is permanently unsupported" and will **stop sending that opcode**
for the lifetime of the mount:

- `FUSE_OPEN` + `ENOSYS` -> kernel stops sending OPEN/RELEASE (v7.11+, with flag)
- `FUSE_OPENDIR` + `ENOSYS` -> kernel stops sending OPENDIR/RELEASEDIR (v7.23+, with flag)
- `FUSE_ACCESS` + `ENOSYS` -> kernel stops sending ACCESS
- `FUSE_FLUSH` + `ENOSYS` -> kernel stops sending FLUSH
- `FUSE_FSYNC` + `ENOSYS` -> kernel stops sending FSYNC

This is useful for performance: return `ENOSYS` for operations you truly don't need.

### 8.4 /dev/fuse Read/Write Errors

These errors come from the `read(2)` and `write(2)` calls on `/dev/fuse` itself:

| Error from `read` | Meaning |
|--------------------|---------|
| `ENODEV` | Filesystem has been unmounted. Exit the main loop. |
| `EINTR` | Interrupted by signal. Retry the read. |
| `EIO` | Buffer too small for the request. Increase buffer size. |

| Error from `write` | Meaning |
|---------------------|---------|
| `EINVAL` | Malformed reply (wrong `unique`, bad `len`, etc.) |
| `ENOENT` | Request was interrupted/aborted before reply. Ignore. |

---

## 9. Sources

- [Linux kernel `include/uapi/linux/fuse.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/fuse.h) -- Definitive protocol structures and constants
- [fuse(4) Linux man page](https://man7.org/linux/man-pages/man4/fuse.4.html) -- Official /dev/fuse device documentation
- [FUSE kernel documentation](https://www.kernel.org/doc/html/next/filesystems/fuse/fuse.html) -- Kernel internals and request lifecycle
- [The FUSE Protocol (John Millikin)](https://john-millikin.com/the-fuse-protocol) -- Comprehensive protocol walkthrough
- [The FUSE Wire Protocol (nuetzlich.net)](https://nuetzlich.net/the-fuse-wire-protocol/) -- Wire format details
- [FUSE Protocol Tutorial (pts.blog)](http://ptspts.blogspot.com/2009/11/fuse-protocol-tutorial-for-linux-26.html) -- Step-by-step server implementation without libfuse
- [libfuse Protocol Sketch (GitHub Wiki)](https://github.com/libfuse/libfuse/wiki/Protocol-Sketch) -- Protocol overview from the libfuse project
- [libfuse `fuse_kernel.h`](https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h) -- Userspace copy of the kernel header
- [Fuse I/O Modes (kernel docs)](https://docs.kernel.org/next/filesystems/fuse/fuse-io.html) -- direct_io and writeback cache documentation
