# Linux Loop Device Setup

Reference document covering the kernel interfaces for loop device management:
creating loop devices, associating backing files, configuring block size and
direct I/O, and doing all of this from Rust.

## Sources

- [loop(4) man page](https://man7.org/linux/man-pages/man4/loop.4.html)
- [linux/include/uapi/linux/loop.h (kernel source)](https://github.com/torvalds/linux/blob/master/include/uapi/linux/loop.h)
- [linux/drivers/block/loop.c (kernel source)](https://github.com/torvalds/linux/blob/master/drivers/block/loop.c)
- [ioctl_number documentation (kernel)](https://docs.kernel.org/userspace-api/ioctl/ioctl-number.html)
- [nix crate docs -- ioctl macros](https://docs.rs/nix/latest/nix/sys/ioctl/index.html)
- [nix crate docs -- mount](https://docs.rs/nix/latest/nix/mount/fn.mount.html)
- [systemd loop-util.c (reference implementation)](https://github.com/systemd/systemd/blob/main/src/shared/loop-util.c)

---

## 1. /dev/loop-control and LOOP_CTL_GET_FREE

Since Linux 3.1, `/dev/loop-control` is a control device that manages loop
device allocation:

```c
int ctlfd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);

// Get the number of a free loop device (allocates one if needed)
int devnr = ioctl(ctlfd, LOOP_CTL_GET_FREE);
// devnr is now e.g. 0, 1, 2, ...

close(ctlfd);
```

`LOOP_CTL_GET_FREE` takes no argument and returns the device number on success.
The kernel allocates a new `/dev/loopN` device node if all existing ones are in
use.

Other loop-control ioctls:

| ioctl              | Value    | Description                                |
|--------------------|----------|--------------------------------------------|
| `LOOP_CTL_ADD`     | `0x4C80` | Add a loop device with a specific number   |
| `LOOP_CTL_REMOVE`  | `0x4C81` | Remove a specific loop device              |
| `LOOP_CTL_GET_FREE`| `0x4C82` | Allocate or find a free loop device        |

---

## 2. Opening /dev/loopN

Once you have a device number from `LOOP_CTL_GET_FREE`, open the corresponding
device node:

```c
char loopdev[64];
snprintf(loopdev, sizeof(loopdev), "/dev/loop%d", devnr);
int loopfd = open(loopdev, O_RDWR | O_CLOEXEC);
```

The loop device starts in a detached state (no backing file). It cannot be
mounted or read from until a backing file is associated via `LOOP_SET_FD`.

---

## 3. LOOP_SET_FD -- Associate a Backing File

```c
int backingfd = open("/path/to/image.ext4", O_RDWR | O_CLOEXEC);
int ret = ioctl(loopfd, LOOP_SET_FD, backingfd);
```

- The third argument is the file descriptor of the backing file (passed as an
  integer, not a pointer).
- After this call, reads/writes to `/dev/loopN` are translated to reads/writes
  at corresponding offsets in the backing file.
- The backing file must remain open until the loop device is detached, or the
  kernel holds its own reference (the caller can close `backingfd` after
  `LOOP_SET_FD`).

**Race condition note** (from systemd source): Between `LOOP_CTL_GET_FREE` and
`LOOP_SET_FD`, another process may claim the same loop device. Robust code
should retry in a loop:

```c
for (;;) {
    int devnr = ioctl(ctlfd, LOOP_CTL_GET_FREE);
    // open /dev/loopN ...
    if (ioctl(loopfd, LOOP_SET_FD, backingfd) == 0)
        break;  // success
    if (errno != EBUSY)
        handle_error();
    close(loopfd);
    // retry
}
```

---

## 4. LOOP_SET_STATUS64 / loop_info64

After associating a backing file, use `LOOP_SET_STATUS64` to configure the loop
device:

```c
#include <linux/loop.h>

struct loop_info64 info;
memset(&info, 0, sizeof(info));

info.lo_offset    = 0;          // byte offset into backing file
info.lo_sizelimit = 0;          // 0 = use entire file
info.lo_flags     = LO_FLAGS_AUTOCLEAR; // auto-detach on last close

strncpy((char *)info.lo_file_name, "/path/to/image.ext4", LO_NAME_SIZE - 1);

int ret = ioctl(loopfd, LOOP_SET_STATUS64, &info);
```

### loop_info64 Structure

```c
struct loop_info64 {
    __u64  lo_device;            // backing device (read-only, set by kernel)
    __u64  lo_inode;             // backing inode (read-only, set by kernel)
    __u64  lo_rdevice;           // read-only
    __u64  lo_offset;            // byte offset into backing file
    __u64  lo_sizelimit;         // max bytes to use (0 = entire file)
    __u32  lo_number;            // loop device number (read-only)
    __u32  lo_encrypt_type;      // obsolete, ignored
    __u32  lo_encrypt_key_size;  // write-only, obsolete
    __u32  lo_flags;             // LO_FLAGS_* bitmask
    __u8   lo_file_name[64];     // backing file name (cosmetic)
    __u8   lo_crypt_name[64];    // obsolete
    __u8   lo_encrypt_key[32];   // write-only, obsolete
    __u64  lo_init[2];           // reserved
};
```

### Settable lo_flags

| Flag                    | Value | Description                                 | Settable via SET_STATUS |
|-------------------------|-------|---------------------------------------------|-------------------------|
| `LO_FLAGS_READ_ONLY`   | 1     | Loop device is read-only                    | No (kernel sets)        |
| `LO_FLAGS_AUTOCLEAR`   | 4     | Auto-detach on last close (since 2.6.25)    | Yes                     |
| `LO_FLAGS_PARTSCAN`    | 8     | Scan for partitions (since 3.2)             | Yes                     |
| `LO_FLAGS_DIRECT_IO`   | 16    | Direct I/O to backing file (since 4.10)     | No (use separate ioctl) |

**Important**: Only `LO_FLAGS_AUTOCLEAR` and `LO_FLAGS_PARTSCAN` can be changed
via `LOOP_SET_STATUS64`. `LO_FLAGS_DIRECT_IO` must be set via the dedicated
`LOOP_SET_DIRECT_IO` ioctl (or via `LOOP_CONFIGURE`).

### EAGAIN on LOOP_SET_STATUS64

Since kernel 5.0, `LOOP_SET_STATUS64` can return `EAGAIN` if `lo_offset` or
`lo_sizelimit` is changed while another process (e.g., udev) is reading the
device. Retry on `EAGAIN`.

---

## 5. LOOP_CLR_FD -- Detach

```c
ioctl(loopfd, LOOP_CLR_FD, 0);
```

Disassociates the loop device from its backing file. After this, the loop device
returns to the free pool. Takes no meaningful argument.

If `LO_FLAGS_AUTOCLEAR` was set, detachment happens automatically when the last
file descriptor to the loop device is closed.

---

## 6. Direct I/O Mode (LOOP_SET_DIRECT_IO / LO_FLAGS_DIRECT_IO)

Direct I/O bypasses the kernel page cache for I/O between the loop device and
its backing file. This avoids double-caching when the filesystem on the loop
device also uses the page cache.

```c
unsigned long dio = 1;  // 1 = enable, 0 = disable
ioctl(loopfd, LOOP_SET_DIRECT_IO, dio);
```

Requirements:
- Available since Linux 4.10.
- The backing file's filesystem must support direct I/O.
- The backing file and loop device block sizes must be compatible.
- Returns `EINVAL` if the backing store does not support direct I/O.

---

## 7. Block Size (LOOP_SET_BLOCK_SIZE)

```c
unsigned long blksz = 4096;
ioctl(loopfd, LOOP_SET_BLOCK_SIZE, blksz);
```

- Available since Linux 4.14.
- `blksz` must be a power of two in the range `[512, PAGE_SIZE]`.
- Returns `EINVAL` if the value is out of range or not a power of two.
- Typically set to 4096 to match the filesystem block size and enable direct I/O.

Alternatively, use `LOOP_CONFIGURE` (see below) to set block size atomically
with the backing file association.

---

## 8. LOOP_CONFIGURE -- All-in-One Setup (Linux 5.8+)

`LOOP_CONFIGURE` combines `LOOP_SET_FD` + `LOOP_SET_STATUS64` +
`LOOP_SET_BLOCK_SIZE` + `LOOP_SET_DIRECT_IO` into a single atomic operation:

```c
struct loop_config config;
memset(&config, 0, sizeof(config));

config.fd         = backingfd;
config.block_size = 4096;

config.info.lo_offset    = 0;
config.info.lo_sizelimit = 0;
config.info.lo_flags     = LO_FLAGS_DIRECT_IO | LO_FLAGS_AUTOCLEAR;
strncpy((char *)config.info.lo_file_name, "/path/to/image.ext4", LO_NAME_SIZE - 1);

int ret = ioctl(loopfd, LOOP_CONFIGURE, &config);
```

### loop_config Structure

```c
struct loop_config {
    __u32              fd;           // backing file descriptor
    __u32              block_size;   // logical block size (0 = default 512)
    struct loop_info64 info;         // full loop_info64
    __u64              __reserved[8];
};
```

Advantages over the multi-step approach:
- Atomic -- no window where udev can probe a half-configured device.
- `LO_FLAGS_DIRECT_IO` can be set directly in `info.lo_flags` (unlike
  `LOOP_SET_STATUS64`).
- `LO_FLAGS_READ_ONLY` can be requested via `info.lo_flags`.
- Block size is set before any I/O occurs.

---

## 9. The Full Flow

### Multi-step (works on Linux < 5.8)

```
open("/dev/loop-control")
    |
    v
ioctl(LOOP_CTL_GET_FREE) --> devnr
    |
    v
open("/dev/loopN")
    |
    v
open("/path/to/image.ext4") --> backingfd
    |
    v
ioctl(loopfd, LOOP_SET_FD, backingfd)
    |
    v
ioctl(loopfd, LOOP_SET_STATUS64, &info)    [optional: set offset, flags]
    |
    v
ioctl(loopfd, LOOP_SET_BLOCK_SIZE, 4096)   [optional: set block size]
    |
    v
ioctl(loopfd, LOOP_SET_DIRECT_IO, 1)       [optional: enable DIO]
    |
    v
mount("/dev/loopN", "/mnt", "ext4", 0, NULL)
    |
    v
... use the filesystem ...
    |
    v
umount("/mnt")
    |
    v
ioctl(loopfd, LOOP_CLR_FD, 0)              [or rely on AUTOCLEAR]
    |
    v
close(loopfd)
```

### Single-step (Linux 5.8+)

```
open("/dev/loop-control")
    |
    v
ioctl(LOOP_CTL_GET_FREE) --> devnr
    |
    v
open("/dev/loopN")
    |
    v
open("/path/to/image.ext4") --> backingfd
    |
    v
ioctl(loopfd, LOOP_CONFIGURE, &config)     [fd + info + block_size, atomic]
    |
    v
mount("/dev/loopN", "/mnt", "ext4", 0, NULL)
```

---

## 10. Ioctl Constants Reference

All loop ioctls use the `0x4C` (`'L'`) magic number. These are "old-style" flat
ioctl numbers (they do not use the `_IO`/`_IOW`/`_IOR`/`_IOWR` encoding
macros).

| Constant               | Hex Value | Decimal | Direction | Argument Type      |
|------------------------|-----------|---------|-----------|--------------------|
| `LOOP_SET_FD`          | `0x4C00`  | 19456   | write     | `int` (fd)         |
| `LOOP_CLR_FD`          | `0x4C01`  | 19457   | none      | (ignored)          |
| `LOOP_SET_STATUS`      | `0x4C02`  | 19458   | write     | `loop_info *`      |
| `LOOP_GET_STATUS`      | `0x4C03`  | 19459   | read      | `loop_info *`      |
| `LOOP_SET_STATUS64`    | `0x4C04`  | 19460   | write     | `loop_info64 *`    |
| `LOOP_GET_STATUS64`    | `0x4C05`  | 19461   | read      | `loop_info64 *`    |
| `LOOP_CHANGE_FD`       | `0x4C06`  | 19462   | write     | `int` (fd)         |
| `LOOP_SET_CAPACITY`    | `0x4C07`  | 19463   | none      | (ignored)          |
| `LOOP_SET_DIRECT_IO`   | `0x4C08`  | 19464   | write     | `unsigned long`    |
| `LOOP_SET_BLOCK_SIZE`  | `0x4C09`  | 19465   | write     | `unsigned long`    |
| `LOOP_CONFIGURE`       | `0x4C0A`  | 19466   | write     | `loop_config *`    |
| `LOOP_CTL_ADD`         | `0x4C80`  | 19584   | write     | `int` (devnr)     |
| `LOOP_CTL_REMOVE`      | `0x4C81`  | 19585   | write     | `int` (devnr)     |
| `LOOP_CTL_GET_FREE`    | `0x4C82`  | 19586   | none      | (none)             |

---

## 11. Rust Implementation

### Cargo.toml

```toml
[dependencies]
nix = { version = "0.29", features = ["ioctl", "mount", "fs"] }
libc = "0.2"
```

### Defining the ioctl Wrappers

Because loop ioctls use old-style flat numbers (not encoded with `_IO` macros),
use the `_bad` variants of the nix ioctl macros:

```rust
use nix::{ioctl_none_bad, ioctl_write_int_bad, ioctl_write_ptr_bad, ioctl_read_bad};

// /dev/loop-control ioctls
const LOOP_CTL_GET_FREE: u64 = 0x4C82;
const LOOP_CTL_ADD: u64 = 0x4C80;
const LOOP_CTL_REMOVE: u64 = 0x4C81;

ioctl_none_bad!(loop_ctl_get_free, LOOP_CTL_GET_FREE);
ioctl_write_int_bad!(loop_ctl_add, LOOP_CTL_ADD);
ioctl_write_int_bad!(loop_ctl_remove, LOOP_CTL_REMOVE);

// /dev/loopN ioctls
const LOOP_SET_FD: u64 = 0x4C00;
const LOOP_CLR_FD: u64 = 0x4C01;
const LOOP_SET_STATUS64: u64 = 0x4C04;
const LOOP_GET_STATUS64: u64 = 0x4C05;
const LOOP_SET_DIRECT_IO: u64 = 0x4C08;
const LOOP_SET_BLOCK_SIZE: u64 = 0x4C09;
const LOOP_CONFIGURE: u64 = 0x4C0A;

ioctl_write_int_bad!(loop_set_fd, LOOP_SET_FD);
ioctl_none_bad!(loop_clr_fd, LOOP_CLR_FD);
ioctl_write_ptr_bad!(loop_set_status64, LOOP_SET_STATUS64, LoopInfo64);
ioctl_read_bad!(loop_get_status64, LOOP_GET_STATUS64, LoopInfo64);
ioctl_write_int_bad!(loop_set_direct_io, LOOP_SET_DIRECT_IO);
ioctl_write_int_bad!(loop_set_block_size, LOOP_SET_BLOCK_SIZE);
ioctl_write_ptr_bad!(loop_configure, LOOP_CONFIGURE, LoopConfig);
```

### Defining the Structures

```rust
pub const LO_NAME_SIZE: usize = 64;
pub const LO_KEY_SIZE: usize = 32;

pub const LO_FLAGS_READ_ONLY: u32 = 1;
pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
pub const LO_FLAGS_PARTSCAN: u32 = 8;
pub const LO_FLAGS_DIRECT_IO: u32 = 16;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LoopInfo64 {
    pub lo_device: u64,
    pub lo_inode: u64,
    pub lo_rdevice: u64,
    pub lo_offset: u64,
    pub lo_sizelimit: u64,
    pub lo_number: u32,
    pub lo_encrypt_type: u32,
    pub lo_encrypt_key_size: u32,
    pub lo_flags: u32,
    pub lo_file_name: [u8; LO_NAME_SIZE],
    pub lo_crypt_name: [u8; LO_NAME_SIZE],
    pub lo_encrypt_key: [u8; LO_KEY_SIZE],
    pub lo_init: [u64; 2],
}

impl Default for LoopInfo64 {
    fn default() -> Self {
        // Safety: loop_info64 is a plain-old-data struct, all-zeros is valid
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LoopConfig {
    pub fd: u32,
    pub block_size: u32,
    pub info: LoopInfo64,
    pub __reserved: [u64; 8],
}

impl Default for LoopConfig {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
```

### Complete Example: Set Up a Loop Device and Mount It

```rust
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use nix::mount::{mount, MsFlags};

fn setup_loop_device(image_path: &str, mount_point: &str) -> nix::Result<()> {
    // 1. Open loop-control and get a free device number
    let ctl = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .expect("open /dev/loop-control");

    let devnr = unsafe { loop_ctl_get_free(ctl.as_raw_fd()) }?;
    drop(ctl);

    let loop_path = format!("/dev/loop{}", devnr);

    // 2. Open the loop device
    let loopdev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&loop_path)
        .expect("open loop device");

    // 3. Open the backing file
    let backing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .expect("open backing file");

    // 4. Associate the backing file with the loop device
    unsafe { loop_set_fd(loopdev.as_raw_fd(), backing.as_raw_fd()) }?;

    // 5. Configure the loop device
    let mut info = LoopInfo64::default();
    info.lo_flags = LO_FLAGS_AUTOCLEAR;
    // Copy the file name for identification
    let name_bytes = image_path.as_bytes();
    let copy_len = name_bytes.len().min(LO_NAME_SIZE - 1);
    info.lo_file_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    unsafe { loop_set_status64(loopdev.as_raw_fd(), &info) }?;

    // 6. Set block size
    unsafe { loop_set_block_size(loopdev.as_raw_fd(), 4096) }?;

    // 7. Enable direct I/O
    unsafe { loop_set_direct_io(loopdev.as_raw_fd(), 1) }?;

    // 8. Mount the loop device
    mount(
        Some(loop_path.as_str()),
        mount_point,
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    Ok(())
}
```

### Complete Example: Using LOOP_CONFIGURE (Linux 5.8+)

```rust
fn setup_loop_device_configure(
    image_path: &str,
    mount_point: &str,
) -> nix::Result<()> {
    // 1. Get a free loop device
    let ctl = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .expect("open /dev/loop-control");

    let devnr = unsafe { loop_ctl_get_free(ctl.as_raw_fd()) }?;
    drop(ctl);

    let loop_path = format!("/dev/loop{}", devnr);
    let loopdev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&loop_path)
        .expect("open loop device");

    // 2. Open backing file
    let backing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .expect("open backing file");

    // 3. Configure everything in one ioctl
    let mut config = LoopConfig::default();
    config.fd = backing.as_raw_fd() as u32;
    config.block_size = 4096;
    config.info.lo_flags = LO_FLAGS_DIRECT_IO | LO_FLAGS_AUTOCLEAR;

    let name_bytes = image_path.as_bytes();
    let copy_len = name_bytes.len().min(LO_NAME_SIZE - 1);
    config.info.lo_file_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    unsafe { loop_configure(loopdev.as_raw_fd(), &config) }?;

    // 4. Mount
    mount(
        Some(loop_path.as_str()),
        mount_point,
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    )?;

    Ok(())
}
```

### Detaching

```rust
fn detach_loop(loop_path: &str) -> nix::Result<()> {
    let loopdev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(loop_path)
        .expect("open loop device");

    unsafe { loop_clr_fd(loopdev.as_raw_fd()) }?;
    Ok(())
}
```

### Alternative: Raw libc::ioctl

If you prefer not to use the nix ioctl macros, you can call `libc::ioctl`
directly:

```rust
use std::os::unix::io::AsRawFd;

// LOOP_CTL_GET_FREE
let devnr = unsafe {
    libc::ioctl(ctl.as_raw_fd(), 0x4C82 as libc::c_ulong)
};
if devnr < 0 {
    return Err(std::io::Error::last_os_error());
}

// LOOP_SET_FD
let ret = unsafe {
    libc::ioctl(loopdev.as_raw_fd(), 0x4C00 as libc::c_ulong, backing.as_raw_fd())
};
if ret < 0 {
    return Err(std::io::Error::last_os_error());
}

// LOOP_SET_STATUS64
let ret = unsafe {
    libc::ioctl(
        loopdev.as_raw_fd(),
        0x4C04 as libc::c_ulong,
        &info as *const LoopInfo64,
    )
};
if ret < 0 {
    return Err(std::io::Error::last_os_error());
}
```

---

## 12. Pitfalls and Notes

### Race between GET_FREE and SET_FD

Another process (or udev) can claim the loop device between
`LOOP_CTL_GET_FREE` and `LOOP_SET_FD`. Always retry in a loop if `LOOP_SET_FD`
returns `EBUSY`.

### EAGAIN from LOOP_SET_STATUS64

Since Linux 5.0, changing `lo_offset` via `LOOP_SET_STATUS64` while the device
is being read (e.g., by udev probing) returns `EAGAIN`. Retry with a small
delay, or use `LOOP_CONFIGURE` to set everything atomically.

### Direct I/O compatibility

`LOOP_SET_DIRECT_IO` returns `EINVAL` if the backing filesystem does not
support `O_DIRECT`, or if the block sizes are incompatible. Set the block size
first (or use `LOOP_CONFIGURE` which sets both atomically).

### Block size constraints

The block size must be a power of two in `[512, PAGE_SIZE]` (typically
`[512, 4096]`). Setting it to 4096 is recommended when the backing file is on
a 4K-sector device or when using direct I/O.

### AUTOCLEAR behavior

With `LO_FLAGS_AUTOCLEAR`, the loop device is automatically detached when the
last fd referencing it is closed. This means you do not need to explicitly call
`LOOP_CLR_FD`. However, if you keep the loop device fd open, it will not
auto-clear until you close it -- even after `umount()`.

### Partition scanning

Setting `LO_FLAGS_PARTSCAN` causes the kernel to scan the loop device for
partitions and create `/dev/loopNpM` device nodes. This is useful for disk
images that contain a partition table (e.g., a full VM image with MBR/GPT).

### ioctl constant types in Rust

The nix `_bad` ioctl macros expect the ioctl number as a type that can convert
to `libc::Ioctl` (which is `c_ulong` on Linux). Using `u64` for the constants
works on both 32-bit and 64-bit, but you may also use `libc::c_ulong` for
precision. The raw `libc::ioctl` function uses `c_ulong` for the request
parameter.

### #[repr(C)] is essential

The `LoopInfo64` and `LoopConfig` structs **must** be `#[repr(C)]` to match the
kernel's memory layout. Rust's default struct layout does not guarantee field
ordering or padding. Without `#[repr(C)]`, the ioctl will read/write garbage.
