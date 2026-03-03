# Linux PID Namespaces and chroot

Reference document covering the kernel APIs for PID namespace isolation and
filesystem root changes, with emphasis on running systemd as PID 1 inside a
chroot.

## Sources

- [clone(2) man page](https://www.man7.org/linux/man-pages/man2/clone.2.html)
- [unshare(2) man page](https://man7.org/linux/man-pages/man2/unshare.2.html)
- [pid_namespaces(7) man page](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [chroot(2) man page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [pivot_root(2) man page](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
- [mount(2) man page](https://man7.org/linux/man-pages/man2/mount.2.html)
- [namespaces(7) man page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [nix crate docs — clone](https://docs.rs/nix/latest/nix/sched/fn.clone.html)
- [nix crate docs — unshare](https://docs.rs/nix/latest/nix/sched/fn.unshare.html)
- [nix crate docs — chroot](https://docs.rs/nix/latest/nix/unistd/fn.chroot.html)
- [nix crate docs — mount](https://docs.rs/nix/latest/nix/mount/fn.mount.html)
- [nix crate docs — MsFlags](https://docs.rs/nix/latest/nix/mount/struct.MsFlags.html)
- [nix crate docs — CloneFlags](https://docs.rs/nix/latest/nix/sched/struct.CloneFlags.html)
- [nix crate docs — ioctl macros](https://docs.rs/nix/latest/nix/sys/ioctl/index.html)
- [LWN: Namespaces in operation, part 4](https://lwn.net/Articles/532748/)

---

## 1. clone() with CLONE_NEWPID

The `clone()` syscall creates a new child process. When the `CLONE_NEWPID` flag
is included, the child is placed in a **new PID namespace** where it becomes
PID 1.

```c
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>

// Signature (glibc wrapper):
int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...);
```

Key flags for container-like isolation:

| Flag              | Effect                                      |
|-------------------|---------------------------------------------|
| `CLONE_NEWPID`    | New PID namespace; child is PID 1           |
| `CLONE_NEWNS`     | New mount namespace (isolate mount table)   |
| `CLONE_NEWUTS`    | New UTS namespace (hostname)                |
| `CLONE_NEWNET`    | New network namespace                       |
| `CLONE_NEWUSER`   | New user namespace (uid/gid mapping)        |

Typical usage:

```c
char stack[65536];
pid_t child = clone(child_fn, stack + sizeof(stack),
                    CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, NULL);
```

The child's `getpid()` returns 1. The parent sees the child's PID in its own
namespace. Requires `CAP_SYS_ADMIN`.

**Important**: `CLONE_NEWPID` cannot be combined with `CLONE_THREAD`.

---

## 2. unshare() Alternative

`unshare()` modifies the calling process's namespace memberships **without
forking**. However, with `CLONE_NEWPID`, the calling process itself does NOT
move into the new PID namespace -- only its subsequently created children will
be in the new namespace.

```c
#include <sched.h>
int unshare(int flags);
```

Typical pattern:

```c
unshare(CLONE_NEWPID | CLONE_NEWNS);
// The NEXT fork()'d child will be PID 1 in the new PID namespace.
pid_t child = fork();
if (child == 0) {
    // I am PID 1 in the new namespace
    mount("proc", "/proc", "proc", 0, NULL);
    execv("/sbin/init", argv);
}
```

A process may call `unshare(CLONE_NEWPID)` only once.

The `unshare(1)` command-line tool wraps this:

```bash
unshare --pid --fork --mount-proc chroot /my/rootfs /sbin/init
```

- `--pid` creates a new PID namespace
- `--fork` ensures the exec'd program is PID 1 (not unshare itself)
- `--mount-proc` mounts a fresh `/proc` that reflects the new namespace

---

## 3. PID 1 in a New PID Namespace

The first process in a PID namespace is the **namespace init**. It has special
properties:

### Orphan Reaping

Any process whose parent terminates is reparented to the namespace init. The
init process **must** call `waitpid()` (or equivalent) to reap these orphans.
Failure to do so accumulates zombie processes.

### Signal Protection

- Other processes **within** the namespace can only send signals for which init
  has installed a handler. Unhandled signals are silently dropped. This prevents
  accidental killing of init.
- Processes in an **ancestor** namespace can send any signal, but SIGKILL and
  SIGSTOP are the only ones that bypass handler checks.

### Namespace Destruction

When the namespace init (PID 1) terminates, the kernel sends `SIGKILL` to every
remaining process in that namespace. After that, no new processes can be
`fork()`'d in that namespace (returns `ENOMEM`).

### Implications for systemd

systemd expects to be PID 1 and installs signal handlers for managing services.
The PID namespace's signal protection guarantees that random child processes
cannot send unexpected signals to systemd.

---

## 4. chroot() Syscall

```c
#include <unistd.h>
int chroot(const char *path);
```

`chroot()` changes the calling process's root directory to `path`. All
subsequent absolute pathname resolution starts from this directory. Key points:

- Requires `CAP_SYS_CHROOT`.
- Children created with `fork()` inherit the chroot.
- `execve()` does **not** reset the root directory.
- Does **not** change the current working directory. You almost always want
  `chdir("/")` immediately after `chroot()`.
- Does **not** provide real security isolation by itself -- a privileged process
  can escape a chroot. Combine with PID/mount namespaces for actual isolation.

### chroot vs pivot_root

| Aspect        | chroot                            | pivot_root                          |
|---------------|-----------------------------------|-------------------------------------|
| Scope         | Per-process illusion              | Mount namespace level               |
| Old root      | Remains mounted and accessible    | Can be unmounted afterward          |
| Use case      | Quick filesystem redirection      | Full root filesystem replacement    |
| Container use | Simpler but weaker                | Used by runc and real runtimes      |

For running systemd in a VM-like environment where we control the mount
namespace anyway, `chroot()` is sufficient and simpler than `pivot_root()`.

---

## 5. Combining chroot + PID Namespace to Run systemd

The sequence to launch systemd as PID 1 inside a chroot with its own PID
namespace:

```
1. Prepare rootfs at /path/to/rootfs (ext4 image mounted, or directory)
2. unshare(CLONE_NEWPID | CLONE_NEWNS)    -- new PID + mount namespace
3. fork()                                  -- child is PID 1 in new ns
4. In child:
   a. Bind-mount /dev, /dev/pts, /dev/shm into rootfs
   b. Mount tmpfs on rootfs/tmp, rootfs/run
   c. chroot("/path/to/rootfs")
   d. chdir("/")
   e. Mount proc on /proc (MUST be after entering PID namespace)
   f. Mount sysfs on /sys
   g. execv("/lib/systemd/systemd", args)
```

The ordering matters:
- Mount namespace (`CLONE_NEWNS`) isolates our mounts from the host.
- `fork()` after `unshare(CLONE_NEWPID)` makes the child PID 1.
- `/proc` must be mounted **after** entering the new PID namespace, otherwise
  it reflects the parent namespace's processes.
- `chroot()` before mounting `/proc` means the mount target is inside the chroot.

---

## 6. Bind-Mounting /proc, /sys, /dev, /dev/pts, /dev/shm

Before calling `chroot()`, we bind-mount host pseudo-filesystems into the
rootfs. After `chroot()`, we mount fresh proc/sysfs.

### Before chroot (bind mounts from host)

```c
// /dev -- device nodes from the host
mount("/dev", "/path/to/rootfs/dev", NULL, MS_BIND | MS_REC, NULL);

// /dev/pts -- pseudo-terminal devices
mount("/dev/pts", "/path/to/rootfs/dev/pts", NULL, MS_BIND, NULL);

// /dev/shm -- POSIX shared memory
mount("/dev/shm", "/path/to/rootfs/dev/shm", NULL, MS_BIND, NULL);
```

### After chroot (fresh mounts for the new namespace)

```c
// /proc -- MUST be mounted after entering PID namespace
mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

// /sys -- kernel sysfs
mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, NULL);
```

### Alternative: Mount tmpfs for /dev instead of bind-mounting

Some setups mount a fresh tmpfs on `/dev` and create only the necessary device
nodes:

```c
mount("tmpfs", "/path/to/rootfs/dev", "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755");
// Then mknod or bind-mount individual devices: null, zero, random, urandom, etc.
```

### /tmp and /run

```c
mount("tmpfs", "/path/to/rootfs/tmp",  "tmpfs", MS_NOSUID | MS_NODEV, NULL);
mount("tmpfs", "/path/to/rootfs/run",  "tmpfs", MS_NOSUID | MS_NODEV, "mode=755");
```

---

## 7. The mount() Syscall

```c
#include <sys/mount.h>

int mount(const char *source, const char *target,
          const char *filesystemtype, unsigned long mountflags,
          const void *data);
```

### Bind Mounts (MS_BIND)

A bind mount makes a directory (or file) visible at a second location:

```c
mount("/dev", "/rootfs/dev", NULL, MS_BIND, NULL);
```

- `source`: the existing path to bind
- `target`: where to make it visible
- `filesystemtype`: ignored for bind mounts (pass NULL)
- `MS_BIND`: creates the bind mount
- `MS_REC`: when combined with `MS_BIND`, recursively bind-mounts submounts
- `data`: ignored for bind mounts

To make a bind mount read-only, a **remount** is required:

```c
mount(NULL, "/rootfs/sys", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
```

### tmpfs

```c
mount("tmpfs", "/rootfs/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=64m");
```

- `source`: conventionally "tmpfs" (the name is cosmetic)
- `filesystemtype`: `"tmpfs"`
- `data`: comma-separated options like `"size=64m,mode=1777"`

### proc

```c
mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
```

### sysfs

```c
mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
```

### Common MsFlags

| Flag           | Value        | Meaning                               |
|----------------|--------------|---------------------------------------|
| `MS_RDONLY`    | 1            | Mount read-only                       |
| `MS_NOSUID`    | 2            | Ignore setuid/setgid bits             |
| `MS_NODEV`     | 4            | Disallow device file access           |
| `MS_NOEXEC`    | 8            | Disallow program execution            |
| `MS_REMOUNT`   | 32           | Alter flags of existing mount         |
| `MS_BIND`      | 4096         | Bind mount                            |
| `MS_REC`       | 16384        | Recursive (with MS_BIND)              |
| `MS_PRIVATE`   | 1 << 18      | Make mount private (no propagation)   |
| `MS_SLAVE`     | 1 << 19      | Make mount a slave                    |
| `MS_SHARED`    | 1 << 20      | Make mount shared                     |

---

## 8. Exec'ing systemd as PID 1

After setting up the namespace, mounts, and chroot, the final step is to
replace the current process with systemd:

```c
// We are PID 1 in the new PID namespace, inside the chroot
char *argv[] = { "/lib/systemd/systemd", "--system", "--log-target=console", NULL };
char *envp[] = {
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TERM=linux",
    NULL
};
execve("/lib/systemd/systemd", argv, envp);
// execve only returns on error
perror("execve");
```

Considerations:
- systemd expects to be PID 1 (checks `getpid() == 1`). If it is not PID 1, it
  behaves as a user session manager instead.
- systemd needs a mounted `/proc`, `/sys`, and `/dev` to function.
- systemd mounts additional filesystems itself (cgroups, etc.) so the mount
  namespace must allow this.
- Set `SIGCHLD` as the exit signal in `clone()` so the parent is notified when
  the namespace init (systemd) exits.

---

## 9. The nix Crate Rust API

Cargo.toml feature flags needed:

```toml
[dependencies]
nix = { version = "0.29", features = ["sched", "mount", "fs", "signal"] }
```

### clone()

```rust
use nix::sched::{clone, CloneFlags, CloneCb};
use nix::sys::signal::Signal;
use std::os::unix::io::RawFd;

let mut stack = vec![0u8; 1024 * 1024]; // 1 MiB stack for child

let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;

let cb: CloneCb = Box::new(|| {
    // This runs as PID 1 in the new namespace
    setup_mounts();
    chroot_and_exec();
    0 // return code
});

let child_pid = unsafe {
    clone(cb, &mut stack, flags, Some(Signal::SIGCHLD as i32))
}.expect("clone failed");
```

**Signature:**
```rust
pub unsafe fn clone(
    cb: CloneCb<'_>,
    stack: &mut [u8],
    flags: CloneFlags,
    signal: Option<c_int>,
) -> Result<Pid>
```

The nix crate handles the stack pointer direction automatically (you pass the
base of the buffer, not the top).

### unshare()

```rust
use nix::sched::{unshare, CloneFlags};
use nix::unistd::fork;

unshare(CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS)
    .expect("unshare failed");

match unsafe { fork() }.expect("fork failed") {
    nix::unistd::ForkResult::Child => {
        // PID 1 in the new namespace
        setup_and_exec_systemd();
    }
    nix::unistd::ForkResult::Parent { child } => {
        // Wait for namespace init to exit
        nix::sys::wait::waitpid(child, None).expect("waitpid failed");
    }
}
```

**Signature:**
```rust
pub fn unshare(flags: CloneFlags) -> Result<()>
```

### chroot()

```rust
use nix::unistd::{chroot, chdir};

chroot("/path/to/rootfs").expect("chroot failed");
chdir("/").expect("chdir failed");  // Always chdir after chroot!
```

**Signature:**
```rust
pub fn chroot<P: ?Sized + NixPath>(path: &P) -> Result<()>
```

### mount()

```rust
use nix::mount::{mount, MsFlags};

// Bind mount /dev into the rootfs
mount(
    Some("/dev"),
    "/rootfs/dev",
    None::<&str>,
    MsFlags::MS_BIND | MsFlags::MS_REC,
    None::<&str>,
).expect("bind mount /dev failed");

// Mount proc (after entering PID namespace and chroot)
mount(
    Some("proc"),
    "/proc",
    Some("proc"),
    MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
    None::<&str>,
).expect("mount proc failed");

// Mount tmpfs
mount(
    Some("tmpfs"),
    "/tmp",
    Some("tmpfs"),
    MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
    None::<&str>,
).expect("mount tmpfs on /tmp failed");
```

**Signature:**
```rust
pub fn mount<P1, P2, P3, P4>(
    source: Option<&P1>,
    target: &P2,
    fstype: Option<&P3>,
    flags: MsFlags,
    data: Option<&P4>,
) -> Result<()>
where
    P1: ?Sized + NixPath,
    P2: ?Sized + NixPath,
    P3: ?Sized + NixPath,
    P4: ?Sized + NixPath,
```

### Complete Example: PID Namespace + chroot + systemd

```rust
use nix::mount::{mount, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::unistd::{chdir, chroot, execve};
use std::ffi::CString;

const ROOTFS: &str = "/path/to/rootfs";

fn child_main() -> isize {
    let rootfs = ROOTFS;

    // --- Bind mounts (before chroot) ---
    mount(Some("/dev"), &format!("{rootfs}/dev"), None::<&str>,
          MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
        .expect("mount /dev");

    mount(Some("/dev/pts"), &format!("{rootfs}/dev/pts"), None::<&str>,
          MsFlags::MS_BIND, None::<&str>)
        .expect("mount /dev/pts");

    mount(Some("/dev/shm"), &format!("{rootfs}/dev/shm"), None::<&str>,
          MsFlags::MS_BIND, None::<&str>)
        .expect("mount /dev/shm");

    // tmpfs for /run and /tmp
    mount(Some("tmpfs"), &format!("{rootfs}/run"), Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some("mode=755"))
        .expect("mount /run");

    mount(Some("tmpfs"), &format!("{rootfs}/tmp"), Some("tmpfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV, None::<&str>)
        .expect("mount /tmp");

    // --- chroot ---
    chroot(rootfs).expect("chroot failed");
    chdir("/").expect("chdir failed");

    // --- Mounts after chroot (inside the new PID namespace) ---
    mount(Some("proc"), "/proc", Some("proc"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
          None::<&str>)
        .expect("mount /proc");

    mount(Some("sysfs"), "/sys", Some("sysfs"),
          MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC
              | MsFlags::MS_RDONLY,
          None::<&str>)
        .expect("mount /sys");

    // --- Exec systemd ---
    let path = CString::new("/lib/systemd/systemd").unwrap();
    let args = [
        CString::new("/lib/systemd/systemd").unwrap(),
        CString::new("--system").unwrap(),
        CString::new("--log-target=console").unwrap(),
    ];
    let env = [
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap(),
        CString::new("TERM=linux").unwrap(),
    ];
    let arg_refs: Vec<&std::ffi::CStr> = args.iter().map(|a| a.as_c_str()).collect();
    let env_refs: Vec<&std::ffi::CStr> = env.iter().map(|e| e.as_c_str()).collect();
    execve(&path, &arg_refs, &env_refs).expect("execve failed");
    unreachable!()
}

fn main() {
    let mut stack = vec![0u8; 1024 * 1024];
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;

    let child_pid = unsafe {
        clone(
            Box::new(|| child_main()),
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .expect("clone failed");

    println!("Child PID (in parent ns): {}", child_pid);

    // Wait for the namespace init to exit
    nix::sys::wait::waitpid(child_pid, None).expect("waitpid failed");
}
```

---

## 10. Pitfalls

### /proc must be mounted AFTER entering the PID namespace

If you mount `/proc` before entering the PID namespace (or in the parent
process), the proc filesystem will show the parent namespace's processes. Mount
it from within the child that is PID 1 in the new namespace.

### unshare(CLONE_NEWPID) does not move the caller

Unlike `CLONE_NEWNS`, calling `unshare(CLONE_NEWPID)` does NOT place the
calling process into the new PID namespace. Only its subsequent children will be
in the new namespace. The calling process's PID remains unchanged. You **must**
fork after unshare.

### chdir("/") after chroot

`chroot()` does not change the current working directory. If the cwd is outside
the new root, the process can still access files outside the chroot via relative
paths. Always call `chdir("/")` immediately after `chroot()`.

### MS_PRIVATE before mounting

When in a new mount namespace created by `CLONE_NEWNS`, mounts may still
propagate back to the parent namespace if the mount is "shared." To prevent
this, make the mount tree private early:

```c
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
```

Or in Rust:

```rust
mount(None::<&str>, "/", None::<&str>,
      MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
    .expect("make / private");
```

### Stack size for clone()

The nix crate's `clone()` requires you to provide the child's stack as a
`&mut [u8]` buffer. Ensure it is large enough for the child's call stack (the
child will typically exec quickly, so 1 MiB is usually sufficient).

### SIGCHLD in clone()

If you do not specify `SIGCHLD` as the signal parameter, `waitpid()` in the
parent will not be notified when the child exits. Always pass
`Some(Signal::SIGCHLD as i32)`.

### CAP_SYS_ADMIN requirement

`CLONE_NEWPID` requires `CAP_SYS_ADMIN` (or running as root). User namespaces
(`CLONE_NEWUSER`) can sometimes be used to gain these capabilities, but
distribution support varies (e.g., disabled on some RHEL kernels).

### systemd cgroup expectations

When running systemd inside a PID namespace + chroot, systemd will attempt to
set up cgroup hierarchies. If cgroups are not available or not delegated, some
systemd features (resource limits, slice management) will fail. Consider
mounting/delegating cgroups or configuring systemd to not require them.
