use anyhow::{anyhow, Context, Result};
use crypto::{Aes256Xts, XtsKey, SECTOR_SIZE};
use fuser::{
    Config, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner,
    MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyWrite, Request, SessionACL, WriteFlags,
};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const ROOT_INODE: INodeNo = INodeNo(1);
const FILE_INODE: INodeNo = INodeNo(2);
const TTL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct CryptoMount {
    _session: fuser::BackgroundSession,
    pub decrypted_path: PathBuf,
}

pub fn mount_crypto_fs(
    encrypted_path: PathBuf,
    mount_dir: PathBuf,
    key: XtsKey,
) -> Result<CryptoMount> {
    std::fs::create_dir_all(&mount_dir).context("create fuse mount dir")?;
    let decrypted_path = mount_dir.join("decrypted.img");

    let fs = CryptoFs::new(encrypted_path, key)?;
    let options = vec![
        MountOption::FSName("fly-vault-crypto".to_string()),
        MountOption::DefaultPermissions,
    ];
    let mut config = Config::default();
    config.mount_options = options;
    config.acl = SessionACL::RootAndOwner;

    let session = fuser::spawn_mount2(fs, &mount_dir, &config).context("mount fuser filesystem")?;
    Ok(CryptoMount {
        _session: session,
        decrypted_path,
    })
}

struct CryptoFs {
    encrypted_file: Arc<Mutex<File>>,
    size: u64,
    xts: Aes256Xts,
}

impl CryptoFs {
    fn new(encrypted_path: PathBuf, key: XtsKey) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&encrypted_path)
            .with_context(|| format!("open encrypted image {}", encrypted_path.display()))?;
        let size = file.metadata().context("stat encrypted image")?.len();
        Ok(Self {
            encrypted_file: Arc::new(Mutex::new(file)),
            size,
            xts: Aes256Xts::new(&key),
        })
    }

    fn read_plaintext(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if offset >= self.size {
            return Ok(vec![]);
        }
        let end = (offset + size as u64).min(self.size);
        let aligned_start = (offset / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let aligned_end =
            ((end + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let aligned_len = (aligned_end - aligned_start) as usize;

        let mut ciphertext = vec![0u8; aligned_len];
        {
            let mut file = self
                .encrypted_file
                .lock()
                .map_err(|_| anyhow!("encrypted file mutex poisoned"))?;
            file.seek(SeekFrom::Start(aligned_start))
                .context("seek encrypted image for read")?;
            file.read_exact(&mut ciphertext)
                .context("read encrypted sectors")?;
        }

        self.xts
            .decrypt_range(aligned_start / SECTOR_SIZE as u64, &mut ciphertext)?;

        let start_in_buf = (offset - aligned_start) as usize;
        let want = (end - offset) as usize;
        Ok(ciphertext[start_in_buf..start_in_buf + want].to_vec())
    }

    fn write_plaintext(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let end = (offset + data.len() as u64).min(self.size);
        let write_len = (end - offset) as usize;
        let aligned_start = (offset / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let aligned_end =
            ((end + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let aligned_len = (aligned_end - aligned_start) as usize;

        let mut ciphertext = vec![0u8; aligned_len];
        {
            let mut file = self
                .encrypted_file
                .lock()
                .map_err(|_| anyhow!("encrypted file mutex poisoned"))?;
            file.seek(SeekFrom::Start(aligned_start))
                .context("seek encrypted image for rmw read")?;
            file.read_exact(&mut ciphertext)
                .context("read encrypted rmw sectors")?;
        }
        self.xts
            .decrypt_range(aligned_start / SECTOR_SIZE as u64, &mut ciphertext)?;

        let start_in_buf = (offset - aligned_start) as usize;
        ciphertext[start_in_buf..start_in_buf + write_len].copy_from_slice(&data[..write_len]);

        self.xts
            .encrypt_range(aligned_start / SECTOR_SIZE as u64, &mut ciphertext)?;

        {
            let mut file = self
                .encrypted_file
                .lock()
                .map_err(|_| anyhow!("encrypted file mutex poisoned"))?;
            file.seek(SeekFrom::Start(aligned_start))
                .context("seek encrypted image for write")?;
            file.write_all(&ciphertext)
                .context("write encrypted sectors")?;
            file.sync_data().context("sync encrypted image")?;
        }

        Ok(write_len)
    }

    fn zero_range(&self, offset: u64, length: u64) -> Result<()> {
        if offset >= self.size {
            return Ok(());
        }
        let end = (offset + length).min(self.size);
        let aligned_start = (offset / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;
        let aligned_end =
            ((end + SECTOR_SIZE as u64 - 1) / SECTOR_SIZE as u64) * SECTOR_SIZE as u64;

        let mut file = self
            .encrypted_file
            .lock()
            .map_err(|_| anyhow!("encrypted file mutex poisoned"))?;

        // Process one sector at a time to keep memory usage bounded.
        let mut sector_num = aligned_start / SECTOR_SIZE as u64;
        let mut pos = aligned_start;
        while pos < aligned_end {
            let mut buf = vec![0u8; SECTOR_SIZE];

            // If this sector is only partially zeroed, do a read-modify-write.
            let sector_start = pos;
            let sector_end = pos + SECTOR_SIZE as u64;
            if sector_start < offset || sector_end > end {
                file.seek(SeekFrom::Start(sector_start))
                    .context("seek for zero rmw read")?;
                file.read_exact(&mut buf).context("read for zero rmw")?;
                self.xts.decrypt_sector(sector_num, &mut buf)?;
                let zero_from = (offset.max(sector_start) - sector_start) as usize;
                let zero_to = (end.min(sector_end) - sector_start) as usize;
                buf[zero_from..zero_to].fill(0);
            }
            // Fully covered sectors stay as all-zero plaintext.

            self.xts.encrypt_sector(sector_num, &mut buf)?;
            file.seek(SeekFrom::Start(sector_start))
                .context("seek for zero write")?;
            file.write_all(&buf).context("write zeroed sector")?;

            pos += SECTOR_SIZE as u64;
            sector_num += 1;
        }

        file.sync_data().context("sync after zero range")?;
        Ok(())
    }

    fn file_attr(&self) -> FileAttr {
        FileAttr {
            ino: FILE_INODE,
            size: self.size,
            blocks: self.size.div_ceil(512),
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: SECTOR_SIZE as u32,
        }
    }

    fn root_attr() -> FileAttr {
        FileAttr {
            ino: ROOT_INODE,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: SECTOR_SIZE as u32,
        }
    }
}

impl Filesystem for CryptoFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INODE && name == "decrypted.img" {
            reply.entry(&TTL, &self.file_attr(), Generation(0));
        } else {
            reply.error(fuser::Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino {
            ROOT_INODE => reply.attr(&TTL, &Self::root_attr()),
            FILE_INODE => reply.attr(&TTL, &self.file_attr()),
            _ => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }

        let entries = [
            (ROOT_INODE, FileType::Directory, "."),
            (ROOT_INODE, FileType::Directory, ".."),
            (FILE_INODE, FileType::RegularFile, "decrypted.img"),
        ];

        for (idx, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*entry_ino, (idx + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        match self.read_plaintext(offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        match self.write_plaintext(offset, data) {
            Ok(written) => reply.written(written as u32),
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        match self.encrypted_file.lock() {
            Ok(file) => match file.sync_data() {
                Ok(_) => reply.ok(),
                Err(_) => reply.error(fuser::Errno::EIO),
            },
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        match self.encrypted_file.lock() {
            Ok(file) => match file.sync_data() {
                Ok(_) => reply.ok(),
                Err(_) => reply.error(fuser::Errno::EIO),
            },
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if ino != FILE_INODE {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        // FALLOC_FL_KEEP_SIZE = 0x01, FALLOC_FL_PUNCH_HOLE = 0x02, FALLOC_FL_ZERO_RANGE = 0x10
        const KEEP_SIZE: i32 = 0x01;
        const PUNCH_HOLE: i32 = 0x02;
        const ZERO_RANGE: i32 = 0x10;

        if mode == PUNCH_HOLE | KEEP_SIZE {
            // PUNCH_HOLE only arrives from the loop driver translating block-layer
            // DISCARDs.  DISCARD is a hint ("I no longer need this data"), so we
            // can safely no-op it — the ciphertext stays on disk but the
            // filesystem above has already freed those sectors.
            reply.ok();
        } else if mode == ZERO_RANGE | KEEP_SIZE || mode == ZERO_RANGE {
            match self.zero_range(offset, length) {
                Ok(()) => reply.ok(),
                Err(_) => reply.error(fuser::Errno::EIO),
            }
        } else if mode == 0 {
            // Plain fallocate (preallocate) — file is already fully allocated.
            reply.ok();
        } else {
            reply.error(fuser::Errno::EOPNOTSUPP);
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

pub fn ensure_image_file(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create {}", parent.display()))?;

    let existing_size = if path.exists() {
        std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .len()
    } else {
        0
    };

    let stat = nix::sys::statvfs::statvfs(parent)
        .with_context(|| format!("statvfs {}", parent.display()))?;
    let free_bytes = stat.blocks_available() as u64 * stat.fragment_size() as u64;
    let target =
        (existing_size + free_bytes * 95 / 100) / SECTOR_SIZE as u64 * SECTOR_SIZE as u64;

    if target <= existing_size {
        return Ok(());
    }

    tracing::info!(existing = existing_size, target, "extending encrypted image");

    if existing_size == 0 {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("create encrypted image {}", path.display()))?;
        file.set_len(target)
            .with_context(|| format!("preallocate encrypted image {}", path.display()))?;
    } else {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open encrypted image for extension {}", path.display()))?;
        file.set_len(target)
            .with_context(|| format!("extend encrypted image to {target} bytes"))?;
    }

    Ok(())
}
