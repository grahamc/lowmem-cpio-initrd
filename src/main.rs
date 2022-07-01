use std::path::Path;

use libcryptsetup_rs::{
    CryptActivateFlags, CryptInit, CryptVolumeKeyFlags, EncryptionFormat, LibcryptErr,
};

fn main() {
    use std::os::unix::fs::MetadataExt;
    let start = std::time::Instant::now();

    let initrd_bytes: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let init_string = std::env::args().nth(2).unwrap();
    let init = std::ffi::CString::new(init_string.clone()).unwrap();

    println!("You made it!");

    {
        let mut entries = std::fs::read_dir("/kernelmodules")
            .unwrap()
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()
            .unwrap();

        // The order in which `read_dir` returns entries is not guaranteed. If reproducible
        // ordering is required the entries should be explicitly sorted.

        entries.sort();
        println!("{:?}", entries);
    }

    insmod("virtio").unwrap();
    insmod("virtio_pci").unwrap();
    insmod("virtio_blk").unwrap();
    insmod("virtio_scsi").unwrap();
    insmod("sd_mod").unwrap();
    //insmod("").unwrap();
    //insmod("").unwrap();
    //insmod("").unwrap();
    //insmod("").unwrap();
    //insmod("").unwrap();

    {
        nix::mount::mount(
            Some("devtmpfs"),
            "/dev",
            Some("devtmpfs"),
            nix::mount::MsFlags::empty(),
            Option::<&'static str>::None,
        )
        .unwrap();
    }

    {
        std::fs::create_dir("/proc").unwrap();
        nix::mount::mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            nix::mount::MsFlags::empty(),
            Option::<&'static str>::None,
        )
        .unwrap();
    }

    let enable_luks = true;
    let mut spill_dev: &'static str;

    if enable_luks {
        spill_dev = "/dev/mapper/spill";
        let start = std::time::Instant::now();
        mkluks().unwrap();
        println!("Made luks in {}ms", start.elapsed().as_millis());
    } else {
        spill_dev = "/dev/sda5";
    }

    let swap_size = mkswap(Path::new(spill_dev)).unwrap();
    unsafe {
        syscalls::syscall!(
            syscalls::Sysno::swapon,
            format!("{}\0", spill_dev).as_bytes().as_ptr(),
            //"/dev/mapper/spill\0".as_bytes().as_ptr(),
            0
        )
        .unwrap();
    };

    {
        std::fs::create_dir("/mnt").unwrap();
        std::fs::create_dir("/mnt/root").unwrap();
        // mount -t proc proc /proc

        nix::mount::mount(
            Some("tmpfs"),
            "/mnt/root",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Some(format!("size={},nr_inodes=10000000", swap_size).as_str()),
        )
        .unwrap();
    }

    {
        let start = std::time::Instant::now();

        println!("Unpacking the cpio");
        let handle = std::fs::File::open(Path::new("/dev/sda4")).unwrap();
        let handle = fscommon::StreamSlice::new(handle, 0, initrd_bytes).unwrap();
        let handle = std::io::BufReader::new(handle);
        unpack_cpio(handle, Path::new("/mnt/root"), initrd_bytes).unwrap();

        println!("Unpacked CPIOs in {}ms", start.elapsed().as_millis());
    }

    println!("Moving to /mnt/root");

    std::env::set_current_dir("/mnt/root").unwrap();

    println!("Remounting /mnt/root to /");
    nix::mount::mount(
        Some("/mnt/root"),
        "/",
        Option::<&'static str>::None,
        nix::mount::MsFlags::MS_MOVE,
        Option::<&'static str>::None,
    )
    .unwrap();

    println!("chroot .");
    nix::unistd::chroot(".").unwrap();

    println!("cd /");
    std::env::set_current_dir("/").unwrap();

    println!("Exec init after {}ms", start.elapsed().as_millis());
    nix::unistd::execv(&init, &[&init]).unwrap();
}

fn insmod(name: &str) -> Result<(), ()> {
    println!("Loading kernel module: {}", name);
    use std::io::Seek;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    let path = format!("/kernelmodules/{}.ko.xz", name);
    let temp_path = format!("/kernelmodules/{}.ko", name);

    let mut in_fd = std::io::BufReader::new(std::fs::File::open(&path).unwrap());
    {
        let mut out_fd = std::fs::File::create(&temp_path).unwrap();

        lzma_rs::xz_decompress(&mut in_fd, &mut out_fd).unwrap();
        out_fd.flush().unwrap();
        out_fd.sync_all().unwrap();
    }
    let mut load_fd = std::fs::File::open(&temp_path).unwrap();

    nix::kmod::finit_module(
        &load_fd,
        &std::ffi::CString::new("").unwrap(),
        nix::kmod::ModuleInitFlags::empty(),
    )
    .unwrap();

    Ok(())
}

fn unpack_cpio<T>(mut handle: T, to: &Path, size: u64) -> Result<(), std::io::Error>
where
    T: std::io::BufRead + std::io::Seek,
{
    const MAGIC_ZSTD: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    const PEEK_BUF_SIZE: usize = 4;
    let mut peek_buffer = [0; PEEK_BUF_SIZE];

    let mut proceed_with_zstd = false;

    loop {
        let skipped = skip_nulls(&mut handle).unwrap();
        if skipped > 0 {
            println!("Skipped {} null bytes", skipped);
        }

        let new_position = handle.stream_position().unwrap();
        if new_position >= size {
            break;
        }

        let read_bytes: i64 = handle.read(&mut peek_buffer).unwrap().try_into().unwrap();
        handle
            .seek(std::io::SeekFrom::Current(0 - read_bytes))
            .unwrap();
        if peek_buffer.starts_with(&MAGIC_ZSTD) {
            proceed_with_zstd = true;
            break;
        }

        match cpio::newc::Reader::new(&mut handle) {
            Ok(archive) => unpack_cpio_entry(archive, &to),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                } else {
                    Err(e)?
                }
            }
        }?;
    }

    if proceed_with_zstd {
        println!("Switching to zstd");
        let mut handle = zstd::stream::read::Decoder::with_buffer(&mut handle).unwrap();

        loop {
            let new_position = handle.get_mut().stream_position().unwrap();
            if new_position >= size {
                break;
            }

            match cpio::newc::Reader::new(&mut handle) {
                Ok(archive) => unpack_cpio_entry(archive, &to),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    } else {
                        Err(e)?
                    }
                }
            }?;
        }
    }

    Ok(())
}

fn unpack_cpio_entry<T>(mut archive: cpio::NewcReader<T>, to: &Path) -> Result<(), std::io::Error>
where
    T: std::io::Read,
{
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let entry = archive.entry();

    let dest = to.join(entry.name());
    // println!("{:#?}", dest);

    if entry.is_trailer() {
        return Ok(());
    }

    let uid = nix::unistd::Uid::from_raw(entry.uid());
    let gid = nix::unistd::Gid::from_raw(entry.gid());
    let permissions = std::fs::Permissions::from_mode(entry.mode());

    let mode = entry.mode();

    let mut set_perms = true;

    match mode & 0o0170000 {
        0o0040000 => {
            // directory
            if !dest.exists() {
                std::fs::create_dir(&dest).unwrap();
            }
        }
        0o0100000 => {
            // File
            let mut f = std::fs::File::create(&dest)?;
            std::io::copy(&mut archive, &mut f)?;
        }
        0o0120000 => {
            let mut target = String::new();
            archive.read_to_string(&mut target)?;
            let t = dest.parent().unwrap().join(&target);
            std::os::unix::fs::symlink(&target, &dest)?;
            set_perms = false;
        }
        _ => {
            println!("Dunno: {:#?}", dest);
        }
    }

    if set_perms {
        nix::unistd::chown(&dest, Some(uid), Some(gid))?;
        std::fs::set_permissions(&dest, permissions)?;
    }
    archive.finish()?;

    Ok(())
}

fn skip_nulls<T>(mut handle: T) -> Result<u64, std::io::Error>
where
    T: std::io::Read + std::io::Seek,
{
    let start_position = handle.stream_position()?;
    let mut silly_buffer = [0; 1];
    let nullread: &[u8; 1] = &[0x00];
    loop {
        match handle.read(&mut silly_buffer) {
            Ok(0) => {
                break;
            }
            Ok(1) => {
                if &silly_buffer != nullread {
                    handle.seek(std::io::SeekFrom::Current(-1))?;
                    break;
                }
            }

            e => {
                e?;
            }
        }
    }

    let new_position = handle.stream_position()?;
    Ok(new_position - start_position)
}

fn mkswap(path: &Path) -> Result<u64, std::io::Error> {
    use std::io::{Seek, SeekFrom, Write};
    use std::str::FromStr;

    let uuid = uuid::Uuid::from_str("87705c6e-9673-4283-b33a-b87dbf6ec490").unwrap();
    let page_size = 4096;

    let mut handle = std::fs::OpenOptions::new()
        .create(false)
        .write(true)
        .read(true)
        .open(path)?;

    handle.seek(SeekFrom::End(0))?;
    let size: u64 = handle.stream_position()?;
    let pages: u32 = (size / page_size).try_into().unwrap_or(u32::MAX);
    handle.seek(SeekFrom::Start(0))?;
    debug_assert!(pages > 40 * 1024);
    /*
     *    union swap_header {
     *       struct {
     *               char reserved[PAGE_SIZE - 10];
     *               char magic[10];                 /* SWAP-SPACE or SWAPSPACE2 */
     *       } magic;
     *       struct {
     *               char            bootbits[1024]; /* Space for disklabel etc. */
     *               __u32           version;
     *               __u32           last_page;
     *               __u32           nr_badpages;
     *               unsigned char   sws_uuid[16];
     *               unsigned char   sws_volume[16];
     *               __u32           padding[117];
     *               __u32           badpages[1];
     *       } info;
     *};
     */
    handle.seek(SeekFrom::Start(1024))?;
    handle.write(&[0x01, 0x00, 0x00, 0x00])?; // version
    handle.write(&(pages - 1).to_ne_bytes())?; // last page
    handle.write(&[0x00, 0x00, 0x00, 0x00])?; // number of bad pages

    handle.write(uuid.as_bytes())?; // sws_uuid
    handle.write(b"SWAP")?; // sws_volume

    handle.seek(SeekFrom::Start(page_size - 10))?;
    handle.write(b"SWAPSPACE2")?; // magic
    handle.seek(SeekFrom::Start(0))?;

    Ok(size)
}

fn mkluks() -> Result<(), LibcryptErr> {
    use std::io::Read;
    std::fs::create_dir("/run").unwrap();
    std::fs::create_dir("/run/cryptsetup").unwrap();
    let mut device = CryptInit::init(&std::path::Path::new("/dev/sda5")).unwrap();

    println!("Initializing LUKS...");

    let start = std::time::Instant::now();
    let mut key: [u8; 64] = [0; 64];

    std::fs::File::open("/dev/random")
        .unwrap()
        .read_exact(&mut key)
        .unwrap();

    println!("Read key in in {}ms", start.elapsed().as_millis());

    let start = std::time::Instant::now();
    device.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        libcryptsetup_rs::Either::Left(&key),
        None,
    )?;
    println!("Formatted in {}ms", start.elapsed().as_millis());

    if true {
        println!("Activating by volume key");
        let start = std::time::Instant::now();
        device.activate_handle().activate_by_volume_key(
            Some("spill"),
            Some(&key),
            CryptActivateFlags::empty(),
        )?;
        println!("Activated in {}ms", start.elapsed().as_millis());
    }

    Ok(())
}
