//! Chromium's Crashpad ignores the upload opt-out when collecting memory.
//! On Linux, deny its mandatory ptrace attachment in the browser process tree.
#[cfg(target_os = "linux")]
pub(crate) fn install() -> std::io::Result<()> {
    const LOAD_SYSCALL: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const EQUAL: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RETURN: u16 = 0x06; // BPF_RET | BPF_K
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let mut instructions = [
        libc::sock_filter {
            code: LOAD_SYSCALL,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: EQUAL,
            jt: 1,
            jf: 0,
            k: ARCH,
        },
        libc::sock_filter {
            code: RETURN,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        libc::sock_filter {
            code: LOAD_SYSCALL,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // x86's x32 ABI uses the same audit architecture and a syscall bit.
        libc::sock_filter {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: !0x40000000,
        },
        libc::sock_filter {
            code: EQUAL,
            jt: 1,
            jf: 0,
            k: libc::SYS_ptrace as u32,
        },
        libc::sock_filter {
            code: RETURN,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
        libc::sock_filter {
            code: RETURN,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    // Called after fork and before exec. The filter survives exec and is inherited
    // by Chrome's crash handlers, including its in-process ptrace broker.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn install() -> std::io::Result<()> {
    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            error: *mut *mut libc::c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(error: *mut libc::c_char);
    }
    // Crashpad's database initializes normally, but its UUID.dmp report files
    // cannot be written. Cookies and Chromium's own renderer sandbox remain
    // subject to their existing policies. The crash fixture is the platform gate.
    let policy = c"(version 1)(allow default)(deny file-write* (regex #\"\\\\.dmp$\"))";
    let mut error = std::ptr::null_mut();
    let result = unsafe { sandbox_init(policy.as_ptr(), 0, &mut error) };
    if !error.is_null() {
        unsafe { sandbox_free_error(error) };
    }
    if result != 0 {
        return Err(std::io::Error::other(
            "Cannot prevent browser crash report writes",
        ));
    }
    Ok(())
}
