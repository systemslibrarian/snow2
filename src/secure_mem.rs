//! Secure memory buffer.
//!
//! On native targets: uses libc for mlock/munlock and guard pages.
//! On WASM: falls back to a simple zeroize-on-drop Vec wrapper (no mlock available).

use anyhow::Result;

// ── Native implementation (Linux / macOS / etc.) ──────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod inner {
    use anyhow::{anyhow, Result};
    use std::ffi::c_void;
    use std::ops::{Deref, DerefMut};
    use std::ptr;
    use zeroize::Zeroize;

    #[derive(Debug)]
    pub struct SecureVec {
        alloc_base: *mut u8,
        mem: *mut u8,
        alloc_len: usize,
        len: usize,
        data_capacity: usize,
    }

    unsafe impl Send for SecureVec {}
    unsafe impl Sync for SecureVec {}

    impl SecureVec {
        pub fn new(capacity: usize) -> Result<Self> {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            if page_size == 0 {
                return Err(anyhow!("Failed to determine system page size"));
            }

            let aligned_data_len = if capacity == 0 {
                page_size
            } else {
                capacity.div_ceil(page_size) * page_size
            };

            let total_alloc = aligned_data_len
                .checked_add(page_size)
                .and_then(|n| n.checked_add(page_size))
                .ok_or_else(|| anyhow!("secure allocation size overflow"))?;

            let alloc_base = unsafe {
                let mut ptr: *mut c_void = ptr::null_mut();
                let ret = libc::posix_memalign(&mut ptr, page_size, total_alloc);
                if ret != 0 {
                    return Err(anyhow!("posix_memalign failed with code {}", ret));
                }
                ptr as *mut u8
            };

            let mem = unsafe { alloc_base.add(page_size) };

            unsafe {
                if libc::mlock(alloc_base as *const c_void, total_alloc) != 0 {
                    let err = std::io::Error::last_os_error();
                    libc::free(alloc_base as *mut c_void);
                    return Err(anyhow!("mlock failed: {}", err));
                }
            }

            // Best-effort Linux hardening: keep locked pages out of core dumps.
            #[cfg(target_os = "linux")]
            unsafe {
                let _ = libc::madvise(
                    alloc_base as *mut c_void,
                    total_alloc,
                    libc::MADV_DONTDUMP,
                );
            }

            let leading_guard_ptr = alloc_base;
            let trailing_guard_ptr = unsafe { mem.add(aligned_data_len) };
            unsafe {
                if libc::mprotect(leading_guard_ptr as *mut c_void, page_size, libc::PROT_NONE)
                    != 0
                {
                    let err = std::io::Error::last_os_error();
                    libc::munlock(alloc_base as *const c_void, total_alloc);
                    libc::free(alloc_base as *mut c_void);
                    return Err(anyhow!("mprotect leading guard page failed: {}", err));
                }
                if libc::mprotect(trailing_guard_ptr as *mut c_void, page_size, libc::PROT_NONE)
                    != 0
                {
                    let err = std::io::Error::last_os_error();
                    libc::mprotect(
                        leading_guard_ptr as *mut c_void,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    libc::munlock(alloc_base as *const c_void, total_alloc);
                    libc::free(alloc_base as *mut c_void);
                    return Err(anyhow!("mprotect trailing guard page failed: {}", err));
                }
            }

            Ok(Self {
                alloc_base,
                mem,
                alloc_len: total_alloc,
                len: 0,
                data_capacity: aligned_data_len,
            })
        }

        /// Linux-only paranoid mode: lock all current and future pages.
        ///
        /// On non-Linux platforms this is a no-op.
        pub fn enable_paranoid_memory() -> Result<()> {
            #[cfg(target_os = "linux")]
            unsafe {
                if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow!("mlockall failed: {}", err));
                }
            }
            Ok(())
        }

        pub fn from_slice(data: &[u8]) -> Result<Self> {
            let mut s = Self::new(data.len())?;
            s.copy_from_slice(data);
            Ok(s)
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        pub fn copy_from_slice(&mut self, data: &[u8]) {
            if data.len() > self.data_capacity {
                panic!("SecureVec::copy_from_slice: source larger than capacity");
            }
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), self.mem, data.len());
            }
            self.len = data.len();
        }
    }

    impl Deref for SecureVec {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            unsafe { std::slice::from_raw_parts(self.mem, self.len) }
        }
    }

    impl DerefMut for SecureVec {
        fn deref_mut(&mut self) -> &mut Self::Target {
            unsafe { std::slice::from_raw_parts_mut(self.mem, self.len) }
        }
    }

    impl Zeroize for SecureVec {
        fn zeroize(&mut self) {
            if !self.mem.is_null() {
                unsafe {
                    ptr::write_bytes(self.mem, 0, self.data_capacity);
                }
            }
        }
    }

    impl Drop for SecureVec {
        fn drop(&mut self) {
            if !self.alloc_base.is_null() {
                self.zeroize();
                unsafe {
                    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                    let leading_guard_ptr = self.alloc_base;
                    let trailing_guard_ptr = self.mem.add(self.data_capacity);
                    libc::mprotect(
                        leading_guard_ptr as *mut c_void,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    libc::mprotect(
                        trailing_guard_ptr as *mut c_void,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    libc::munlock(self.alloc_base as *const c_void, self.alloc_len);
                    libc::free(self.alloc_base as *mut c_void);
                }
                self.alloc_base = ptr::null_mut();
                self.mem = ptr::null_mut();
            }
        }
    }
}

// ── WASM fallback (no mlock / mprotect) ───────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod inner {
    use anyhow::Result;
    use std::ops::{Deref, DerefMut};
    use zeroize::Zeroize;

    /// On WASM, SecureVec is just a zeroize-on-drop Vec<u8>.
    #[derive(Debug)]
    pub struct SecureVec {
        buf: Vec<u8>,
    }

    impl SecureVec {
        pub fn new(capacity: usize) -> Result<Self> {
            Ok(Self {
                buf: Vec::with_capacity(capacity),
            })
        }

        pub fn enable_paranoid_memory() -> Result<()> {
            Ok(())
        }

        pub fn from_slice(data: &[u8]) -> Result<Self> {
            Ok(Self { buf: data.to_vec() })
        }

        pub fn len(&self) -> usize {
            self.buf.len()
        }

        pub fn is_empty(&self) -> bool {
            self.buf.is_empty()
        }

        pub fn copy_from_slice(&mut self, data: &[u8]) {
            self.buf.clear();
            self.buf.extend_from_slice(data);
        }
    }

    impl Deref for SecureVec {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            &self.buf
        }
    }

    impl DerefMut for SecureVec {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.buf
        }
    }

    impl Zeroize for SecureVec {
        fn zeroize(&mut self) {
            self.buf.zeroize();
        }
    }

    impl Drop for SecureVec {
        fn drop(&mut self) {
            self.zeroize();
        }
    }
}

// Re-export so callers just use `secure_mem::SecureVec`
pub use inner::SecureVec;

/// Enable paranoid process-wide memory locking where supported.
///
/// On Linux this calls `mlockall(MCL_CURRENT | MCL_FUTURE)`.
/// On other targets it is a no-op.
pub fn enable_paranoid_memory() -> Result<()> {
    inner::SecureVec::enable_paranoid_memory()
}
