//! Secure memory buffer.
//!
//! On native targets: uses libc for mlock/munlock and guard pages.
//! On WASM: falls back to a simple zeroize-on-drop Vec wrapper (no mlock available).

use anyhow::Result;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

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
        mem: *mut u8,
        capacity: usize,
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
                (capacity + page_size - 1) / page_size * page_size
            };

            let total_alloc = aligned_data_len + page_size;

            let mem = unsafe {
                let mut ptr: *mut c_void = ptr::null_mut();
                let ret = libc::posix_memalign(&mut ptr, page_size, total_alloc);
                if ret != 0 {
                    return Err(anyhow!("posix_memalign failed with code {}", ret));
                }
                ptr as *mut u8
            };

            unsafe {
                if libc::mlock(mem as *const c_void, total_alloc) != 0 {
                    let err = std::io::Error::last_os_error();
                    libc::free(mem as *mut c_void);
                    return Err(anyhow!("mlock failed: {}", err));
                }
            }

            let guard_page_ptr = unsafe { mem.add(aligned_data_len) };
            unsafe {
                if libc::mprotect(guard_page_ptr as *mut c_void, page_size, libc::PROT_NONE) != 0 {
                    let err = std::io::Error::last_os_error();
                    libc::munlock(mem as *const c_void, total_alloc);
                    libc::free(mem as *mut c_void);
                    return Err(anyhow!("mprotect guard page failed: {}", err));
                }
            }

            Ok(Self {
                mem,
                capacity: total_alloc,
                len: 0,
                data_capacity: aligned_data_len,
            })
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
            if !self.mem.is_null() {
                self.zeroize();
                unsafe {
                    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                    let guard_page_ptr = self.mem.add(self.data_capacity);
                    libc::mprotect(
                        guard_page_ptr as *mut c_void,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    libc::munlock(self.mem as *const c_void, self.capacity);
                    libc::free(self.mem as *mut c_void);
                }
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

        pub fn from_slice(data: &[u8]) -> Result<Self> {
            Ok(Self {
                buf: data.to_vec(),
            })
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
