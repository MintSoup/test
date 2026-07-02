//! Standalone reproduction of the mirrord `freeifaddrs` hooking problem.
//!
//! On macOS/arm64 the exported `freeifaddrs` is a 4-byte single unconditional
//! branch (`b <impl>`) in the dyld shared cache. Our detour lives in this
//! binary, far more than 128 MB away, so frida can't redirect with a single
//! 4-byte `b` and instead writes a ~16-byte far-branch (`ldr x16 / br x16 /
//! .quad addr`). That spills 12 bytes past the tiny stub, over the neighboring
//! stubs -- so unrelated callers get funneled into our detour.
//!
//! This program: resolves `freeifaddrs` the same way mirrord does, dumps the
//! bytes (and neighbor symbol names) before/after `Interceptor::replace`, then
//! does one legit `getifaddrs`/`freeifaddrs` and reports how many times the
//! detour actually fired.

use std::{
    ffi::{CStr, c_void},
    ptr,
    sync::{
        LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use frida_gum::{Gum, Module, NativePointer, interceptor::Interceptor};

type FreeFn = unsafe extern "C" fn(*mut c_void);

static GUM: LazyLock<Gum> = LazyLock::new(Gum::obtain);
static CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn freeifaddrs_detour(ifaddrs: *mut c_void) {
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    if n < 12 {
        eprintln!(
            "== freeifaddrs_detour call #{n}, arg = {ifaddrs:?} ({}) ==",
            symbolicate(ifaddrs)
        );
    }
    // Intentionally do NOT call the original: swallowing is fine for a repro and
    // avoids crashing if a hijacked neighbor passes us a non-ifaddrs pointer.
}

/// If `word` is an arm64 unconditional `b`, return the address it branches to.
unsafe fn branch_target(at: *const u8, word: u32) -> Option<*const u8> {
    if word & 0xFC00_0000 != 0x1400_0000 {
        return None;
    }
    let imm26 = (word & 0x03FF_FFFF) as i32;
    let off = ((imm26 << 6) >> 6) * 4; // sign-extend 26 bits, then *4
    Some(at.offset(off as isize))
}

unsafe fn symbolicate(addr: *const c_void) -> String {
    let mut info: libc::Dl_info = std::mem::zeroed();
    if libc::dladdr(addr, &mut info) != 0 && !info.dli_sname.is_null() {
        let name = CStr::from_ptr(info.dli_sname).to_string_lossy();
        format!("{name}+{}", addr as usize - info.dli_saddr as usize)
    } else {
        "<unknown>".to_owned()
    }
}

unsafe fn dump(label: &str, base: *const u8) {
    let words = std::slice::from_raw_parts(base as *const u32, 8);
    let hex: Vec<String> = words.iter().map(|w| format!("{w:#010x}")).collect();
    eprintln!("{label} @ {base:?}: {}", hex.join(" "));
}

fn main() {
    unsafe {
        // Obtaining the interceptor initializes gum before any Module lookup.
        let mut interceptor = Interceptor::obtain(&GUM);

        eprintln!(
            "app-linked freeifaddrs = {:p}",
            libc::freeifaddrs as *const c_void
        );

        let export = Module::find_global_export_by_name("freeifaddrs")
            .expect("no global export named freeifaddrs");
        let base = export.0 as *const u8;
        let detour = freeifaddrs_detour as FreeFn as *mut c_void;

        eprintln!("frida-resolved freeifaddrs = {:?}", export.0);
        eprintln!("detour                     = {detour:?}");
        eprintln!(
            "detour is {} MB from target (>128 MB forces a multi-word far branch)",
            (detour as usize).abs_diff(export.0 as usize) / (1024 * 1024)
        );

        eprintln!("symbols at the target and the following words:");
        for off in [0usize, 4, 8, 12, 16] {
            eprintln!("  +{off:<2} -> {}", symbolicate(base.add(off) as *const c_void));
        }

        dump("BEFORE replace (stub)", base);

        // The stub is a `b`; follow it to the real implementation and watch that too.
        let target = branch_target(base, *(base as *const u32));
        if let Some(t) = target {
            eprintln!("stub branches to {t:?} ({})", symbolicate(t as *const c_void));
            dump("BEFORE replace (impl)", t);
        }

        interceptor.begin_transaction();
        match interceptor.replace(export, NativePointer(detour), NativePointer(ptr::null_mut())) {
            Ok(orig) => eprintln!("interceptor.replace OK (trampoline = {:?})", orig.0),
            Err(e) => eprintln!("interceptor.replace FAILED: {e:?}"),
        }
        interceptor.end_transaction();

        dump("AFTER  replace (stub)", base);
        if let Some(t) = target {
            dump("AFTER  replace (impl)", t);
        }
        eprintln!("^ compare stub vs impl before/after to see where frida actually patched.");

        eprintln!("--- exercising libc: one getifaddrs + one freeifaddrs ---");
        let mut head: *mut libc::ifaddrs = ptr::null_mut();
        if libc::getifaddrs(&mut head) == 0 {
            let mut count = 0;
            let mut cur = head;
            while !cur.is_null() {
                count += 1;
                cur = (*cur).ifa_next;
            }
            eprintln!("walked {count} interfaces");
            libc::freeifaddrs(head);
        }

        eprintln!(
            "TOTAL freeifaddrs_detour invocations = {} (a clean hook fires exactly once)",
            CALLS.load(Ordering::Relaxed)
        );
    }
}
