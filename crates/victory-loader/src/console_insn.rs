//! Instructions the console's CPU (Zen 2) has and an Intel PC's lacks, emulated: the title's
//! code raises STATUS_ILLEGAL_INSTRUCTION on them (the title zeroes memory with a `clzero` loop at
//! its first frames), and the vectored handler steps over them here.
//!
//! Ported from XCL (github.com/ivall/xcl, GPL-2.0-only): `insn.rs` (decoder, as
//! `console_insn_decode.rs`, unchanged) and `eh.rs` `emulate_console_only`.

#[path = "console_insn_decode.rs"]
mod decode;

use decode::ConsoleOnly;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

const CONTINUE_EXECUTION: i32 = -1;

/// Whether what Windows said about memory is remembered per thread (the regions it found
/// writable, the code bytes it found readable) and not asked again at every emulated
/// instruction. A query walks the pages of the region it answers for: asked from outside, it
/// took 2-9 ms in the title's heaps of 0.6-2.2 GB and 89 ms in its 6.2 GB page pool (run 30),
/// and the title zeroes blocks of them with `clzero` loops all through a frame: six of its
/// threads spent 25-78 % of their time inside that query (runs 29 and 30), about 27 s of
/// processor time in Windows per 9 s frame. On by default; `VICTORY_CLZERO_ASK=1` asks every
/// time, as before.
fn remembers() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("VICTORY_CLZERO_ASK").is_none_or(|v| v != "1"))
}

/// Answers a remembered region gives before Windows is asked about it again: one freed or
/// protected meanwhile is forgotten then.
const ANSWERS: u32 = 4096;

thread_local! {
    /// The regions Windows last said are committed and writable (start, end), newest first,
    /// and the answers they gave since they were emptied.
    static WRITABLE: Cell<([(usize, usize); 4], u32)> = const { Cell::new(([(0, 0); 4], 0)) };
    /// Faulting addresses and the code bytes found readable there, newest first.
    static CODE: Cell<[(usize, usize); 8]> = const { Cell::new([(0, 0); 8]) };
}

/// Instructions emulated, the times Windows was asked about memory for them, and the bytes
/// `clzero` loops zeroed, since the start.
static EMULATED: AtomicU64 = AtomicU64::new(0);
static ASKED: AtomicU64 = AtomicU64::new(0);
static ZEROED: AtomicU64 = AtomicU64::new(0);

/// Whether `monitorx` and `mwaitx` are replaced in the title's code the first time they fault
/// (`monitorx` by a 3-byte no-op, `mwaitx` by `pause` and a no-op), so that they never fault
/// again. Emulated, each pass of such a wait loop is two trips into Windows and back, through
/// every vectored handler, and no lighter a wait for it: the emulation does no more than
/// `pause` either, and the loop looks at its value again after it. On by default;
/// `VICTORY_PATCH_WAITS=0` emulates each time, as before.
fn patches_waits() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("VICTORY_PATCH_WAITS").is_none_or(|v| v != "0"))
}

/// What replaces the 3 bytes of a wait instruction.
fn wait_patch(what: ConsoleOnly) -> Option<[u8; 3]> {
    match what {
        ConsoleOnly::Monitorx => Some([0x0f, 0x1f, 0x00]),
        ConsoleOnly::Mwaitx => Some([0xf3, 0x90, 0x90]),
        _ => None,
    }
}

/// Whether a `clzero` loop ([`ConsoleOnly::ClzeroLoop`]) is replaced the first time it faults
/// by a jump to the same loop with plain stores ([`clzero_stub`]). Run cpu-5 (the dorm): 25,000
/// exceptions a second, 2,100 a frame, at five such loops of one function of the title, for
/// some kilobytes each; ten times what the wait instructions raised. On by default;
/// `VICTORY_PATCH_CLZERO=0` emulates each time, as before.
fn patches_clzero() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("VICTORY_PATCH_CLZERO").is_none_or(|v| v != "0"))
}

/// `jmp rel32` at `at` to `to`, if it reaches.
pub(crate) fn jump(at: usize, to: usize) -> Option<[u8; 5]> {
    let rel = i32::try_from(to as i64 - (at as i64 + 5)).ok()?;
    let [a, b, c, d] = rel.to_le_bytes();
    Some([0xe9, a, b, c, d])
}

/// The `clzero` loop of 12 bytes at `at` with plain stores, as code at `stub`: every register
/// and the flags come out as the loop leaves them. `cmp` is its `cmp rax, reg` (3 bytes, the
/// register not `rax`), `None` for another form. (The scratch register is saved on the stack
/// and back before the compare, whose register it may be.)
fn clzero_stub(at: usize, stub: usize, cmp: [u8; 3]) -> Option<Vec<u8>> {
    if !matches!(cmp[0], 0x48 | 0x4c) || cmp[1] != 0x39 || cmp[2] & 0xc7 != 0xc0 || (cmp[0] == 0x48 && cmp[2] == 0xc0) {
        return None;
    }
    let mut code = vec![
        0x51, // push rcx
        0x48, 0x89, 0xc1, // mov rcx, rax
        0x48, 0x83, 0xe1, 0xc0, // and rcx, -64
    ];
    for k in 0..8 {
        code.extend([0x48, 0xc7, 0x41, k * 8, 0, 0, 0, 0]); // mov qword [rcx + 8k], 0
    }
    code.push(0x59); // pop rcx
    code.extend([0x48, 0x83, 0xc0, 0x40]); // add rax, 0x40
    code.extend(cmp);
    let back = -(code.len() as i64 + 2);
    code.extend([0x72, i8::try_from(back).ok()? as u8]); // jb the start
    let end = stub + code.len();
    code.extend(jump(end, at + 12)?);
    Some(code)
}

/// Room for [`clzero_stub`]s near the title's code: where it is and the bytes used.
static STUBS: std::sync::Mutex<Option<(usize, usize)>> = std::sync::Mutex::new(None);
pub(crate) const STUBS_LEN: usize = 64 << 10;

/// Memory for code within reach of a `jmp rel32` at `at`.
pub(crate) fn near(at: usize) -> Option<usize> {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc};
    let at = at & !0xffff;
    (0x10_0000..0x7000_0000).step_by(0x10_0000).flat_map(|d| [at.checked_sub(d), at.checked_add(d)]).flatten().find_map(|place| {
        // SAFETY: reserves free memory at that address or fails.
        let got = unsafe { VirtualAlloc(place as *const _, STUBS_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) } as usize;
        (got != 0).then_some(got)
    })
}

/// Replaces the `clzero` loop at `at`, whose 12 bytes are `code`: whether it did.
///
/// No thread is ever inside the loop's other instructions (the emulation does the whole loop
/// in one), so the five bytes of the jump may take the place of two of them.
///
/// # Safety
/// `at` is in the title's code, which stays mapped.
unsafe fn patch_clzero(at: usize, code: &[u8]) -> bool {
    let &[a, b, c, d, e, _, _, x, y, z, 0x72, 0xf4] = code else {
        return false;
    };
    let mut stubs = STUBS.lock().unwrap_or_else(|e| e.into_inner());
    if stubs.is_none() {
        *stubs = near(at).map(|place| (place, 0));
    }
    let Some((place, used)) = stubs.as_mut() else {
        return false;
    };
    let stub = *place + *used;
    let (Some(body), Some(jump)) = (clzero_stub(at, stub, [x, y, z]), jump(at, stub)) else {
        return false;
    };
    if *used + body.len() > STUBS_LEN || (at & 15) + 5 > 16 {
        return false;
    }
    // SAFETY: inside the memory made for it, which nothing runs yet; then the title's code.
    unsafe {
        std::ptr::copy_nonoverlapping(body.as_ptr(), stub as *mut u8, body.len());
        *used += body.len().next_multiple_of(16);
        patch(at, [a, b, c, d, e], jump)
    }
}

/// The aligned 16 bytes `word` around address `at` with the bytes at `at` replaced; `None`
/// where they do not all lie in those 16. (16 and not 8: the title's busiest one lies over the
/// end of its 8 and took 28,000 exceptions a second, run cpu-6.)
fn with_patch(word: u128, at: usize, patch: &[u8]) -> Option<u128> {
    let offset = at & 15;
    if offset + patch.len() > 16 {
        return None;
    }
    let mut bytes = word.to_le_bytes();
    bytes[offset..offset + patch.len()].copy_from_slice(patch);
    Some(u128::from_le_bytes(bytes))
}

/// One thread at a time changes code: a second one would take the first one's loosened
/// protection for the page's own.
static PATCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Replaces the bytes at `at`, which are `was`, by `patch`, in one store that other threads
/// see whole: whether they are replaced now (not where they cross 16 aligned bytes, or the page
/// cannot be written).
///
/// # Safety
/// `at` is in code that stays mapped, and `patch` does for it what `was` does.
unsafe fn patch<const N: usize>(at: usize, was: [u8; N], patch: [u8; N]) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    if (at & 15) + N > 16 || !std::is_x86_feature_detected!("cmpxchg16b") {
        return false;
    }
    let _one = PATCHING.lock().unwrap_or_else(|e| e.into_inner());
    let word = (at & !15) as *mut u128;
    let here = (at & 15)..(at & 15) + N;
    let mut old = 0u32;
    // SAFETY: the aligned 16 bytes around the instruction lie in one page of mapped code, made
    // writable for the store and put back; the processor has the instruction (asked above).
    unsafe {
        if VirtualProtect(word.cast(), 16, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return false;
        }
        // What is there (zeros are replaced by zeros).
        let mut now = std::arch::x86_64::cmpxchg16b(word, 0, 0, SeqCst, SeqCst);
        let done = loop {
            let bytes = &now.to_le_bytes()[here.clone()];
            if bytes == patch {
                // (Another thread's fault at the same place: done already.)
                break true;
            }
            let Some(new) = (bytes == was).then(|| with_patch(now, at, &patch)).flatten() else {
                break false;
            };
            let there = std::arch::x86_64::cmpxchg16b(word, now, new, SeqCst, SeqCst);
            if there == now {
                break true;
            }
            now = there;
        };
        VirtualProtect(word.cast(), 16, old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), word.cast(), 16);
        done
    }
}

/// Diagnostics: how often each place in the title's code raises one of these exceptions, the
/// busiest logged every five seconds.
#[cfg(feature = "diagnostics")]
mod sites {
    use super::{AtomicU64, Relaxed};
    use std::sync::atomic::AtomicUsize;

    /// Address, what is there (an index into [`NAMES`]), exceptions since the last line.
    static SITES: [(AtomicUsize, AtomicUsize, AtomicU64); 512] =
        [const { (AtomicUsize::new(0), AtomicUsize::new(0), AtomicU64::new(0)) }; 512];
    const NAMES: [&str; 8] = ["other", "clwb", "monitorx", "mwaitx", "clzero", "clzero loop", "rdpru", "extrq/insertq"];
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    static PATCHED: AtomicU64 = AtomicU64::new(0);

    pub(super) fn patched() {
        PATCHED.fetch_add(1, Relaxed);
    }

    pub(super) fn count(at: usize, what: super::ConsoleOnly) {
        use super::ConsoleOnly as C;
        let kind = match what {
            C::Clwb => 1,
            C::Monitorx => 2,
            C::Mwaitx => 3,
            C::Clzero => 4,
            C::ClzeroLoop { .. } => 5,
            C::Rdpru => 6,
            C::Extrq { .. } | C::Insertq { .. } => 7,
            _ => 0,
        };
        let mut i = (at ^ at >> 9) % SITES.len();
        for _ in 0..8 {
            let s = &SITES[i];
            let there = s.0.compare_exchange(0, at, Relaxed, Relaxed).unwrap_or_else(|there| there);
            if there == 0 || there == at {
                s.1.store(kind, Relaxed);
                s.2.fetch_add(1, Relaxed);
                break;
            }
            i = (i + 1) % SITES.len();
        }
        // Now and then: is a line due? Never waited for.
        if let Ok(mut last) = LAST.try_lock() {
            let since = *last.get_or_insert_with(std::time::Instant::now);
            if since.elapsed().as_secs() >= 5 {
                let s = since.elapsed().as_secs_f64();
                *last = Some(std::time::Instant::now());
                drop(last);
                line(s);
            }
        }
    }

    fn line(seconds: f64) {
        let mut all: Vec<(u64, usize, usize)> =
            SITES.iter().map(|s| (s.2.swap(0, Relaxed), s.0.load(Relaxed), s.1.load(Relaxed))).filter(|s| s.0 > 0).collect();
        all.sort_unstable_by_key(|s| std::cmp::Reverse(s.0));
        let mut kinds = [0u64; NAMES.len()];
        for s in &all {
            kinds[s.2] += s.0;
        }
        let kinds: Vec<String> = NAMES
            .iter()
            .zip(kinds)
            .filter(|(_, n)| *n > 0)
            .map(|(name, n)| format!("{name} {:.0}", n as f64 / seconds))
            .collect();
        let top: Vec<String> =
            all.iter().take(8).map(|s| format!("{:#x} {} {:.0}", s.1, NAMES[s.2], s.0 as f64 / seconds)).collect();
        tracing::info!(
            "console CPU instructions that fault, a second: {}; places replaced so far: {}; the busiest places: {}",
            kinds.join(", "),
            PATCHED.load(Relaxed),
            top.join(", ")
        );
    }
}

fn readable(va: usize, bytes: usize) -> bool {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};
    // SAFETY: plain data filled in by the query.
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out pointer of the right size.
    let found = unsafe { VirtualQuery(va as *const _, &mut m, size_of_val(&m)) } != 0;
    ASKED.fetch_add(1, Relaxed);
    found && m.State == MEM_COMMIT && m.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0 && m.BaseAddress as usize + m.RegionSize >= va + bytes
}

fn writable(va: usize, bytes: usize) -> bool {
    writable_to(va, va + bytes) == Some(va + bytes)
}

/// Where the committed, writable memory that `va` lies in ends, at most `end`; None if `va`
/// is not in such memory. A region found is remembered ([`remembers`]).
/// shortcut: a remembered region that was freed or protected since is written all the same
/// for up to [`ANSWERS`] answers: the write then faults inside the handler, which the guard
/// on view memory opens as it does any write, and which is a crash otherwise (as the
/// unchecked single-line emulation behind this one already is).
fn writable_to(va: usize, end: usize) -> Option<usize> {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualQuery};
    let remember = remembers();
    if remember {
        let (regions, answers) = WRITABLE.with(Cell::get);
        if let Some(&(_, to)) = regions.iter().find(|&&(from, to)| from <= va && va < to) {
            let next = if answers >= ANSWERS { ([(0, 0); 4], 0) } else { (regions, answers + 1) };
            WRITABLE.with(|w| w.set(next));
            return Some(to.min(end));
        }
    }
    // SAFETY: plain data filled in by the query.
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out pointer of the right size.
    let found = unsafe { VirtualQuery(va as *const _, &mut m, size_of_val(&m)) } != 0;
    ASKED.fetch_add(1, Relaxed);
    if !found || m.State != MEM_COMMIT || m.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE) == 0 {
        return None;
    }
    let (from, to) = (m.BaseAddress as usize, m.BaseAddress as usize + m.RegionSize);
    if remember {
        WRITABLE.with(|w| {
            let (mut regions, answers) = w.get();
            regions.rotate_right(1);
            regions[0] = (from, to);
            w.set((regions, answers));
        });
    }
    Some(to.min(end))
}

/// An illegal instruction at `ctx.Rip`: a console-only one is emulated and stepped over
/// (`CONTINUE_EXECUTION`); anything else returns 0 (the crash report and the title's handlers
/// see it).
///
/// # Safety
/// `ctx` is the faulting thread's context, from the exception being dispatched.
pub(crate) unsafe fn emulate(ctx: &mut CONTEXT) -> i32 {
    let rip = ctx.Rip as usize;
    // The same few instructions fault again and again: their bytes are asked about once.
    let known = if remembers() { CODE.with(Cell::get) } else { [(0, 0); 8] };
    let n = match known.iter().find(|&&(at, n)| at == rip && n > 0) {
        Some(&(_, n)) => n,
        None => {
            if !readable(rip, 1) {
                return 0;
            }
            let n = (1..=16).rev().find(|&n| readable(rip, n)).unwrap_or(0);
            if remembers() {
                let mut known = known;
                known.rotate_right(1);
                known[0] = (rip, n);
                CODE.with(|c| c.set(known));
            }
            n
        }
    };
    // SAFETY: `n` bytes at `rip` are readable.
    let code = unsafe { std::slice::from_raw_parts(rip as *const u8, n) };
    let Some((what, len)) = decode::decode(code) else { return 0 };
    static SEEN: std::sync::Mutex<Vec<std::mem::Discriminant<ConsoleOnly>>> = std::sync::Mutex::new(Vec::new());
    if let Ok(mut seen) = SEEN.lock()
        && !seen.contains(&std::mem::discriminant(&what))
    {
        seen.push(std::mem::discriminant(&what));
        if what != ConsoleOnly::Ud2 {
            tracing::warn!(instruction = ?what, at = format_args!("{rip:#x}"), "a console CPU instruction this CPU lacks: emulated (logged once)");
        }
    }
    #[cfg(feature = "diagnostics")]
    if what != ConsoleOnly::Ud2 {
        sites::count(rip, what);
    }
    match what {
        ConsoleOnly::Ud2 => return 0,
        ConsoleOnly::Clwb => {
            // nothing to write back on the PC: patched to NOPs, no exception next time
            use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
            let mut old = 0u32;
            let _one = PATCHING.lock().unwrap_or_else(|e| e.into_inner());
            // SAFETY: the instruction's own bytes, made writable for the patch and restored.
            unsafe {
                if VirtualProtect(rip as *const _, len, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
                    std::slice::from_raw_parts_mut(rip as *mut u8, len).fill(0x90);
                    VirtualProtect(rip as *const _, len, old, &mut old);
                }
            }
        }
        ConsoleOnly::Monitorx | ConsoleOnly::Mwaitx => {
            // Without a prefix, so 3 bytes: replaced, the next pass does not fault.
            if len == 3
                && patches_waits()
                && let Some(new) = wait_patch(what)
                // SAFETY: the title's code, where the instruction just faulted; both
                // replacements are waits that wait for nothing, as the emulation is.
                && unsafe { patch(rip, [code[0], code[1], code[2]], new) }
            {
                #[cfg(feature = "diagnostics")]
                sites::patched();
            }
            std::hint::spin_loop();
        }
        ConsoleOnly::Clzero => {
            // with an address-size prefix (0x67) the line is at EAX, zero-extended
            let a32 = code[..len - 3].contains(&0x67);
            let line = (if a32 { ctx.Rax & 0xFFFF_FFFF } else { ctx.Rax } as usize) & !63;
            if !writable(line, 64) {
                return 0; // the real instruction faults there too
            }
            // SAFETY: the 64-byte line is committed and writable.
            unsafe { std::ptr::write_bytes(line as *mut u8, 0, 64) };
        }
        ConsoleOnly::ClzeroLoop { end_reg } => {
            // the whole `clzero; add rax,40h; cmp rax,end; jb` loop at once
            // (and not again: the next time it is plain stores)
            if len == 12
                && patches_clzero()
                // SAFETY: the title's code, where the loop's first instruction just faulted.
                && unsafe { patch_clzero(rip, &code[..12]) }
            {
                #[cfg(feature = "diagnostics")]
                sites::patched();
            }
            let regs: [u64; 16] = [
                ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp, ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13, ctx.R14, ctx.R15,
            ];
            let end = regs[end_reg as usize & 15] as usize;
            let start = ctx.Rax as usize;
            // A pass zeroes the whole line `rax` is in, wherever in it, and the test comes
            // after it: lines are zeroed past an `end` inside one, and one is for an `end`
            // not above the start. (The bytes from `start` to `end` were, `rax` came out as
            // `end`, and the flags stayed what they were.)
            const MOST: usize = (2 << 30) / 64;
            let wanted = if end > start { (end - start).div_ceil(64) } else { 1 };
            let passes = wanted.min(MOST);
            let first = start & !63;
            let Some(stop) = first.checked_add(passes * 64) else { return 0 };
            // Region by region: a block may lie across several (the title's pages are
            // mapped one view each), and one answer for all of it was a refusal, after
            // which every 64-byte line took an exception of its own.
            let mut at = first;
            while at < stop {
                let Some(to) = writable_to(at, stop) else { break };
                // SAFETY: committed and writable from `at` to `to`.
                unsafe { std::ptr::write_bytes(at as *mut u8, 0, to - at) };
                at = to;
            }
            let done = (at - first) / 64;
            if done == 0 {
                return 0;
            }
            ZEROED.fetch_add((done * 64) as u64, Relaxed);
            ctx.Rax = ctx.Rax.wrapping_add((done * 64) as u64);
            if done < wanted {
                // What follows is not writable (or the block is huge): the loop goes on
                // there (the same instruction again), where the real one faults too.
                return CONTINUE_EXECUTION;
            }
            ctx.EFlags = ctx.EFlags & !crate::crash::CMP_FLAGS | crate::crash::cmp_flags(ctx.Rax, end as u64);
        }
        ConsoleOnly::Rdpru => {
            let mut v = 0i64;
            // SAFETY: a valid out pointer.
            unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut v) };
            let v = if ctx.Rcx as u32 <= 1 { v as u64 } else { 0 };
            ctx.Rax = v & 0xFFFF_FFFF;
            ctx.Rdx = v >> 32;
        }
        ConsoleOnly::Rdpid(r) => {
            // SAFETY: no preconditions.
            let cpu = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessorNumber() } as u64;
            let regs: [&mut u64; 16] = [
                &mut ctx.Rax, &mut ctx.Rcx, &mut ctx.Rdx, &mut ctx.Rbx, &mut ctx.Rsp, &mut ctx.Rbp, &mut ctx.Rsi, &mut ctx.Rdi, &mut ctx.R8, &mut ctx.R9, &mut ctx.R10, &mut ctx.R11, &mut ctx.R12, &mut ctx.R13,
                &mut ctx.R14, &mut ctx.R15,
            ];
            *regs[r as usize & 15] = cpu;
        }
        // the low quadword changes; the high one is zeroed, as a Zen 5 does
        ConsoleOnly::Extrq { dst, src, len, idx } => {
            // SAFETY: the context's XMM registers (CONTEXT_FLOATING_POINT is captured for exceptions).
            let x = unsafe { &mut ctx.Anonymous.FltSave.XmmRegisters };
            let (len, idx) = match src {
                Some(s) => {
                    let c = x[s as usize & 15].Low;
                    (c as u8, (c >> 8) as u8)
                }
                None => (len, idx),
            };
            let d = &mut x[dst as usize & 15];
            d.Low = decode::extrq(d.Low, len, idx);
            d.High = 0;
        }
        ConsoleOnly::Insertq { dst, src, reg, len, idx } => {
            // SAFETY: as above.
            let x = unsafe { &mut ctx.Anonymous.FltSave.XmmRegisters };
            let s = x[src as usize & 15];
            let (len, idx) = if reg { (s.High as u8, (s.High >> 8) as u8) } else { (len, idx) };
            let d = &mut x[dst as usize & 15];
            d.Low = decode::insertq(d.Low, s.Low, len, idx);
            d.High = 0;
        }
    }
    ctx.Rip += len as u64;
    // How often this runs at all (each one is an exception: a trip into Windows and back).
    let emulated = EMULATED.fetch_add(1, Relaxed) + 1;
    if emulated >= 1 << 16 && emulated.is_power_of_two() {
        tracing::info!(
            emulated,
            asked = ASKED.load(Relaxed),
            zeroed_mb = ZEROED.load(Relaxed) >> 20,
            "console CPU instructions emulated so far, the times Windows was asked about memory for them, and what clzero loops zeroed"
        );
    }
    CONTINUE_EXECUTION
}

/// Outcome of static AOT console-instruction scanning or translation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AotReport {
    pub clzero_loops: usize,
    pub clzero_preinc_loops: usize,
    pub waits: usize,
    pub insertq: usize,
    pub patched: usize,
}

impl AotReport {
    /// Total statically translatable console-only instruction sites found.
    pub fn total(&self) -> usize {
        self.clzero_loops + self.clzero_preinc_loops + self.waits + self.insertq
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AotKind {
    ClzeroLoop { cmp: [u8; 3] },
    ClzeroPreIncLoop { code: [u8; 15], ptr_reg: u8, end_reg: u8 },
    Wait { replacement: [u8; 3] },
    Insertq { dst: u8, src: u8, len: u8, idx: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AotSite {
    pub(crate) rva: usize,
    pub(crate) len: usize,
    pub(crate) kind: AotKind,
}

#[derive(Debug, Clone, Copy)]
struct CpuSupport {
    clzero: bool,
    mwaitx: bool,
    sse4a: bool,
}

fn host_cpu_support() -> CpuSupport {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `cpuid` is always supported on x86_64.
        unsafe {
            let max_ext = std::arch::x86_64::__cpuid(0x8000_0000).eax;
            let ext1 = if max_ext >= 0x8000_0001 {
                std::arch::x86_64::__cpuid(0x8000_0001).ecx
            } else {
                0
            };
            let ext8 = if max_ext >= 0x8000_0008 {
                std::arch::x86_64::__cpuid(0x8000_0008).ebx
            } else {
                0
            };
            CpuSupport {
                sse4a: ext1 & (1 << 6) != 0,
                mwaitx: ext1 & (1 << 29) != 0,
                clzero: ext8 & 1 != 0,
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        CpuSupport {
            clzero: true,
            mwaitx: true,
            sse4a: true,
        }
    }
}

fn parse_pdata(bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut funcs = Vec::with_capacity(bytes.len() / 12);
    for chunk in bytes.chunks_exact(12) {
        let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        if begin < end {
            funcs.push((begin, end));
        }
    }
    funcs.sort_unstable_by_key(|&(b, _)| b);
    funcs
}

fn in_sorted_ranges(ranges: &[(u32, u32)], rva: u32) -> bool {
    let i = ranges.partition_point(|&(b, _)| b <= rva);
    i > 0 && rva < ranges[i - 1].1
}

/// Scans executable sections for unambiguous console-only instruction sites.
pub(crate) fn scan_code_sections<'a>(
    funcs: &[(u32, u32)],
    sections: impl IntoIterator<Item = (u32, &'a [u8])>,
) -> Vec<AotSite> {
    let mut sites = Vec::new();
    for (sec_rva, code) in sections {
        let mut i = 0usize;
        while i < code.len() {
            let tail = &code[i..];
            if tail.len() >= 15
                && let Some((ptr_reg, end_reg)) = decode::match_clzero_preinc_loop(tail)
            {
                sites.push(AotSite {
                    rva: sec_rva as usize + i,
                    len: 15,
                    kind: AotKind::ClzeroPreIncLoop {
                        code: tail[..15].try_into().unwrap(),
                        ptr_reg,
                        end_reg,
                    },
                });
                i += 15;
                continue;
            }
            if tail.len() >= 12 && decode::match_clzero_loop(tail).is_some() {
                sites.push(AotSite {
                    rva: sec_rva as usize + i,
                    len: 12,
                    kind: AotKind::ClzeroLoop {
                        cmp: tail[7..10].try_into().unwrap(),
                    },
                });
                i += 12;
                continue;
            }
            if tail.len() >= 7 && tail[..7] == [0x31, 0xC9, 0x31, 0xD2, 0x0F, 0x01, 0xFA] {
                let rva = sec_rva + i as u32 + 4;
                if in_sorted_ranges(funcs, rva) {
                    sites.push(AotSite {
                        rva: rva as usize,
                        len: 3,
                        kind: AotKind::Wait {
                            replacement: [0x0F, 0x1F, 0x00],
                        },
                    });
                    i += 7;
                    continue;
                }
            }
            if tail.len() >= 5 && matches!(tail[0], 0x31 | 0x33) && tail[1..5] == [0xC0, 0x0F, 0x01, 0xFB] {
                let rva = sec_rva + i as u32 + 2;
                if in_sorted_ranges(funcs, rva) {
                    sites.push(AotSite {
                        rva: rva as usize,
                        len: 3,
                        kind: AotKind::Wait {
                            replacement: [0xF3, 0x90, 0x90],
                        },
                    });
                    i += 5;
                    continue;
                }
            }
            if tail.first().copied() == Some(0xF2)
                && let Some((insn_len, dst, src, len, idx)) = decode::match_insertq_imm(tail)
                && insn_len >= 5
                && let Some(rva) = sec_rva.checked_add(i as u32)
                && in_sorted_ranges(funcs, rva)
            {
                sites.push(AotSite {
                    rva: rva as usize,
                    len: insn_len,
                    kind: AotKind::Insertq { dst, src, len, idx },
                });
                i += insn_len;
                continue;
            }
            i += 1;
        }
    }
    sites
}

fn tally_sites(sites: &[AotSite]) -> AotReport {
    let mut r = AotReport::default();
    for s in sites {
        match s.kind {
            AotKind::ClzeroLoop { .. } => r.clzero_loops += 1,
            AotKind::ClzeroPreIncLoop { .. } => r.clzero_preinc_loops += 1,
            AotKind::Wait { .. } => r.waits += 1,
            AotKind::Insertq { .. } => r.insertq += 1,
        }
    }
    r
}

/// Scans raw PE32+ bytes (an unpatched title exe or DLL) for statically
/// translatable console-only instruction sites.
pub fn scan_aot(original: &[u8]) -> Result<AotReport, victory_pe::PeError> {
    let info = victory_pe::ImageInfo::parse(original)?;
    let funcs = victory_pe::layout::data_directory_offset(original, victory_pe::layout::dir::EXCEPTION)
        .and_then(|at| {
            let rva = victory_pe::layout::read_u32(original, at)?;
            let size = victory_pe::layout::read_u32(original, at + 4)?;
            let off = info.rva_to_file_offset(rva)? as usize;
            let pdata = original.get(off..off.checked_add(size as usize)?)?;
            Some(parse_pdata(pdata))
        })
        .unwrap_or_default();
    let sections: Vec<(u32, &[u8])> = info
        .sections
        .iter()
        .filter(|s| s.characteristics & 0x2000_0000 != 0)
        .filter_map(|s| {
            let len = if s.virtual_size != 0 {
                s.virtual_size.min(s.file_size)
            } else {
                s.file_size
            } as usize;
            let off = s.file_offset as usize;
            let slice = original.get(off..off.checked_add(len)?)?;
            Some((s.rva, slice))
        })
        .collect();
    Ok(tally_sites(&scan_code_sections(&funcs, sections)))
}

fn clzero_preinc_stub(
    at: usize,
    stub: usize,
    code: &[u8; 15],
    ptr_reg: u8,
    end_reg: u8,
) -> Option<Vec<u8>> {
    let scratch = [1u8, 2, 3].into_iter().find(|&r| r != ptr_reg && r != end_reg)?;
    let mut out = Vec::with_capacity(96);
    out.push(0x50 + scratch); // push scratch
    let loop_start = out.len();
    out.extend_from_slice(&code[0..3]); // mov rax, ptr_reg
    out.extend_from_slice(&code[3..7]); // add ptr_reg, 0x40
    out.extend([0x48, 0x89, 0xC0 | scratch]); // mov scratch, rax
    out.extend([0x48, 0x83, 0xE0 | scratch, 0xC0]); // and scratch, -64
    for k in 0..8u8 {
        out.extend([0x48, 0xC7, 0x40 | scratch, k * 8, 0, 0, 0, 0]);
    }
    out.extend_from_slice(&code[10..13]); // cmp ptr_reg, end_reg
    let back = (loop_start as i64) - (out.len() as i64 + 2);
    out.extend([0x72, i8::try_from(back).ok()? as u8]); // jb loop_start
    out.push(0x58 + scratch); // pop scratch (preserves EFLAGS)
    out.extend(jump(stub + out.len(), at + 15)?);
    Some(out)
}

fn insertq_stub(
    at: usize,
    stub: usize,
    insn_len: usize,
    dst: u8,
    src: u8,
    len: u8,
    idx: u8,
) -> Option<Vec<u8>> {
    if dst >= 16 || src >= 16 || insn_len < 5 {
        return None;
    }
    let len_bits = match len & 63 {
        0 => 64u32,
        n => u32::from(n),
    };
    let idx_bits = u32::from(idx & 63);
    let ones = if len_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << len_bits) - 1
    };
    let mask = ones.checked_shl(idx_bits).unwrap_or(0);
    let movq_to_gp = |xmm: u8, gp: u8| -> [u8; 5] {
        [
            0x66,
            0x48 | (u8::from(xmm >= 8) << 2),
            0x0F,
            0x7E,
            0xC0 | ((xmm & 7) << 3) | (gp & 7),
        ]
    };
    let movq_from_gp = |xmm: u8, gp: u8| -> [u8; 5] {
        [
            0x66,
            0x48 | (u8::from(xmm >= 8) << 2),
            0x0F,
            0x6E,
            0xC0 | ((xmm & 7) << 3) | (gp & 7),
        ]
    };
    let mut out = Vec::with_capacity(80);
    out.extend([0x9C, 0x50, 0x51, 0x52]); // pushfq; push rax; push rcx; push rdx
    out.extend(movq_to_gp(dst, 0)); // movq rax, xmm(dst)
    out.extend(movq_to_gp(src, 1)); // movq rcx, xmm(src)
    if mask == u64::MAX {
        out.extend([0x48, 0x89, 0xC8]); // mov rax, rcx
    } else if mask != 0 {
        out.extend([0x48, 0xBA]); // mov rdx, !mask
        out.extend((!mask).to_le_bytes());
        out.extend([0x48, 0x21, 0xD0]); // and rax, rdx
        out.extend([0x48, 0xBA]); // mov rdx, ones
        out.extend(ones.to_le_bytes());
        out.extend([0x48, 0x21, 0xD1]); // and rcx, rdx
        if idx_bits > 0 {
            out.extend([0x48, 0xC1, 0xE1, idx_bits as u8]); // shl rcx, idx_bits
        }
        out.extend([0x48, 0x09, 0xC8]); // or rax, rcx
    }
    out.extend(movq_from_gp(dst, 0)); // movq xmm(dst), rax
    out.extend([0x5A, 0x59, 0x58, 0x9D]); // pop rdx; pop rcx; pop rax; popfq
    out.extend(jump(stub + out.len(), at + insn_len)?);
    Some(out)
}

static AOT_STUBS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

/// Applies `sites` statically into a single-threaded mapped image at `base`
/// (`size` bytes).
///
/// # Safety
/// `[base, base + size)` is mapped and no title thread executes it concurrently.
pub(crate) unsafe fn apply_aot_sites(base: usize, size: usize, sites: &[AotSite]) -> AotReport {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut report = AotReport::default();
    let mut stubs = AOT_STUBS.lock().unwrap_or_else(|e| e.into_inner());
    for site in sites {
        if site.rva.checked_add(site.len).is_none_or(|end| end > size) {
            continue;
        }
        let at = base + site.rva;
        let mut replacement = [0x90u8; 15];
        match site.kind {
            AotKind::Wait { replacement: wait } => {
                if site.len != 3 {
                    continue;
                }
                replacement[..3].copy_from_slice(&wait);
                report.waits += 1;
            }
            AotKind::ClzeroLoop { .. }
            | AotKind::ClzeroPreIncLoop { .. }
            | AotKind::Insertq { .. } => {
                if site.len < 5 || site.len > replacement.len() {
                    continue;
                }
                const RESERVE: usize = 112;
                let idx = stubs
                    .iter()
                    .position(|&(place, used)| {
                        used + RESERVE <= STUBS_LEN
                            && jump(at, place + used).is_some()
                            && jump(place + used + RESERVE, at + site.len).is_some()
                    })
                    .or_else(|| {
                        let place = near(at)?;
                        stubs.push((place, 0));
                        Some(stubs.len() - 1)
                    });
                let Some(idx) = idx else {
                    continue;
                };
                let (place, used) = &mut stubs[idx];
                let stub = *place + *used;
                let body = match site.kind {
                    AotKind::ClzeroLoop { cmp } => clzero_stub(at, stub, cmp),
                    AotKind::ClzeroPreIncLoop {
                        code,
                        ptr_reg,
                        end_reg,
                    } => clzero_preinc_stub(at, stub, &code, ptr_reg, end_reg),
                    AotKind::Insertq { dst, src, len, idx } => {
                        insertq_stub(at, stub, site.len, dst, src, len, idx)
                    }
                    AotKind::Wait { .. } => unreachable!(),
                };
                let Some(body) = body else {
                    continue;
                };
                if *used + body.len() > STUBS_LEN {
                    continue;
                }
                let Some(jmp) = jump(at, stub) else {
                    continue;
                };
                // SAFETY: `stub` lies inside our newly allocated RWX stub block.
                unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), stub as *mut u8, body.len()) };
                *used += body.len().next_multiple_of(16);
                replacement[..5].copy_from_slice(&jmp);
                match site.kind {
                    AotKind::ClzeroLoop { .. } => report.clzero_loops += 1,
                    AotKind::ClzeroPreIncLoop { .. } => report.clzero_preinc_loops += 1,
                    AotKind::Insertq { .. } => report.insertq += 1,
                    AotKind::Wait { .. } => unreachable!(),
                }
            }
        }
        let mut old = 0u32;
        // SAFETY: `[at, at + site.len)` is inside the mapped image and no thread runs it yet.
        unsafe {
            if VirtualProtect(at as *const _, site.len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                continue;
            }
            std::ptr::copy_nonoverlapping(replacement.as_ptr(), at as *mut u8, site.len);
            VirtualProtect(at as *const _, site.len, old, &mut old);
            FlushInstructionCache(GetCurrentProcess(), at as *const _, site.len);
        }
        report.patched += 1;
    }
    report
}

/// Statically translates console-only CPU instructions in a freshly loaded
/// image at `base` for the classes this host CPU lacks (unless
/// `VICTORY_AOT_CPU=0`).
///
/// # Safety
/// The image at `base` is mapped per `info` and no thread executes it yet.
pub unsafe fn pretranslate_loaded(base: usize, info: &victory_pe::ImageInfo) -> AotReport {
    if std::env::var_os("VICTORY_AOT_CPU").is_some_and(|v| v == "0") {
        return AotReport::default();
    }
    let cpu = host_cpu_support();
    if cpu.clzero && cpu.mwaitx && cpu.sse4a {
        return AotReport::default();
    }
    let size = info.size_of_image as usize;
    // SAFETY: PE headers at `base` up to `size` are mapped read-only by the OS loader.
    let funcs = unsafe {
        let header = std::slice::from_raw_parts(base as *const u8, size.min(0x2000));
        victory_pe::layout::data_directory_offset(header, victory_pe::layout::dir::EXCEPTION)
            .and_then(|at| {
                let rva = victory_pe::layout::read_u32(header, at)? as usize;
                let dir_len = victory_pe::layout::read_u32(header, at + 4)? as usize;
                if rva == 0 || dir_len < 12 || rva.checked_add(dir_len)? > size {
                    return None;
                }
                let pdata = std::slice::from_raw_parts((base + rva) as *const u8, dir_len);
                Some(parse_pdata(pdata))
            })
            .unwrap_or_default()
    };
    let sections: Vec<(u32, &[u8])> = info
        .sections
        .iter()
        .filter(|s| s.characteristics & 0x2000_0000 != 0)
        .filter_map(|s| {
            let len = if s.virtual_size != 0 {
                s.virtual_size.min(s.file_size)
            } else {
                s.file_size
            } as usize;
            let end = (s.rva as usize).checked_add(len)?;
            (end <= size).then(|| {
                // SAFETY: executable section slice inside the mapped image.
                (s.rva, unsafe { std::slice::from_raw_parts((base + s.rva as usize) as *const u8, len) })
            })
        })
        .collect();
    let mut sites = scan_code_sections(&funcs, sections);
    sites.retain(|s| match s.kind {
        AotKind::ClzeroLoop { .. } | AotKind::ClzeroPreIncLoop { .. } => !cpu.clzero,
        AotKind::Wait { .. } => !cpu.mwaitx,
        AotKind::Insertq { .. } => !cpu.sse4a,
    });
    if sites.is_empty() {
        return AotReport::default();
    }
    // SAFETY: caller guarantees single-threaded mapped image before execution.
    let report = unsafe { apply_aot_sites(base, size, &sites) };
    tracing::info!(
        clzero_loops = report.clzero_loops,
        clzero_preinc = report.clzero_preinc_loops,
        waits = report.waits,
        insertq = report.insertq,
        patched = report.patched,
        "static AOT CPU translation applied"
    );
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_instructions_are_replaced_inside_sixteen_aligned_bytes() {
        let word = u128::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 0x0f, 0x01, 0xfb, 11, 12, 13, 14, 15, 16]);
        let new = with_patch(word, 0x1007, &[0xf3, 0x90, 0x90]).unwrap();
        assert_eq!(new.to_le_bytes(), [1, 2, 3, 4, 5, 6, 7, 0xf3, 0x90, 0x90, 11, 12, 13, 14, 15, 16]);
        assert!(with_patch(word, 0x100d, &[0; 3]).is_some());
        assert!(with_patch(word, 0x100e, &[0; 3]).is_none(), "crosses into the next sixteen");
    }

    /// `monitorx; mwaitx; ret` in a page of its own: each is replaced at its first fault,
    /// and the page is protected as before.
    #[test]
    fn a_wait_faults_once_and_the_page_keeps_its_protection() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAlloc, VirtualFree,
            VirtualProtect, VirtualQuery,
        };
        // SAFETY: memory of our own, read, written and run within its page.
        unsafe {
            let page = VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE).cast::<u8>();
            assert!(!page.is_null());
            let code = [0x0f, 0x01, 0xfa, 0x0f, 0x01, 0xfb, 0xc3];
            // The first over the end of its aligned eight bytes, as the title's is; and one
            // over the end of its sixteen (at 46), which is left alone.
            std::ptr::copy_nonoverlapping(code.as_ptr(), page.add(6), code.len());
            std::ptr::copy_nonoverlapping(code.as_ptr(), page.add(46), code.len());
            let mut old = 0;
            assert_ne!(VirtualProtect(page.cast(), 4096, PAGE_EXECUTE_READ, &mut old), 0);
            let at = page as usize;
            let mut context: CONTEXT = std::mem::zeroed();
            for rip in [at + 6, at + 9, at + 46] {
                context.Rip = rip as u64;
                assert_eq!(emulate(&mut context), CONTINUE_EXECUTION);
                assert_eq!(context.Rip, rip as u64 + 3);
            }
            if patches_waits() {
                let now = std::slice::from_raw_parts(page.add(6), 7);
                assert_eq!(now, [0x0f, 0x1f, 0x00, 0xf3, 0x90, 0x90, 0xc3]);
                // They run now.
                let run: extern "system" fn() = std::mem::transmute(page.add(6));
                run();
                // A second thread that faulted at the same place meanwhile.
                assert!(patch(at + 6, [0x0f, 0x01, 0xfa], [0x0f, 0x1f, 0x00]));
                assert!(!patch(at + 46, [0x0f, 0x01, 0xfa], [0x0f, 0x1f, 0x00]), "crosses its sixteen bytes");
            }
            assert_eq!(std::slice::from_raw_parts(page.add(46), 3), [0x0f, 0x01, 0xfa]);
            let mut m: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            VirtualQuery(page.cast(), &mut m, size_of_val(&m));
            assert_eq!(m.Protect, PAGE_EXECUTE_READ);
            VirtualFree(page.cast(), 0, MEM_RELEASE);
        }
    }

    /// `clzero` loops run as plain stores: the lines they name are zero and no other byte,
    /// and the pointer, the scratch register and the flags come out as from the loop.
    #[test]
    fn a_clzero_loop_becomes_plain_stores() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree};
        // Against rdx (rm rax, reg rdx) and against rcx, the scratch register.
        for (cmp, by) in [([0x48, 0x39, 0xd0], 2), ([0x48, 0x39, 0xc8], 1), ([0x4c, 0x39, 0xc0], 8)] {
            // SAFETY: memory of our own, written and run inside it.
            unsafe {
                let page = VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as usize;
                assert_ne!(page, 0);
                // A function of (start, end): the start in rax, the end in its register, the
                // loop at 16, and what rax became.
                let mut head = vec![0x48, 0x89, 0xc8]; // mov rax, rcx
                match by {
                    1 => head.extend([0x48, 0x89, 0xd1]),  // mov rcx, rdx
                    8 => head.extend([0x49, 0x89, 0xd0]),  // mov r8, rdx
                    _ => {}
                }
                head.resize(16, 0x90);
                let mut code = head;
                code.extend([0x0f, 0x01, 0xfc, 0x48, 0x83, 0xc0, 0x40]);
                code.extend(cmp);
                code.extend([0x72, 0xf4]);
                code.push(0xc3);
                std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
                let mut context: CONTEXT = std::mem::zeroed();
                let mut block = vec![0xaau8; 64 * 8 + 64];
                let base = block.as_mut_ptr() as usize;
                let first = base.next_multiple_of(64);
                // The fault itself: emulated whole, and replaced.
                context.Rip = page as u64 + 16;
                context.Rax = first as u64;
                context.Rdx = first as u64 + 128;
                context.Rcx = context.Rdx;
                context.R8 = context.Rdx;
                assert_eq!(emulate(&mut context), CONTINUE_EXECUTION);
                assert_eq!((context.Rip, context.Rax), (page as u64 + 28, first as u64 + 128));
                if patches_clzero() {
                    assert_eq!(*((page + 16) as *const u8), 0xe9, "a jump");
                    block.fill(0xaa);
                    let run: extern "system" fn(usize, usize) -> usize = std::mem::transmute(page);
                    // From inside a line to inside the third: whole lines, one past the end.
                    assert_eq!(run(first + 8, first + 130), first + 8 + 128);
                    let at = first - base;
                    assert!(block[at..at + 128].iter().all(|&b| b == 0));
                    assert!(block[..at].iter().chain(&block[at + 128..]).all(|&b| b == 0xaa));
                    // An end at the start: one line.
                    block.fill(0xaa);
                    assert_eq!(run(first, first), first + 64);
                    assert!(block[at..at + 64].iter().all(|&b| b == 0) && block[at + 64] == 0xaa);
                }
                VirtualFree(page as *mut _, 0, MEM_RELEASE);
            }
        }
        assert!(clzero_stub(0x1000, 0x2000, [0x48, 0x39, 0xc0]).is_none(), "against rax itself");
        assert!(jump(0x1000, 0x9000_0000_0000).is_none(), "out of reach");
    }

    #[test]
    fn clzero_preinc_loop_becomes_plain_stores() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
        };
        // Case A: ptr = r10, end = r11 (`mov rax, r10; add r10, 0x40; clzero; cmp r10, r11; jb -15`)
        let loop_r10 = [
            0x4C, 0x89, 0xD0, 0x49, 0x83, 0xC2, 0x40, 0x0F, 0x01, 0xFC, 0x4D, 0x39, 0xDA, 0x72, 0xF1,
        ];
        // Case B: ptr = rdx, end = r8 (`mov rax, rdx; add rdx, 0x40; clzero; cmp rdx, r8; jb -15`)
        let loop_rdx = [
            0x48, 0x89, 0xD0, 0x48, 0x83, 0xC2, 0x40, 0x0F, 0x01, 0xFC, 0x4C, 0x39, 0xC2, 0x72, 0xF1,
        ];
        for (which, loop_bytes) in [(0, loop_r10), (1, loop_rdx)] {
            // SAFETY: fresh RWX buffer of our own, patched and called inside this test.
            unsafe {
                let page = VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as usize;
                assert_ne!(page, 0);
                // extern "C" fn(start: rcx, end: rdx, out_ptr: r8) -> rax
                let mut code = Vec::new();
                if which == 0 {
                    // mov r10, rcx; mov r11, rdx
                    code.extend([0x49, 0x89, 0xCA, 0x49, 0x89, 0xD3]);
                } else {
                    // mov r9, r8 (save out_ptr); mov r8, rdx (end); mov rdx, rcx (ptr)
                    code.extend([0x4D, 0x89, 0xC1, 0x49, 0x89, 0xD0, 0x48, 0x89, 0xCA]);
                }
                let loop_rva = code.len();
                code.extend_from_slice(&loop_bytes);
                if which == 0 {
                    code.extend([0x4D, 0x89, 0x10]); // mov [r8], r10
                } else {
                    code.extend([0x49, 0x89, 0x11]); // mov [r9], rdx
                }
                code.push(0xC3); // ret
                std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
                let sites = scan_code_sections(&[(0, code.len() as u32)], [(0, &code[..])]);
                assert_eq!(sites.len(), 1);
                let report = apply_aot_sites(page, 4096, &sites);
                assert_eq!((report.clzero_preinc_loops, report.patched), (1, 1));
                assert_eq!(*((page + loop_rva) as *const u8), 0xE9);

                let mut block = vec![0xAAu8; 64 * 8 + 64];
                let base = block.as_mut_ptr() as usize;
                let first = base.next_multiple_of(64);
                let run: extern "system" fn(usize, usize, *mut usize) -> usize = std::mem::transmute(page);
                let mut final_ptr = 0usize;
                let final_rax = run(first, first + 192, &raw mut final_ptr);
                assert_eq!(final_rax, first + 128);
                assert_eq!(final_ptr, first + 192);
                let at = first - base;
                assert!(block[at..at + 192].iter().all(|&b| b == 0));
                assert!(block[..at].iter().chain(&block[at + 192..]).all(|&b| b == 0xAA));
                VirtualFree(page as *mut _, 0, MEM_RELEASE);
            }
        }
    }

    #[test]
    fn insertq_imm_stub_matches_emulation_and_preserves_state() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
        };
        #[repr(C, align(16))]
        struct Io {
            dst_in: [u64; 2],
            src_in: [u64; 2],
            dst_out: [u64; 2],
            flags_before: u64,
            flags_after: u64,
        }
        let cases: [(u8, u8, u8, u8, u64, u64); 5] = [
            (0, 1, 16, 16, 0x1122_3344_5566_7788, 0xAAAA_BBBB_CCCC_DDDD),
            (14, 13, 16, 16, 0x0102_0304_0506_0708, 0xFEDC_BA98_7654_3210),
            (9, 7, 8, 24, 0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0042),
            (4, 5, 0, 0, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            (3, 3, 16, 48, 0x89AB_CDEF_0123_4567, 0x89AB_CDEF_0123_4567),
        ];
        for (dst, src, len, idx, dst_lo, src_lo) in cases {
            // SAFETY: fresh RWX buffer of our own, patched and called inside this test.
            unsafe {
                let page = VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) as usize;
                assert_ne!(page, 0);
                // extern "system" fn(io: *mut Io (rcx)) -> u64 (preserved rax check)
                let movdqu_load = |xmm: u8, disp: u8| -> Vec<u8> {
                    // F3 [44 if xmm>=8] 0F 6F [41 | (xmm&7)<<3] disp (load from [rcx+disp])
                    let mut v = vec![0xF3];
                    if xmm >= 8 {
                        v.push(0x44);
                    }
                    v.extend([0x0F, 0x6F, 0x41 | ((xmm & 7) << 3), disp]);
                    v
                };
                let movdqu_store = |xmm: u8, disp: u8| -> Vec<u8> {
                    let mut v = vec![0xF3];
                    if xmm >= 8 {
                        v.push(0x44);
                    }
                    v.extend([0x0F, 0x7F, 0x41 | ((xmm & 7) << 3), disp]);
                    v
                };
                let mut code = Vec::new();
                code.extend(movdqu_load(dst, 0));
                if src != dst {
                    code.extend(movdqu_load(src, 16));
                }
                code.extend([0x48, 0xB8]); // mov rax, 0x1357_2468_ABCD_EF01
                code.extend(0x1357_2468_ABCD_EF01u64.to_le_bytes());
                code.extend([0x48, 0xBA, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]); // mov rdx, ...
                code.extend([0x48, 0x83, 0xFA, 0x00]); // cmp rdx, 0
                code.extend([0x9C, 0x5A, 0x48, 0x89, 0x51, 48, 0x52, 0x9D]); // capture flags -> [rcx+48] and restore flags
                let insn_rva = code.len();
                code.push(0xF2);
                let rex = (u8::from(dst >= 8) << 2) | u8::from(src >= 8);
                if rex != 0 {
                    code.push(0x40 | rex);
                }
                code.extend([0x0F, 0x78, 0xC0 | ((dst & 7) << 3) | (src & 7), len, idx]);
                code.extend([0x9C, 0x5A, 0x48, 0x89, 0x51, 56]); // pushfq; pop rdx; mov [rcx+56], rdx
                code.extend(movdqu_store(dst, 32)); // store [rcx+32] = dst_out
                code.push(0xC3); // ret (returns rax)
                std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
                let sites = scan_code_sections(&[(0, code.len() as u32)], [(0, &code[..])]);
                assert_eq!(sites.len(), 1, "expected 1 insertq site for dst={dst}, src={src}");
                assert!(matches!(sites[0].kind, AotKind::Insertq { .. }));
                let report = apply_aot_sites(page, 4096, &sites);
                assert_eq!((report.insertq, report.patched), (1, 1));
                assert_eq!(*((page + insn_rva) as *const u8), 0xE9);

                let mut io = Io {
                    dst_in: [dst_lo, 0xDEAD_BEEF_CAFE_BABE],
                    src_in: [src_lo, 0x1122_3344_5566_7788],
                    dst_out: [0, 1],
                    flags_before: 0,
                    flags_after: 1,
                };
                let run: extern "system" fn(*mut Io) -> u64 = std::mem::transmute(page);
                let got_rax = run(&raw mut io);
                assert_eq!(got_rax, 0x1357_2468_ABCD_EF01);
                assert_eq!(io.dst_out[0], decode::insertq(dst_lo, src_lo, len, idx));
                assert_eq!(io.dst_out[1], 0, "high quadword must be zeroed");
                assert_eq!(io.flags_after, io.flags_before, "EFLAGS must be preserved");
                VirtualFree(page as *mut _, 0, MEM_RELEASE);
            }
        }
    }

    #[test]
    fn scan_ignores_call_displacements_and_finds_valid_sites() {
        let mut code = Vec::new();
        // False positive check 1: `call rel32` whose displacement contains `0f 01 fd` and `0f 01 fc`.
        code.extend([0x89, 0xF9, 0xE8, 0xCA, 0x0F, 0x01, 0xFD]);
        code.extend([0x89, 0xCF, 0xE8, 0x46, 0x0F, 0x01, 0xFC]);
        // Valid 12-byte clzero loop
        code.extend([0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x4C, 0x39, 0xD0, 0x72, 0xF4]);
        // Valid 15-byte preinc clzero loop
        code.extend([0x4C, 0x89, 0xD0, 0x49, 0x83, 0xC2, 0x40, 0x0F, 0x01, 0xFC, 0x4D, 0x39, 0xDA, 0x72, 0xF1]);
        // Valid monitorx / mwaitx
        code.extend([0x31, 0xC9, 0x31, 0xD2, 0x0F, 0x01, 0xFA]);
        code.extend([0x31, 0xC0, 0x0F, 0x01, 0xFB]);
        // Valid insertq inside function bounds
        code.extend([0xF2, 0x44, 0x0F, 0x78, 0xCF, 0x08, 0x00]);
        // Trailing bytes NOT in .pdata should be ignored for insertq
        let fn_end = code.len() as u32;
        code.extend([0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x10]);

        let sites = scan_code_sections(&[(0, fn_end)], [(0, &code[..])]);
        let r = tally_sites(&sites);
        assert_eq!(
            (r.clzero_loops, r.clzero_preinc_loops, r.waits, r.insertq),
            (1, 1, 2, 1),
            "sites: {sites:?}"
        );
    }
}
