// Copyright 2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Backtrace strategy for MSVC platforms.
//!
//! This module contains the ability to generate a backtrace on MSVC using one
//! of two possible methods. The `StackWalkEx` function is primarily used if
//! possible, but not all systems have that. Failing that the `StackWalk64`
//! function is used instead. Note that `StackWalkEx` is favored because it
//! handles debuginfo internally and returns inline frame information.
//!
//! Note that all dbghelp support is loaded dynamically, see `src/dbghelp.rs`
//! for more information about that.

#![allow(bad_style)]

use super::super::{dbghelp, windows::*};
use core::ffi::c_void;
use core::mem;

#[derive(Clone, Copy)]
pub enum Frame {
    New(STACKFRAME_EX),
    Old(STACKFRAME64),
}

// we're just sending around raw pointers and reading them, never interpreting
// them so this should be safe to both send and share across threads.
unsafe impl Send for Frame {}
unsafe impl Sync for Frame {}

impl Frame {
    pub fn ip(&self) -> *mut c_void {
        self.addr_pc().Offset as *mut _
    }

    pub fn sp(&self) -> *mut c_void {
        self.addr_stack().Offset as *mut _
    }

    pub fn symbol_address(&self) -> *mut c_void {
        self.ip()
    }

    fn addr_pc(&self) -> &ADDRESS64 {
        match self {
            Frame::New(new) => &new.AddrPC,
            Frame::Old(old) => &old.AddrPC,
        }
    }

    fn addr_pc_mut(&mut self) -> &mut ADDRESS64 {
        match self {
            Frame::New(new) => &mut new.AddrPC,
            Frame::Old(old) => &mut old.AddrPC,
        }
    }

    fn addr_frame_mut(&mut self) -> &mut ADDRESS64 {
        match self {
            Frame::New(new) => &mut new.AddrFrame,
            Frame::Old(old) => &mut old.AddrFrame,
        }
    }

    fn addr_stack(&self) -> &ADDRESS64 {
        match self {
            Frame::New(new) => &new.AddrStack,
            Frame::Old(old) => &old.AddrStack,
        }
    }

    fn addr_stack_mut(&mut self) -> &mut ADDRESS64 {
        match self {
            Frame::New(new) => &mut new.AddrStack,
            Frame::Old(old) => &mut old.AddrStack,
        }
    }
}

#[repr(C, align(16))] // required by `CONTEXT`, is a FIXME in winapi right now
struct MyContext(CONTEXT);

#[inline(always)]
pub unsafe fn trace(cb: &mut dyn FnMut(&super::Frame) -> bool) {
    // Allocate necessary structures for doing the stack walk
    let process = GetCurrentProcess();
    let thread = GetCurrentThread();

    let mut context = mem::zeroed::<MyContext>();

    cfg_if::cfg_if! {
        if #[cfg(any(not(target_arch = "x86"), target_api_feature = "5.1.2600"))] {
            RtlCaptureContext(&mut context.0);
        } else {
            rtl_capture_context(&mut context.0 as *mut _);
        }
    }

    // Ensure this process's symbols are initialized
    let dbghelp = match dbghelp::init() {
        Ok(dbghelp) => dbghelp,
        Err(()) => return, // oh well...
    };

    // On x86_64 and ARM64 we opt to not use the default `Sym*` functions from
    // dbghelp for getting the function table and module base. Instead we use
    // the `RtlLookupFunctionEntry` function in kernel32 which will account for
    // JIT compiler frames as well. These should be equivalent, but using
    // `Rtl*` allows us to backtrace through JIT frames.
    //
    // Note that `RtlLookupFunctionEntry` only works for in-process backtraces,
    // but that's all we support anyway, so it all lines up well.
    cfg_if::cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            use core::ptr;

            unsafe extern "system" fn function_table_access(_process: HANDLE, addr: DWORD64) -> PVOID {
                let mut base = 0;
                RtlLookupFunctionEntry(addr, &mut base, ptr::null_mut()).cast()
            }

            unsafe extern "system" fn get_module_base(_process: HANDLE, addr: DWORD64) -> DWORD64 {
                let mut base = 0;
                RtlLookupFunctionEntry(addr, &mut base, ptr::null_mut());
                base
            }
        } else {
            let function_table_access = dbghelp.SymFunctionTableAccess64();
            let get_module_base = dbghelp.SymGetModuleBase64();
        }
    }

    // Attempt to use `StackWalkEx` if we can, but fall back to `StackWalk64`
    // since it's in theory supported on more systems.
    match (*dbghelp.dbghelp()).StackWalkEx() {
        Some(StackWalkEx) => {
            let mut frame = super::Frame {
                inner: Frame::New(mem::zeroed()),
            };
            let image = init_frame(&mut frame.inner, &context.0);
            let frame_ptr = match &mut frame.inner {
                Frame::New(ptr) => ptr as *mut STACKFRAME_EX,
                _ => unreachable!(),
            };

            while StackWalkEx(
                image as DWORD,
                process,
                thread,
                frame_ptr,
                &mut context.0 as *mut CONTEXT as *mut _,
                None,
                Some(function_table_access),
                Some(get_module_base),
                None,
                0,
            ) == TRUE
            {
                if !cb(&frame) {
                    break;
                }
            }
        }
        None => {
            let mut frame = super::Frame {
                inner: Frame::Old(mem::zeroed()),
            };
            let image = init_frame(&mut frame.inner, &context.0);
            let frame_ptr = match &mut frame.inner {
                Frame::Old(ptr) => ptr as *mut STACKFRAME64,
                _ => unreachable!(),
            };

            while dbghelp.StackWalk64()(
                image as DWORD,
                process,
                thread,
                frame_ptr,
                &mut context.0 as *mut CONTEXT as *mut _,
                None,
                Some(function_table_access),
                Some(get_module_base),
                None,
            ) == TRUE
            {
                if !cb(&frame) {
                    break;
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Rip as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Rsp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    frame.addr_frame_mut().Offset = ctx.Rbp as u64;
    frame.addr_frame_mut().Mode = AddrModeFlat;

    IMAGE_FILE_MACHINE_AMD64
}

#[cfg(target_arch = "x86")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Eip as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Esp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    frame.addr_frame_mut().Offset = ctx.Ebp as u64;
    frame.addr_frame_mut().Mode = AddrModeFlat;

    IMAGE_FILE_MACHINE_I386
}

#[cfg(target_arch = "aarch64")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Pc as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Sp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    unsafe {
        frame.addr_frame_mut().Offset = ctx.u.s().Fp as u64;
    }
    frame.addr_frame_mut().Mode = AddrModeFlat;
    IMAGE_FILE_MACHINE_ARM64
}

#[cfg(target_arch = "arm")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Pc as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Sp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    unsafe {
        frame.addr_frame_mut().Offset = ctx.R11 as u64;
    }
    frame.addr_frame_mut().Mode = AddrModeFlat;
    IMAGE_FILE_MACHINE_ARMNT
}

/// Manual implementation of RtlCaptureContext for pre-XP systems
#[cfg(all(target_arch = "x86", not(target_api_feature = "5.1.2600")))]
#[naked]
#[inline(never)]
unsafe extern "system" fn rtl_capture_context(context: *mut CONTEXT) {
    const SEGGS: u8 = 0x8C;
    const SEGFS: u8 = 0x90;
    const SEGES: u8 = 0x94;
    const SEGDS: u8 = 0x98;
    const EDI: u8 = 0x9C;
    const ESI: u8 = 0xA0;
    const EBX: u8 = 0xA4;
    const EDX: u8 = 0xA8;
    const ECX: u8 = 0xAC;
    const EAX: u8 = 0xB0;
    const EBP: u8 = 0xB4;
    const EIP: u8 = 0xB8;
    const SEGCS: u8 = 0xBC;
    const EFLAGS: u8 = 0xC0;
    const ESP: u8 = 0xC4;
    const SEGSS: u8 = 0xC8;

    const CONTEXT_FLAGS: u8 = 0x00;
    const CONTEXT_FULL: u32 = 0x10007;

    asm!(
        "push ebx",
        "mov ebx, [esp+8]",
        "mov [ebx+{}], eax",
        "mov eax, [esp]",
        "mov [ebx+{}], eax",
        "mov [ebx+{}], ecx",
        "mov [ebx+{}], edx",
        "mov [ebx+{}], esi",
        "mov [ebx+{}], edi",

        "mov [ebx+{}], cs",
        "mov [ebx+{}], ds",
        "mov [ebx+{}], es",
        "mov [ebx+{}], fs",
        "mov [ebx+{}], gs",
        "mov [ebx+{}], ss",
        "pushf",
        "pop dword ptr [ebx+{}]",
        "mov eax, [ebp]",
        "mov [ebx+{}], eax",
        "mov eax, [ebp+4]",
        "mov [ebx+{}], eax",
        "lea eax, [ebp+8]",
        "mov [ebx+{}], eax",
        "mov dword ptr [ebx+{}], {}",
        "pop ebx",
        "ret 4",
        const EAX,
        const EBX,
        const ECX,
        const EDX,
        const ESI,
        const EDI,

        const SEGCS,
        const SEGDS,
        const SEGES,
        const SEGFS,
        const SEGGS,
        const SEGSS,

        const EFLAGS,

        const EBP,
        const EIP,
        const ESP,
        const CONTEXT_FLAGS,
        const CONTEXT_FULL,
        out("eax") _,
    );
}
