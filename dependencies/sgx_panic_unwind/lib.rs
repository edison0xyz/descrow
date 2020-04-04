//! Implementation of panics via stack unwinding
//!
//! This crate is an implementation of panics in Rust using "most native" stack
//! unwinding mechanism of the platform this is being compiled for. This
//! essentially gets categorized into three buckets currently:
//!
//! 1. MSVC targets use SEH in the `seh.rs` file.
//! 2. The 64-bit MinGW target half-uses SEH and half-use gcc-like information
//!    in the `seh64_gnu.rs` module.
//! 3. All other targets use libunwind/libgcc in the `gcc/mod.rs` module.
//!
//! More documentation about each implementation can be found in the respective
//! module.

#![no_std]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]
#![unstable(feature = "panic_unwind", issue = "32837")]
#![feature(core_intrinsics)]
#![feature(lang_items)]
#![feature(nll)]
#![feature(panic_unwind)]
#![feature(raw)]
#![feature(staged_api)]
#![feature(std_internals)]
#![feature(unwind_attributes)]

#![panic_runtime]
#![feature(panic_runtime)]

extern crate alloc;
extern crate sgx_libc;
extern crate sgx_unwind;

use alloc::boxed::Box;
use core::intrinsics;
use core::mem;
use core::raw;
use core::panic::BoxMeUp;


#[path = "gcc.rs"]
mod imp;
mod dwarf;

// Entry point for catching an exception, implemented using the `try` intrinsic
// in the compiler.
//
// The interaction between the `payload` function and the compiler is pretty
// hairy and tightly coupled, for more information see the compiler's
// implementation of this.
#[no_mangle]
pub unsafe extern "C" fn __rust_maybe_catch_panic(f: fn(*mut u8),
                                                  data: *mut u8,
                                                  data_ptr: *mut usize,
                                                  vtable_ptr: *mut usize)
                                                  -> u32 {
    let mut payload = imp::payload();
    if intrinsics::r#try(f, data, &mut payload as *mut _ as *mut _) == 0 {
        0
    } else {
        let obj = mem::transmute::<_, raw::TraitObject>(imp::cleanup(payload));
        *data_ptr = obj.data as usize;
        *vtable_ptr = obj.vtable as usize;
        1
    }
}

// Entry point for raising an exception, just delegates to the platform-specific
// implementation.
#[no_mangle]
#[unwind(allowed)]
pub unsafe extern "C" fn __rust_start_panic(payload: usize) -> u32 {
    let payload = payload as *mut &mut dyn BoxMeUp;
    imp::panic(Box::from_raw((*payload).take_box()))
}
