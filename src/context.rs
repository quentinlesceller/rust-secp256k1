use core::marker::PhantomData;
use core::mem;
use ffi::{self, types::AlignedType};
use ffi::types::{c_uint};
use Secp256k1;

#[cfg(feature = "std")]
pub use self::std_only::*;

#[cfg(feature = "global-context")]
/// Module implementing a singleton pattern for a global `Secp256k1` context
pub mod global {
    use rand;
    use std::ops::Deref;
    use std::sync::Once;
    use {Secp256k1, All};

    /// Proxy struct for global `SECP256K1` context
    pub struct GlobalContext {
        __private: (),
    }

    /// A global, static context to avoid repeatedly creating contexts where one can't be passed
    pub static SECP256K1: &GlobalContext = &GlobalContext { __private: () };

    impl Deref for GlobalContext {
        type Target = Secp256k1<All>;

        fn deref(&self) -> &Self::Target {
            static ONCE: Once = Once::new();
            static mut CONTEXT: Option<Secp256k1<All>> = None;
            ONCE.call_once(|| unsafe {
                let mut ctx = Secp256k1::new();
                ctx.randomize(&mut rand::thread_rng());
                CONTEXT = Some(ctx);
            });
            unsafe { CONTEXT.as_ref().unwrap() }
        }
    }
}


/// A trait for all kinds of Context's that Lets you define the exact flags and a function to deallocate memory.
/// It shouldn't be possible to implement this for types outside this crate.
pub unsafe trait Context : private::Sealed {
    /// Flags for the ffi.
    const FLAGS: c_uint;
    /// A constant description of the context.
    const DESCRIPTION: &'static str;
    /// A function to deallocate the memory when the context is dropped.
    unsafe fn deallocate(ptr: *mut u8, size: usize);
}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing.
pub trait Signing: Context {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for verification.
pub trait Verification: Context {}

/// Marker trait for indicating that an instance of `Secp256k1` can be used for signing, verification and pedersen commitments.
pub trait Commit: Context {}

/// Represents the set of capabilities needed for signing with a user preallocated memory.
pub struct SignOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of capabilities needed for verification with a user preallocated memory.
pub struct VerifyOnlyPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

/// Represents the set of all capabilities with a user preallocated memory.
pub struct AllPreallocated<'buf> {
    phantom: PhantomData<&'buf ()>,
}

mod private {
    use super::*;
    // A trick to prevent users from implementing a trait.
    // on one hand this trait is public, on the other it's in a private module
    // so it's not visible to anyone besides it's parent (the context module)
    pub trait Sealed {}

    impl<'buf> Sealed for AllPreallocated<'buf> {}
    impl<'buf> Sealed for VerifyOnlyPreallocated<'buf> {}
    impl<'buf> Sealed for SignOnlyPreallocated<'buf> {}
}

#[cfg(feature = "std")]
mod std_only {
    impl private::Sealed for SignOnly {}
    impl private::Sealed for All {}
    impl private::Sealed for VerifyOnly {}

    use super::*;
    use std::alloc;
    const ALIGN_TO: usize = mem::align_of::<AlignedType>();

    /// Represents the set of capabilities needed for signing.
    pub enum SignOnly {}

    /// Represents the set of capabilities needed for verification.
    pub enum VerifyOnly {}

    /// Represents the set of all capabilities.
    pub enum All {}

    impl Signing for SignOnly {}
    impl Signing for All {}

    impl Verification for VerifyOnly {}
    impl Verification for All {}

    unsafe impl Context for SignOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_SIGN;
        const DESCRIPTION: &'static str = "signing only";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    unsafe impl Context for VerifyOnly {
        const FLAGS: c_uint = ffi::SECP256K1_START_VERIFY;
        const DESCRIPTION: &'static str = "verification only";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    unsafe impl Context for All {
        const FLAGS: c_uint = VerifyOnly::FLAGS | SignOnly::FLAGS;
        const DESCRIPTION: &'static str = "all capabilities";

        unsafe fn deallocate(ptr: *mut u8, size: usize) {
            let layout = alloc::Layout::from_size_align(size, ALIGN_TO).unwrap();
            alloc::dealloc(ptr, layout);
        }
    }

    impl<C: Context> Secp256k1<C> {
        /// Lets you create a context in a generic manner(sign/verify/all)
        pub fn gen_new() -> Secp256k1<C> {
            #[cfg(target_arch = "wasm32")]
            ffi::types::sanity_checks_for_wasm();

            let size = 0;
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_create(C::FLAGS) },
                phantom: PhantomData,
                size,
            }
        }
    }

    impl Secp256k1<All> {
        /// Creates a new Secp256k1 context with all capabilities
        pub fn new() -> Secp256k1<All> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<SignOnly> {
        /// Creates a new Secp256k1 context that can only be used for signing
        pub fn signing_only() -> Secp256k1<SignOnly> {
            Secp256k1::gen_new()
        }
    }

    impl Secp256k1<VerifyOnly> {
        /// Creates a new Secp256k1 context that can only be used for verification
        pub fn verification_only() -> Secp256k1<VerifyOnly> {
            Secp256k1::gen_new()
        }
    }

    impl Default for Secp256k1<All> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<C: Context> Clone for Secp256k1<C> {
        fn clone(&self) -> Secp256k1<C> {
            let size = 0;
            Secp256k1 {
                ctx: unsafe { ffi::secp256k1_context_clone(self.ctx) },
                phantom: PhantomData,
                size,
            }
        }
    }
}
