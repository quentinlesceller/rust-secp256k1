//! # schnorrsig
//! Support for Schnorr signatures.
//!

use super::Error::InvalidSignature;
use super::{from_hex, Error};
use core::{fmt, str};
use ffi::{self, CPtr};
use {constants, Secp256k1};
use {Message, Signing, Verification};

/// Represents a Schnorr signature.
pub struct Signature([u8; constants::SCHNORRSIG_SIGNATURE_SIZE]);
impl_array_newtype!(Signature, u8, constants::SCHNORRSIG_SIGNATURE_SIZE);
impl_pretty_debug!(Signature);
serde_impl!(Signature, constants::SCHNORRSIG_SIGNATURE_SIZE);

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0; constants::SCHNORRSIG_SIGNATURE_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORRSIG_SIGNATURE_SIZE) => {
                Signature::from_slice(&res[0..constants::SCHNORRSIG_SIGNATURE_SIZE])
            }
            _ => Err(Error::InvalidSignature),
        }
    }
}

/// Opaque data structure that holds a keypair consisting of a secret and a public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct KeyPair(ffi::KeyPair);

/// A Schnorr public key, used for verification of Schnorr signatures
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct PublicKey(ffi::XOnlyPublicKey);

impl Signature {
    /// Creates a Signature directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Signature, Error> {
        match data.len() {
            constants::SCHNORRSIG_SIGNATURE_SIZE => {
                let mut ret = [0; constants::SCHNORRSIG_SIGNATURE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(Signature(ret))
            }
            _ => Err(InvalidSignature),
        }
    }
}

impl KeyPair {
    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::KeyPair {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::KeyPair {
        &mut self.0
    }

    /// Tweak a keypair by adding the given tweak to the secret key and updating the
    /// public key accordingly.
    /// Will return an error if the resulting key would be invalid or if
    /// the tweak was not a 32-byte length slice.
    #[inline]
    pub fn tweak_add_assign<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &[u8],
    ) -> Result<(), Error> {
        if tweak.len() != 32 {
            return Err(Error::InvalidTweak);
        }

        unsafe {
            let err = ffi::secp256k1_keypair_xonly_tweak_add(
                secp.ctx,
                &mut self.0,
                tweak.as_c_ptr(),
            );

            if err == 1 {
                Ok(())
            } else {
                Err(Error::InvalidTweak)
            }
        }
    }
}

impl PublicKey {
    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::XOnlyPublicKey {
        &self.0
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::XOnlyPublicKey {
        &mut self.0
    }
}

impl CPtr for PublicKey {
    type Target = ffi::XOnlyPublicKey;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

/// Creates a new Schnorr public key from a FFI x-only public key
impl From<ffi::XOnlyPublicKey> for PublicKey {
    #[inline]
    fn from(pk: ffi::XOnlyPublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

serde_impl_from_slice!(PublicKey);

impl<C: Signing> Secp256k1<C> {
    /// Verify a Schnorr signature.
    pub fn schnorrsig_verify(
        &self,
        sig: &Signature,
        msg: &Message,
        pubkey: &PublicKey,
    ) -> Result<(), Error> {
        unsafe {
            let ret = ffi::secp256k1_schnorrsig_verify(
                self.ctx,
                sig.as_c_ptr(),
                msg.as_c_ptr(),
                pubkey.as_c_ptr(),
            );

            if ret == 1 {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }
}
