use super::{EasySecretKey, EasyPublicKey, EasyHash, Hashable};
use secp256k1::{SecretKey, PublicKey, Error};
use secp256k1::schnorr::Signature;
use std::hash::{Hasher, Hash};
use std::fmt::Debug;

pub struct Signed<T: Hash>(PublicKey, Signature, T);

impl<T: Hash> Signed<T> {
    pub fn new(inner: T, key: &SecretKey) -> Self {
        let signature = key.easy_sign(EasyHash::core_hash(&inner).as_ref());
        Signed(key.easy_public_key(), signature, inner)
    }
    pub fn into_inner(self) -> T {self.2}
    pub fn signer(&self) -> &PublicKey {&self.0}
    pub fn verify(&self) -> Result<PublicKey, Error> {
        self.0.easy_verify(&self.1, EasyHash::core_hash(&self.2).as_ref())?;
        Ok(self.0)
    }
}

///Signed is hashed by the signing key and the inner content ignoring the signature
impl<T: Hash> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {self.0.hash(state); self.2.hash(state);}
}

impl<T: Hash> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {&self.2}
}

impl<T: Hash + Clone> Clone for Signed<T> {
    fn clone(&self) -> Self {Signed(self.0, self.1, self.2.clone())}
}
impl<T: Hash + Copy> Copy for Signed<T> {}

impl<T: Hash + Debug> Debug for Signed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
         .field("signer", &self.0)
         .field("signature", &self.1)
         .field("inner", &self.2)
         .finish()
    }
}

#[cfg(feature = "serde")]
use serde::ser::{Serializer, Serialize, SerializeStruct};
#[cfg(feature = "serde")]
impl<T: Hash + Serialize> Serialize for Signed<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (&self.0, &self.1, &self.2).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
use serde::de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};
#[cfg(feature = "serde")]
impl<'de, T: Hash + Deserialize<'de>> Deserialize<'de> for Signed<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (zero, one, two) = <(PublicKey, Signature, T)>::deserialize(deserializer);
        Signed(zero, one, tw)
    }
}
