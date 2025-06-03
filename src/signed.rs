use super::{EasySecretKey, EasyPublicKey, EasyHash, Hashable, Error};
use secp256k1::{SecretKey, PublicKey};
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Signed", 3)?;
        s.serialize_field("signer", &self.0)?;
        s.serialize_field("signature", &self.1)?;
        s.serialize_field("inner", &self.2)?;
        s.end()
    }
}

#[cfg(feature = "serde")]
use serde::de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};
#[cfg(feature = "serde")]
impl<'de, T: Hash + Deserialize<'de>> Deserialize<'de> for Signed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Signer, Signature, Inner }

        struct SignedVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Hash + Deserialize<'de>> Visitor<'de> for SignedVisitor<T> {
            type Value = Signed<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Signed")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Signed<T>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let signer = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let signature = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let inner = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                Ok(Signed(signer, signature, inner))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Signed<T>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut signer = None;
                let mut signature = None;
                let mut inner = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Signer => {
                            if signer.is_some() {
                                return Err(de::Error::duplicate_field("signer"));
                            }
                            signer = Some(map.next_value()?);
                        },
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        },
                        Field::Inner => {
                            if inner.is_some() {
                                return Err(de::Error::duplicate_field("inner"));
                            }
                            inner = Some(map.next_value()?);
                        }
                    }
                }
                let signer = signer.ok_or_else(|| de::Error::missing_field("signer"))?;
                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                let inner = inner.ok_or_else(|| de::Error::missing_field("inner"))?;
                Ok(Signed(signer, signature, inner))
            }
        }

        const FIELDS: &[&str] = &["signed", "signature", "inner"];
        deserializer.deserialize_struct("Signed", FIELDS, SignedVisitor(std::marker::PhantomData::<T>))
    }
}
