use bitcoin_hashes::sha256::{HashEngine, Midstate};
use bitcoin_hashes::sha256t::Hash;
use bitcoin_hashes::sha256t::Tag;

use secp256k1::{SECP256K1, SecretKey, PublicKey, Keypair, Message};
use secp256k1::ellswift::{ElligatorSwiftParty, ElligatorSwift};
use secp256k1::schnorr::Signature;
use secp256k1::rand;

use bitcoin::bip32::{ChildNumber, ChainCode, Xpriv};

use chacha20_poly1305::{ChaCha20Poly1305, Nonce, Key};

use secp256k1::Error;

mod signed;
pub use signed::Signed;

const MIDSTATE: Midstate = Midstate::hash_tag(b"SECP256K1_EASY");
const DATA: &str = "easy_secp256k1_ellswift_xonly_ecdh";

struct HashReader(Vec<u8>);
impl core::hash::Hasher for HashReader {
    fn finish(&self) -> u64 {panic!("NOOP");}
    fn write(&mut self, bytes: &[u8]) {self.0.extend(bytes);}
}

pub struct EasyTag;
impl Tag for EasyTag {
    fn engine() -> HashEngine {HashEngine::from_midstate(MIDSTATE)}
}
///Tagged Sha256 Hasher
pub type EasyHash = Hash<EasyTag>;

pub trait Hashable {
    fn core_hash<H: core::hash::Hash>(hashable: &H) -> Self where Self: Sized;
}

impl Hashable for EasyHash {
   fn core_hash<H: core::hash::Hash>(hashable: &H) -> Self {
        let mut reader = HashReader(Vec::new());
        hashable.hash(&mut reader);
        EasyHash::hash(&reader.0)
   }
}

pub trait EasyPublicKey {
    fn easy_verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error>;
    fn easy_encrypt(&self, payload: Vec<u8>) -> Result<Vec<u8>, Error>;
}
impl EasyPublicKey for PublicKey {
    fn easy_verify(&self, signature: &Signature, payload: &[u8]) -> Result<(), Error> {
        signature.verify(
            &Message::from_digest(*EasyHash::hash(payload).as_ref()),
            &self.x_only_public_key().0
        )
    }

    fn easy_encrypt(&self, mut payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        let secret = SecretKey::easy_new();
        let mine = ElligatorSwift::from_pubkey(secret.easy_public_key());
        let theirs = ElligatorSwift::from_pubkey(*self);
        let ecdh_sk = ElligatorSwift::shared_secret(mine, theirs, secret, ElligatorSwiftParty::A, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());
        Ok([
            mine.to_array().to_vec(),//TODO: unencrypted
            ChaCha20Poly1305::new(key, Nonce::new([0; 12])).encrypt(&mut payload, None).to_vec(),
            payload
        ].concat())
    }
}

pub trait EasySecretKey {
    fn easy_new() -> Self where Self: Sized;
    fn easy_sign(&self, payload: &[u8]) -> Signature;
    fn easy_decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error>;
    fn easy_public_key(&self) -> PublicKey;
    fn easy_derive(&self, path: &[u16]) -> Result<Self, Error> where Self: Sized;
}

impl EasySecretKey for SecretKey {
    fn easy_new() -> Self {SecretKey::new(&mut rand::thread_rng())}

    fn easy_public_key(&self) -> PublicKey {self.public_key(SECP256K1)}

    fn easy_sign(&self, payload: &[u8]) -> Signature {
        let keypair = Keypair::from_secret_key(SECP256K1, self);
        SECP256K1.sign_schnorr(&Message::from_digest(*EasyHash::hash(payload).as_ref()), &keypair)
    }

    fn easy_decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if payload.len() < 64+16 {return Err(Error::InvalidMessage);}
        let theirs = ElligatorSwift::from_array(payload[0..64].try_into().or(Err(Error::InvalidMessage))?);
        let tag: [u8; 16] = payload[64..64+16].try_into().or(Err(Error::InvalidMessage))?;
        let mut payload = payload[64+16..].to_vec();

        let mine = ElligatorSwift::from_pubkey(self.easy_public_key());
        let ecdh_sk = ElligatorSwift::shared_secret(theirs, mine, *self, ElligatorSwiftParty::B, Some(DATA.as_bytes()));
        let key = Key::new(ecdh_sk.to_secret_bytes());

        ChaCha20Poly1305::new(key, Nonce::new([0; 12])).decrypt(&mut payload, tag, None).map_err(|_| Error::InvalidMessage)?;
        Ok(payload)
    }

    fn easy_derive(&self, path: &[u16]) -> Result<Self, Error> {
        let x_priv = Xpriv{
            network: bitcoin::Network::Bitcoin.into(),
            depth: 0,
            parent_fingerprint: [0; 4].into(),
            child_number: ChildNumber::from_hardened_idx(0).unwrap(),
            private_key: *self,
            chain_code: ChainCode::from(self.secret_bytes())
        };
        let path = path.iter().map(|i| ChildNumber::from_hardened_idx((*i).into()).unwrap()).collect::<Vec<_>>();
        let r_priv = x_priv.derive_priv(SECP256K1, &path).unwrap().to_priv().inner;
        Ok(r_priv)
    }
}

#[test]
fn signature() {
    let secret_key = SecretKey::easy_new();
    let message = b"my message";
    let signature = secret_key.easy_sign(message);

    let public_key = secret_key.easy_public_key();
    public_key.easy_verify(message, &signature).unwrap();
}

#[test]
fn encryption() {
    let secret_key = SecretKey::easy_new();
    let public_key = secret_key.easy_public_key();

    let message = b"my message".to_vec();
    let payload = public_key.easy_encrypt(message.clone()).unwrap();

    assert_eq!(message, secret_key.easy_decrypt(&payload).unwrap());
}
