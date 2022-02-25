use secp256k1::{Message, Secp256k1, SecretKey};
use rlp::{RlpStream};
use tiny_keccak::{Keccak, Hasher};
use hex;

const ETH_CHAIN_ID: u64 = 1;
const RINKEBY_CHAIN_ID: u64 = 4;
const SK_TEST_1: &str = "4646464646464646464646464646464646464646464646464646464646464646";

#[derive(Debug, PartialEq)]
pub struct LegacyTransaction {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    pub to: Vec<u8>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl LegacyTransaction {
    /// Creates a new legacy transaction with v as chain_id, and r,s initialized to 0
    pub fn new(
        nonce: u128,
        gas_price: u128,
        gas_limit: u128,
        to: Vec<u8>,
        value: u128,
        data: Vec<u8>,
        chain_id: u64
    ) -> Self {
        LegacyTransaction {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            v: chain_id,
            r: vec![0],
            s: vec![0],
        }
    }

    /// Signs the raw transaction, returning the RLP-encoded transaction
    pub fn sign(&mut self, secret_key: &[u8]) -> Vec<u8> {
        let encoded_txn = self.rlp_encode();
        let hashed_txn = keccak256(&encoded_txn);
        let sig = EcdsaSig::ecdsa_sign(&hashed_txn, secret_key);

        self.v = sig.v + self.v * 2 + 35;
        self.r = sig.r;
        self.s = sig.s;
        
        self.rlp_encode()
    }

    /// Serializes the transaction with RLP algorithm
    fn rlp_encode(&self) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.to);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
        s.out().to_vec()
    }
}

/// Hashes arbitrary data input
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn ecdsa_sign(data: &[u8], secret_key: &[u8]) -> Self {
        let secp = Secp256k1::new();
        let msg = Message::from_slice(data).unwrap();
        let sk = SecretKey::from_slice(secret_key).unwrap();
        let (recovery_id, sig_bytes) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();

        EcdsaSig {
            v: recovery_id.to_i32() as u64,
            r: sig_bytes[0..32].to_vec(),
            s: sig_bytes[32..].to_vec(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rlp_encode_txn() {
        let nonce = u128::from_str_radix("9", 16).unwrap();
        let gas_price = u128::from_str_radix("4a817c800", 16).unwrap();
        let gas_limit = u128::from_str_radix("5208", 16).unwrap();
        let to = hex::decode("3535353535353535353535353535353535353535").unwrap();
        let value = u128::from_str_radix("de0b6b3a7640000", 16).unwrap();
        let data = vec![];

        let mut txn = LegacyTransaction::new(nonce, gas_price, gas_limit, to, value, data, ETH_CHAIN_ID);
        let encoded = txn.rlp_encode();
        println!("{:?}", encoded);
    }

    #[test]
    fn test_create_new_legacy_txn() {
        let result = LegacyTransaction::new(10, 10, 10, vec![], 10, vec![], RINKEBY_CHAIN_ID);
        let expected = LegacyTransaction {
            nonce: 10,
            gas_price: 10,
            gas_limit: 10,
            to: vec![],
            value: 10,
            data: vec![],
            v: RINKEBY_CHAIN_ID as u64,
            r: vec![0],
            s: vec![0],
        };
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sign_legacy_txn() {
        let nonce = u128::from_str_radix("9", 16).unwrap();
        let gas_price = u128::from_str_radix("4a817c800", 16).unwrap();
        let gas_limit = u128::from_str_radix("5208", 16).unwrap();
        let to = hex::decode("3535353535353535353535353535353535353535").unwrap();
        let value = u128::from_str_radix("de0b6b3a7640000", 16).unwrap();
        let data = vec![];

        let mut txn = LegacyTransaction::new(nonce, gas_price, gas_limit, to, value, data, ETH_CHAIN_ID);
        let secret_key = hex::decode(SK_TEST_1).unwrap();
        let result = txn.sign(&secret_key);

        let expected: Vec<u8> = vec![248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53,
                            53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53,
                            136, 13, 224, 182, 179, 167, 100, 0, 0, 128, 37, 160, 40, 239, 97, 52,
                            11, 217, 57, 188, 33, 149, 254, 83, 117, 103, 134, 96, 3, 225, 161, 93,
                            60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118, 160, 103, 203, 233,
                            216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245, 85, 201,
                            243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131];

        assert_eq!(result, expected);
    }
}

//pub enum Transaction {
//    FeeMarketEIP1559(FMTransaction),
//    AccessListEIP2930(ALTransaction),
//    Legacy(LegacyTransaction),
//}
