use secp256k1::{Message, Secp256k1, SecretKey};
use rlp::{RlpStream};
use tiny_keccak::{Keccak, Hasher};
//pub enum Transaction {
//    FeeMarketEIP1559(FMTransaction),
//    AccessListEIP2930(ALTransaction),
//    Legacy(LegacyTransaction),
//}

const RINKEBY_CHAIN_ID: u8 = 4;

pub struct LegacyTransaction {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    pub to: Vec<u8>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: i32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl LegacyTransaction {
    /// Creates a new legacy transaction with v as chain_id, and r,s initialized to 0
    pub fn new(nonce: u128, gas_price: u128, gas_limit: u128, to: Vec<u8>, value: u128, data: Vec<u8>, chain_id: u64) -> Self {
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
        // rlp-encode the transaction
        let encoded_txn = self.rlp_encode();
        let hashed_txn = keccak256(&encoded_txn);
        let sig = EcdsaSig::ecdsa_sign(&hashed_txn, secret_key);
        
        // re-encode txn with v,r,s (do we need new txn, or can we mutate?)
        self.v = sig.v + (RINKEBY_CHAIN_ID as u64 * 2 + 35); //TODO: recheck v value
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
    v: i32,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn ecdsa_sign(data: &[u8], secret_key: &[u8]) -> Self {
        let secp = Secp256k1::new();
        let msg = Message::from_slice(data).unwrap();
        let sk = SecretKey::from_slice(secret_key).unwrap();
        let (recoveryID, sig_bytes) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();
        
        //TODO: figure out what r and s values really are
        EcdsaSig {
            v: recoveryID.to_i32(),
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
        let txn = LegacyTransaction::new(10,10,10, vec![], 10, vec![], 10);
        let encoded = txn.rlp_encode();
        println!("{:?}", encoded);
    }

    #[test]
    fn test_create_new_legacy_txn() {
        let result = LegacyTransaction::new(10, 10, 10, vec![], 10, vec![], 10);
        //let expected = LegacyTransaction {
        //    nonce: 10,
        //    ...
        //};
        
        //assert_eq!(result, expected);
    }

    #[test]
    fn test_sign_legacy_txn() {
        // dummy fields
        let txn = LegacyTransaction {
            nonce: 0,
            gas_price: 10,
            gas_limit: 10,
            to: vec![1,2,3],
            value: 10,
            data: vec![],
            v: 0,
            r: 0,
            s: 0,
        };

        let raw_txn = txn.sign();

        // now can call RPC method to send txn to network
        // eth_sendRawTransaction(raw_txn);
    }
}
