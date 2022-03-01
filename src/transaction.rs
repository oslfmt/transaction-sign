use secp256k1::{Message, Secp256k1, SecretKey};
use rlp::{RlpStream};
use tiny_keccak::{Keccak, Hasher};
use serde::{Serialize, Deserialize};
use ethereum_types::{H256, H160, U256};
use hex;

const ETH_CHAIN_ID: u64 = 1;
const RINKEBY_CHAIN_ID: u64 = 4;

// So when deserializing from JSON to this struct, using rust primitive types like u128 doesn't
// work, but U256 does, I have no idea why. My guess is that the derive macro for deserialize
// looks at the hex string, and U256 type has a method from_str to parse a string and somehow
// this is called?? But using u128 doesn't automatically convert from radix string to u128.
// So for now I'll use these wrapper types.
#[derive(Deserialize, Debug, PartialEq)]
pub struct LegacyTransaction {
    pub nonce: U256,
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    #[serde(rename = "gas")]
    pub gas_limit: U256,
    pub to: Option<H160>,
    pub value: U256,
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
            nonce: U256::from(nonce),
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(gas_limit),
            to: Some(H160::from_slice(&to)),
            value: U256::from(value),
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

        // TODO: figure out why this is needed
        let mut r_n = sig.r;
        let mut s_n = sig.s;

        while r_n[0] == 0 {
            r_n.remove(0);
        }
        while s_n[0] == 0 {
            s_n.remove(0);
        }

        self.v = sig.v + self.v * 2 + 35;
        self.r = r_n;
        self.s = s_n;

        println!("{:?}", self);
        println!("{:?}", self.rlp_encode());
        
        self.rlp_encode()
    }

    /// Serializes the transaction with RLP algorithm
    fn rlp_encode(&self) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);

        if let Some(v) = self.to {
            s.append(&v);
        } else {
            s.append(&vec![]);
        }

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
    use std::io::Read;
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("83646f67", "dog")]
    //#[case("c7c0c1c0c3c0c1c0", "VALID")]
    //#[case("bf0f000000000000021111", "INVALID")]
    //#[case("c6827a77c10401", vec![ "zw", vec![ 4 ], 1 ])]
    fn test_rlp_decode(#[case] input: String, #[case] expected: String) {
        let data = hex::decode(input).unwrap();
        let decoded: String = rlp::decode(&data).unwrap();
        assert_eq!(expected, decoded);
    }

    #[rstest]
    #[case("dog", "83646f67")]
    //#[case("VALID", "c7c0c1c0c3c0c1c0")]
    fn test_rlp_encode(#[case] input: String, #[case] expected: String) {
        let encoded = rlp::encode(&input);
        assert_eq!(expected, hex::encode(encoded));
    }

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

/*    #[test]
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
    }*/

    #[test]
    fn test_sign_legacy_txns() {
        use std::fs::File;

        #[derive(Deserialize)]
        struct Signing {
            private_key: U256,
            signed: Vec<u8>,
        }

        let mut file = File::open("./tests/test_eth_txns.json").unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txns: Vec<(LegacyTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();

        for (mut txn, signed) in txns {
            let sk: [u8; 32] = signed.private_key.try_into().unwrap();
            assert_eq!(signed.signed, txn.sign(&sk));
        }
    }
}

//pub enum Transaction {
//    FeeMarketEIP1559(FMTransaction),
//    AccessListEIP2930(ALTransaction),
//    Legacy(LegacyTransaction),
//}
