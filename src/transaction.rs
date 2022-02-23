
//pub enum Transaction {
//    FeeMarketEIP1559(FMTransaction),
//    AccessListEIP2930(ALTransaction),
//    Legacy(LegacyTransaction),
//}

pub struct LegacyTransaction {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: u64,
    pub s: u64,
}

impl LegacyTransaction {
    /// Creates a new legacy transaction with v as chain_id, and r,s initialized to 0
    pub fn new(nonce: u128, gas_price: u128, gas_limit: u128, to: [u8; 20], value: u128, data: Vec<u8>, chain_id: u64) -> Self {
        LegacyTransaction {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            v: chain_id,
            r: 0,
            s: 0,
        }
    }

    /// Signs the raw transaction, returning the RLP-encoded transaction
    pub fn sign(&self) -> Vec<u8> {
        // rlp-encode the transaction
        let encoded_txn = rlp_encode(&self);
        let hashed_txn = keccak256(encoded_txn);
        let sig = EcdsaSig::ecdsa_sign(hashed_txn); // returns v,r,s components
        
        // re-encode txn with v,r,s (do we need new txn, or can we mutate?)
        let modified_txn = LegacyTransaction::new(self, v, r, s);
        rlp_encode(modified_txn)
    }

    /// Serializes the transaction with RLP algorithm
    fn rlp_encode() -> Vec<u8> {
         
    }
}

/// Hashes arbitrary data input
fn keccak256(data: &[u8]) -> [u8; 32] {
    // hash data
}

pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn ecdsa_sign(data: &[u8], private_key: &[u8]) -> Self {
        // sign the data with the private key
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_new_legacy_txn() {
        let result = LegacyTransaction::new(10, 10, 10, vec![], 10, vec![], 10);
        let expected = LegacyTransaction {
            nonce: 10,
            ...
        };
        
        assert_eq!(result, expected);
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
            data: vec![].
        };

        let raw_txn = txn.sign();

        // now can call RPC method to send txn to network
        // eth_sendRawTransaction(raw_txn);
    }
}
