A library that implements offline transaction signing for Ethereum
transactions.

In order for a transaction to be considered valid, it must have
a valid signature. The only way to generate a valid signature is by
possessing the private key corresponding to the public key. Obviously, this
key must be kept local. Thus, transaction signing must occur on the local
machine.

The ETH JSON-RPC API specifies an `eth_sendTransaction` method, which takes
a transaction object, and returns a transaction hash. Essentially, this
method takes a transaction and sends it to the Ethereum network, and when it
is mined, returns the hash. Weirdly, no mention of private keys or signatures
appear. Under the hood, then, the software must be signing the transaction
with the private key (thus creating the signature) on the user's behalf.

Indeed, this is what Ethereum clients like Geth are doing. Geth is the
software in this case. If a user is running a local Geth client, Geth also
contains wallet functionality. That is, it manages your keys on your behalf.
So if you are calling `eth_sendTransaction` with Geth, then under the hood,
Geth uses your private key to sign the transaction and create a valid
signature. Now, the transaction can be sent to the network and validated.

However, if you are using wallets like Metamask, which rely on Infura, this
cannot be done. That is because you are relying on an Infura node to relay
your transaction, and obviously it would be unwise to store your keys on a
public Infura node. This is why Infura does not support the `eth_sendTransaction`
method. Instead, it only supports `eth_sendRawTransaction`.

`eth_sendRawTransaction` takes in a "raw" transaction, and sends it to the
network. A raw transaction is just the signed transaction data. Specifically, it
is the RLP-encoded transaction, that has the signature included in it.

To support the case of offline signing, we must have a way to sign transactions
locally, and then perform a call to the network. A library to do this would help,
since transaction signing is more complex than it appears. In addition to signing,
hashing and serialization is also involved. Here is the full process:

1. Create a transaction object with fields: nonce, gasPrice, gasLimit, to, value,
data, chainID, 0, 0.
2. RLP-encode this object.
3. Hash the serialized object with keccak256.
4. Sign the hash with the sender's private key using ECDSA.
5. With the newly computed v,r,s values from the signature, create a new transaction
object with fields: nonce, gasPrice, gasLimit, to, value, data, v, r, s.
6. RLP-encode this new transaction object.
7. Send transaction to the network with `eth_sendRawTransaction`

Additionally, there are 3 types of transactions in Ethereum:
1. EIP-1559 (gas fee market) transactions
2. EIP-2930 (access list) transactions
3. Legacy transactions (what we've defined above)

Consider a library that allows users to create any such type of Ethereum
transaction. Once this object is created, all that needs to be done is pass it
into the signing mechanism, which is the same for all transactions. This could
be further extrapolated to transactions in any blockchain. The returned raw
transaction is then readily able to be sent to the network, perhaps via a call to
`eth_signRawTransaction`.


