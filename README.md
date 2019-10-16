# Introduction

This is a proof of concept for a key exchange protocol based on the Classic
McEliece (CM) key encapsulation mechanism proposed by Bernstein et al.

**This protocol was not designed for general use. In particular, it is not a
replacement for TLS and does not provide equivalent security. It ensures neither
authenticity nor integrity, and the implemented key exchange does not match the
performance of others.**

This protocol is designed to act as a layer on top of a bidirectional stream
such as TCP or TLS. It is not suited for connectionless communication.

# Parameters

- `E` is the symmetric cipher. We suggest using AES in Counter mode.
- `s` is the size of the symmetric key. We suggest using 256 bits.
- `b` is the size of the initialization vector. In the case of AES in Counter
  mode, this must be 128 bits.
- `H` is a hash function. The output size of `H` must be equal to `s`. We
  suggest using SHA-256.

The protocol does not negotiate these parameters.

# Steps

 1. The client begins the key exchange by sending a `ClientHello` message. This
    message has an optional `sni` field. It allows to pass a hostname to the
    server.
 2. The server selects a CM public key `T` and a `s`-bit nonce `N` for the
    connection. It sends a `ServerHello` message and sets the `key_id` field to
    `H(T)` and `nonce` to `N`.
 3. If the client has a local copy of `T` identified by `H(T)`, proceed at step 6.
 4. The client sends a `PublicKeyRequest` message.
 5. The server sends a `PublicKeyResponse` message and sets the `public_key`
    field to `T`.
 6. The client selects a random initialization vector `v` of length `b`, and
    performs the CM key encapsulation operation using the public key `T` in order
    to obtain a random key `K` of length `s` and the ciphertext `C`.
 7. The client sends a `EncryptedKey` message and sets the `iv` field to `v` and
    `encrypted_key` to `C`.
 8. The server performs the CM key decapsulation operation using the public key
    `T` and the ciphertext `C` to obtain `K`.
 9. The server sends a `TunnelReady` message.
10. Both parties compute `K' = K ⊕ N`.
11. Both parties compute `K_1 = H(00000000 || K')` and
    `K_2 = H(11111111 || K')`.
12. Both parties set up the tunnel by encrypting the remainder of the connection
    with the symmetric cipher `E` using the initialization vector `v` and the
    key `K_1` for data from the server to the client, and `K_2` for data from
    client to the server.

# Message format

The message format is intentionally kept very simple. Each message begins with a
single byte that indicates the type of the message, followed by three bytes
that encode the length of the rest of the message as a big-endian 24-bit
integer. This header is only four bytes long, but limits the total size of all
contained fields to 16 megabytes.

```
--------------------------------------------------------
| Byte offset | 0   | 1 .. 3 | 4        ..       3+len |
--------------------------------------------------------
| Field       | tag | length | field 1 | field 2 | ... |
--------------------------------------------------------
```

Message types and their fields:

- **ClientHello**
  - `sni`: hostname that the client is trying to connect to (optional)
- **ServerHello**
  - `key_id`: uniquely identifies the server's public key
  - `nonce`: selected randomly by the server
- **PublicKeyRequest**
- **PublicKeyReply**
  - `public_key`: the server's public key
- **EncryptedKey**
  - `encrypted_key`: ciphertext produced by CM key encapsulation
  - `iv`: randomly chosen initialization vector
- **TunnelReady**

# Security considerations

## Man-in-the-middle attacks

Since this protocol does not perform any kind of authentication, it does not
protect against man-in-the-middle attacks. An attacker who can intercept the
communication between client and server can use their own public key instead of
the server's public key, and then perform the key exchange both between client
and attacker and attacker and server. This would allow the attacker to observe
and manipulate all transmitted data.

## Maximum transmission size

This protocol does not support renegotiations of the used keys or initialization
vector. For AES in Counter mode, this restriction means that the initialization
vector will be reused after a fixed number of blocks have been transmitted.
Reusing the initialization vector with the same key could negatively affect the
security of the transferred data, it is therefore important to restrict the size
of the transmission such that this does not happen.

With the chosen parameters, the initialization vector will be reused after
exactly `2^b` blocks, each having a size of `b` bits. The maximum transmission
size is therefore `b * 2^b` bits, which equals 5.07 * 10<sup>30</sup> gigabytes.
Note that this restriction applies to each transmission direction independently.

## Prevention of (intentional) key and IV reuse

Apart from restricting the transmission size to avoid accidental reuse of
pairs of keys and initialization vectors, the protocol also ensures that neither
the client nor the server can intentionally cause such pairs to be reused.

The client can choose the initialization vector `v` freely, leaving no way for
the server to influence its choice. If the client chooses `v` at random, the
chance of choosing a previously used initialization vector is small, in fact,
the probability of coincidentally reusing an initialization vector reaches
1% after not less than 2.6 * 10<sup>18</sup> key exchanges (see
[Birthday attack](https://en.wikipedia.org/wiki/Birthday_attack#Mathematics)).
This does not prevent clients from intentionally reusing initialization vectors,
but as we will see in the following, this does not present a problem.

We will now consider key reuse. The protocol uses two keys for symmetric
encryption and decryption, `K_1` and `K_2`. Both parties derive these from the
key `K'`, which is computed as `K' = K ⊕ N`. Since the server can only choose
`N` and cannot influence `K`, it cannot affect `K'` in a predictable way,
making it impossible for the server to cause keys to be reused. For the client,
there are two possible strategies for causing `K_1` or `K_2` to be reused:

1. Given `K_1` and `K_2`, find a valid `K'` such that `00000000 || K'` (or
   `11111111 || K'`, respectively) is a preimage of `K_1` (or `K_2`,
   respectivly) under `H`. This is infeasible due to `H` having the property
   of (weak) collision resistance.
2. Given `K'`, find a valid ciphertext `C` that, when decrypted, produces a `K`
   with `K' = K ⊕ N`, thus resulting in the same keys `K_1` and `K_2`.
   As specified by Bernstein et al., `K` is the result of a cryptographic hash
   function applied to multiple inputs, one of which is the ciphertext `C`.
   Finding a suitable `C` thus requires finding a suitable preimage of `K`,
   which is infeasible due to the preimage resistance of the used hash function.
   Even if an attacker was able to find such a preimage, the probability that a
   given preimage of `K` represents a valid ciphertext `C` is negligible.

Therefore, it is infeasible both for the server and for the client to reuse
previously used keys. Note that, without `N`, it would be trivial for the client
to force the server to reuse a previously used key.
