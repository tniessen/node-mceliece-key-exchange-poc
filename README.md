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

# Message format

Each message has the following format:

```
| Byte offset | 0   | 1 .. 3 | 4 .. 3+len |
-------------------------------------------
| Field       | tag | len    | data       |
-------------------------------------------
```

The multibyte `len` field uses big-endian encoding.

## 0x00: ClientHello

```
| Byte offset | 0    | 1 .. 3 | 4 .. 3+len |
--------------------------------------------
| Field       | 0x00 | len    | sni        |
--------------------------------------------
```

The `sni` field is optional. If it is set, it contains the hostname that the
client wants to connect to.

## 0x01: ServerHello

```
| Byte offset | 0    | 1 .. 3 | 4 .. 3+s/8 | 4+s/8 .. 3+s/4 |
-------------------------------------------------------------
| Field       | 0x01 | s / 4  | key_id     | nonce          |
-------------------------------------------------------------
```

## 0x02: PublicKeyRequest

```
| Byte offset | 0    | 1 .. 3 |
-------------------------------
| Field       | 0x02 | 0      |
-------------------------------
```

## 0x03: PublicKeyReply

```
| Byte offset | 0    | 1 .. 3 | 4 .. 3+len |
--------------------------------------------
| Field       | 0x03 | len    | public_key |
--------------------------------------------
```

## 0x04: EncryptedKey


```
| Byte offset | 0    | 1 .. 3 | 4 .. 3+s/8    | 4+s/8 .. 3+len |
----------------------------------------------------------------
| Field       | 0x04 | len    | encrypted_key | iv             |
----------------------------------------------------------------
```

## 0x05: TunnelReady

```
| Byte offset | 0    | 1 .. 3 |
-------------------------------
| Field       | 0x05 | 0      |
-------------------------------
```

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

# Prevention of key and IV reuse

A critical aspect when using AES in Counter mode is to prevent the reuse of
pairs of keys and initialization vectors. The protocol achieves this in the
following ways:

The client can choose the initialization vector `v` freely, leaving no way for
the server to influence its choice. If the client chooses `v` at random, the
chance of choosing a previously used initialization vector is small, in fact,
the probability of coincidentally reusing an initialization vector reaches
1% after not less than 2.6e18 key exchanges (see
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
