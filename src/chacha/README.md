## ChaCha20

ChaCha20 is a stream cipher designed by Daniel J. Bernstein in 2008. It is an improvement on the Salsa20 cipher, which was also designed by Bernstein. The ChaCha cipher operates on a 64 byte block of data at a time. It uses a key, nonce, and block counter to generate a stream of pseudo-random bits, which are then XORed with the plaintext to produce the ciphertext.

## Pseudo Random Generators (PRGs)

The ChaCha cipher uses a pseudo-random generator (PRG) to produce a stream of pseudo-random bits. It is a deterministic algorithm that takes the key, nonce, and block counter as input and produces a sequence of bits that appears random, but which can be reproduced given the same inputs.

ChaCha holds data in a 4x4 matrix consisting of 16 32 bit words containing the following contents:

- The first row contains the constants "0x61707865", "0x3320646e", "0x79622d32", "0x6b206574" (ascii encoding of "expand 32-byte k")
- The second row contains the first 4 words of the key
- The third row contains the last 4 words of the key
- The fourth row contains the block counter (1 word) and the nonce (3 words)

More succinctly:

```math
\begin{bmatrix} c_1 & c_2 & c_3 & c_4 \\ k_1 & k_2 & k_3 & k_4 \\ k_5 & k_6 & k_7 & k_8 \\ b & n_1 & n_2 & n_3 \end{bmatrix}
```

Each iteration of the PRG produces a single 512 bit block of random data. The bit stream produced by the PRG is generated as needed, with the block counter being incremented and the algorithm being rerun to produce each successive block.

The nonce value is typically chosen at random. It must be unique for each message that is encrypted, because reusing the same nonce is effectively creating a "two-time pad". With a two-time pad, the attacker has access to the ciphertext of two messages that were encrypted with the same random stream. An attacker can XOR these two ciphertexts together to cancel out the random stream and produce the XOR of the two plaintexts. If the plaintexts have any common words or patterns, the attacker may be able to recover parts of the message.

## Encryption

To encrypt a message with the ChaCha cipher, the following steps are performed:

1. The key and nonce are used to initialize the PRG.
2. The PRG produces a stream of pseudo-random bits.
3. The pseudo-random bits are XORed with the plaintext to produce the ciphertext.
4. The sender sends both the ciphertext and the nonce to the receiver.

## Decryption

To decrypt a message that has been encrypted with the ChaCha cipher, the following steps are performed:

1. The key and nonce are used to initialize the PRG.
2. The PRG produces the same stream of pseudo-random bits that was used to encrypt the message.
3. The pseudo-random bits are XORed with the ciphertext to produce the plaintext.

## How It Works

The PRG in the ChaCha cipher operates by applying a series of operations to the input matrix. The basic building block for these operations is called the quarter-round, which takes in four 32-bit integers, and scrambles them by applying a series of XOR, bitwise rotation, and overflowing addition between the values. Here is the code for the quarter-round function we use in our implementation.

```rust
/// Quarter-round function as defined by section 2.1 of RFC 8439
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl(*d, 16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl(*b, 12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl(*d, 8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl(*b, 7);
}

/// Circular left shift. Panics if shift if greater than 32.
fn rotl(value: u32, shift: u32) -> u32 {
    value << shift | value >> (32 - shift)
}
```

In order to sufficiently scramble the input matrix, ChaCha20 applies the quarter-round on each column of the matrix and then on each diagonal. These two steps combined are called the double-round, and are performed a total of 10 times in ChaCha20. Finally, we perform a element-wise overflowing addition to combine the scrambled matrix with the original input matrix. This makes the output noninvertable. After these operations we concatenate all elements of the matrix to produce the 512 bit block of pseudo-random bits.

The constants used in the ChaCha cipher are a set of fixed values that are included in the input to the PRG. They were added to the cipher to reduce the amount of attacker-controlled input. This has the effect of removing certain correlations between inputs that are maintained in the outputs, increasing security.

The constants used in the ChaCha cipher are also known as "nothing up my sleeve numbers." This phrase refers to the idea that the constants are chosen in a transparent and verifiable way, to ensure that they do not contain any hidden information or backdoors. In other words, the constants are chosen in a way that makes it clear that there is "nothing up my sleeve" – no hidden tricks or secrets.

## Security

The security of the ChaCha cipher relies on the PRG being able to produce a stream of bits that is difficult for an attacker to predict or distinguish from a truly random stream. If the PRG is predictable, then an attacker may be able to determine the output of the PRG and recover the plaintext of a message.

As far as we know, the double-round technique for scrambling the matrix is secure. The state of the art attacks against ChaCha can currently only break the first 7 of 20 quarter-rounds.
