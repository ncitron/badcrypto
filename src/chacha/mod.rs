use eyre::Result;
use rand::random;

/// ChaCha20 encryption with 96 bit nonce and 32 bit counter
pub struct ChaCha {
    key: Key,
}

/// ChaCha20 ciphertext
pub struct CipherText {
    /// Variable length ciphertext bytes
    pub c: Vec<u8>,
    /// Nonce used to seed PRG state
    pub nonce: Nonce,
}

/// 256 bit ChaCha private key
pub struct Key([u32; 8]);

/// 96 bit nonce used in PRG
pub struct Nonce([u32; 3]);

/// Internal ChaCha state representing the 4x4 u32 matrix
struct ChaChaState(Vec<u32>);

impl ChaCha {
    /// Creates a new ChaCha cipher from a private key
    pub fn new(key: Key) -> Self {
        Self { key }
    }

    /// Encrypts a message
    pub fn encrypt(&self, message: &str) -> CipherText {
        let nonce = Nonce::new(random::<[u32; 3]>());
        let message_bytes = message.as_bytes().to_vec();
        let c = self.apply_cipher_with_nonce(&message_bytes, &nonce);

        CipherText { c, nonce }
    }

    /// Decrypts a message. Errors if the message is not valid utf-8
    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<String> {
        let message_bytes = self.apply_cipher_with_nonce(&ciphertext.c, &ciphertext.nonce);
        Ok(String::from_utf8(message_bytes)?)
    }

    /// Applies cipher to the message with a given nonce. Can be used to encrypt
    /// or decrypt. Nonce must be unique. If a nonce is reused, messages may be
    /// decrypted.
    fn apply_cipher_with_nonce(&self, message: &Vec<u8>, nonce: &Nonce) -> Vec<u8> {
        let counter_start = 1u32;

        let c = message
            .chunks(64)
            .enumerate()
            .map(|(i, chunk)| {
                let j = counter_start + i as u32;
                let mut state = ChaChaState::new(&self.key, j, &nonce);
                state.chacha_block();

                let key_stream = state
                    .0
                    .iter()
                    .flat_map(|n| n.to_le_bytes())
                    .collect::<Vec<u8>>();

                key_stream
                    .iter()
                    .zip(chunk)
                    .map(|(key_byte, message_byte)| key_byte ^ message_byte)
                    .collect::<Vec<u8>>()
            })
            .flatten()
            .collect::<Vec<u8>>();

        c
    }
}

impl ChaChaState {
    /// Creates a new ChaChaState
    pub fn new(key: &Key, counter: u32, nonce: &Nonce) -> Self {
        let constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

        let mut block = Vec::<u32>::new();
        block.extend(constants);
        block.extend(key.0);
        block.push(counter);
        block.extend(nonce.0);

        Self(block)
    }

    /// Runs the ChaCha PRG function to generate a random block
    pub fn chacha_block(&mut self) {
        let original = self.0.clone();

        for _ in 0..10 {
            self.quarter_round_state(0, 4, 8, 12);
            self.quarter_round_state(1, 5, 9, 13);
            self.quarter_round_state(2, 6, 10, 14);
            self.quarter_round_state(3, 7, 11, 15);
            self.quarter_round_state(0, 5, 10, 15);
            self.quarter_round_state(1, 6, 11, 12);
            self.quarter_round_state(2, 7, 8, 13);
            self.quarter_round_state(3, 4, 9, 14);
        }

        for i in 0..16 {
            self.0[i] = self.0[i].wrapping_add(original[i]);
        }
    }

    /// Applies the quarter round function with the given state idices
    fn quarter_round_state(&mut self, ai: usize, bi: usize, ci: usize, di: usize) {
        let mut a = self.0[ai];
        let mut b = self.0[bi];
        let mut c = self.0[ci];
        let mut d = self.0[di];

        quarter_round(&mut a, &mut b, &mut c, &mut d);

        self.0[ai] = a;
        self.0[bi] = b;
        self.0[ci] = c;
        self.0[di] = d;
    }
}

impl Key {
    /// Create a new Key. Errors if the string is not a 32 byte hex value.
    pub fn new(s: &str) -> Result<Self> {
        let key: [u32; 8] = hex::decode(s)
            .map_err(|_| eyre::eyre!("cannot parse key"))?
            .chunks(4)
            .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
            .collect::<Result<Vec<u32>>>()
            .map_err(|_| eyre::eyre!("cannot parse key"))?
            .try_into()
            .map_err(|_| eyre::eyre!("cannot parse key"))?;

        Ok(Self(key))
    }
}

impl Nonce {
    /// Create a new Nonce from a string. Fails if the string is not a 12 byte hex value.
    pub fn from_str(s: &str) -> Result<Self> {
        let nonce: [u32; 3] = hex::decode(s)
            .map_err(|_| eyre::eyre!("cannot parse nonce"))?
            .chunks(4)
            .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
            .collect::<Result<Vec<u32>>>()
            .map_err(|_| eyre::eyre!("cannot parse nonce"))?
            .try_into()
            .map_err(|_| eyre::eyre!("cannot parse nonce"))?;

        Ok(Self(nonce))
    }

    /// Creates a new nonce from a fixed length u32 array
    pub fn new(n: [u32; 3]) -> Self {
        Self(n)
    }
}

/// Quarter round function as defined by section 2.1 of RFC 8439
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

#[test]
fn test_full_cycle() {
    let message = "Hello, World!";
    let key = Key::new(&hex::encode(random::<[u8; 32]>())).unwrap();

    let cipher = ChaCha::new(key);
    let ciphertext = cipher.encrypt(message);
    let decrypted_message = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted_message, message);
}

#[test]
fn test_apply_cipher() {
    // test vector from RFC 8439
    let key = Key::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let nonce = "000000000000004a00000000";
    let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let nonce = Nonce::from_str(nonce).unwrap();

    let k = ChaCha::new(key);

    let c = k.apply_cipher_with_nonce(&message.as_bytes().to_vec(), &nonce);

    let expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";

    assert_eq!(c, hex::decode(expected).unwrap());
}

#[test]
fn test_chacha_block() {
    // test vector from RFC 8439
    let key = Key::new("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let nonce = Nonce::from_str("000000090000004a00000000").unwrap();
    let counter = 1;

    let mut state = ChaChaState::new(&key, counter, &nonce);
    state.chacha_block();

    let block = hex::encode(
        state
            .0
            .iter()
            .flat_map(|chunk| chunk.to_le_bytes())
            .collect::<Vec<_>>(),
    );

    let expected_block = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";

    assert_eq!(block, expected_block);
}

#[test]
fn test_quarter_round() {
    // test vector from RFC 8439
    let mut a = 0x11111111;
    let mut b = 0x01020304;
    let mut c = 0x9b8d6f43;
    let mut d = 0x01234567;

    quarter_round(&mut a, &mut b, &mut c, &mut d);

    assert_eq!(a, 0xea2a92f4);
    assert_eq!(b, 0xcb1cf8ce);
    assert_eq!(c, 0x4581472e);
    assert_eq!(d, 0x5881c4bb);
}
