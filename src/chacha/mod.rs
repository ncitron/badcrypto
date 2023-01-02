use eyre::Result;
use rand::random;

/// ChaCha20 encryption with 96 bit nonce and 32 bit counter
pub struct ChaCha {
    key: [u32; 8],
}

pub struct CipherText {
    pub c: Vec<u8>,
    pub nonce: [u32; 3],
}

impl ChaCha {
    pub fn new(key: &str) -> Result<Self> {
        let key: [u32; 8] = hex::decode(key)
            .map_err(|_| eyre::eyre!("cannot parse key"))?
            .chunks(4)
            .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
            .collect::<Result<Vec<u32>>>()
            .map_err(|_| eyre::eyre!("cannot parse key"))?
            .try_into()
            .map_err(|_| eyre::eyre!("cannot parse key"))?;

        Ok(Self { key })
    }

    pub fn encrypt(&self, message: &str) -> Result<CipherText> {
        let nonce = random::<[u32; 3]>();
        let message_bytes = message.as_bytes().to_vec();
        let c = self.apply_cipher_with_nonce(&message_bytes, &nonce)?;

        Ok(CipherText { c, nonce })
    }

    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<String> {
        let message_bytes = self.apply_cipher_with_nonce(&ciphertext.c, &ciphertext.nonce)?;
        Ok(String::from_utf8(message_bytes)?)
    }

    fn apply_cipher_with_nonce(&self, message: &Vec<u8>, nonce: &[u32; 3]) -> Result<Vec<u8>> {
        let counter_start = 1u32;

        let c = message
            .chunks(64)
            .enumerate()
            .map(|(i, chunk)| {
                let j = counter_start + i as u32;
                let key_stream = chacha_block(&self.key, j, &nonce)
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

        Ok(c)
    }
}

fn chacha_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    let mut block = Vec::<u32>::new();
    block.extend(constants);
    block.extend(key);
    block.push(counter);
    block.extend(nonce);

    let mut block: [u32; 16] = block.try_into().unwrap();
    let original = block.clone();

    for _ in 0..10 {
        quarter_round_state(&mut block, 0, 4, 8, 12);
        quarter_round_state(&mut block, 1, 5, 9, 13);
        quarter_round_state(&mut block, 2, 6, 10, 14);
        quarter_round_state(&mut block, 3, 7, 11, 15);
        quarter_round_state(&mut block, 0, 5, 10, 15);
        quarter_round_state(&mut block, 1, 6, 11, 12);
        quarter_round_state(&mut block, 2, 7, 8, 13);
        quarter_round_state(&mut block, 3, 4, 9, 14);
    }

    for i in 0..16 {
        block[i] = block[i].wrapping_add(original[i]);
    }

    block
}

fn quarter_round_state(state: &mut [u32; 16], ai: usize, bi: usize, ci: usize, di: usize) {
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    quarter_round(&mut a, &mut b, &mut c, &mut d);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rot(*d, 16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rot(*b, 12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rot(*d, 8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rot(*b, 7);
}

fn rot(value: u32, shift: u32) -> u32 {
    value << shift | value >> (32 - shift)
}

#[test]
fn test_full_cycle() {
    let message = "Hello, World!";
    let key = hex::encode(random::<[u8; 32]>());

    let cipher = ChaCha::new(&key).unwrap();
    let ciphertext = cipher.encrypt(message).unwrap();
    let decrypted_message = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted_message, message);
}

#[test]
fn test_apply_cipher() {
    // test vector from rfc8439
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce = "000000000000004a00000000";
    let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let nonce: [u32; 3] = hex::decode(nonce)
        .unwrap()
        .chunks(4)
        .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
        .collect::<Result<Vec<u32>>>()
        .unwrap()
        .try_into()
        .unwrap();

    let k = ChaCha::new(key).unwrap();

    let c = k
        .apply_cipher_with_nonce(&message.as_bytes().to_vec(), &nonce)
        .unwrap();

    let expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d";

    assert_eq!(c, hex::decode(expected).unwrap());
}

#[test]
fn test_chacha_block() {
    // test vector from rfc8439
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce = "000000090000004a00000000";
    let counter = 1;

    let key: [u32; 8] = hex::decode(key)
        .unwrap()
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    let nonce: [u32; 3] = hex::decode(nonce)
        .unwrap()
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    let block = chacha_block(&key, counter, &nonce);

    let block = hex::encode(
        block
            .iter()
            .flat_map(|chunk| chunk.to_le_bytes())
            .collect::<Vec<_>>(),
    );

    let expected_block = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";

    assert_eq!(block, expected_block);
}

#[test]
fn test_quarter_round() {
    // test vector from rfc8439
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
