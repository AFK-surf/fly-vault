use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

pub const XTS_KEY_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 4096;
const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone)]
pub struct XtsKey(pub Zeroizing<[u8; XTS_KEY_SIZE]>);

impl XtsKey {
    pub fn from_bytes(bytes: [u8; XTS_KEY_SIZE]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != XTS_KEY_SIZE {
            return Err(anyhow!(
                "invalid XTS key length {}, expected {}",
                bytes.len(),
                XTS_KEY_SIZE
            ));
        }
        let mut out = [0u8; XTS_KEY_SIZE];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    pub fn as_bytes(&self) -> &[u8; XTS_KEY_SIZE] {
        &self.0
    }
}

pub struct Aes256Xts {
    data_cipher: Aes256,
    tweak_cipher: Aes256,
}

impl Aes256Xts {
    pub fn new(key: &XtsKey) -> Self {
        let key1 = GenericArray::from_slice(&key.as_bytes()[..32]);
        let key2 = GenericArray::from_slice(&key.as_bytes()[32..]);
        Self {
            data_cipher: Aes256::new(key1),
            tweak_cipher: Aes256::new(key2),
        }
    }

    pub fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        self.crypt_sector(sector_index, buf, true)
    }

    pub fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        self.crypt_sector(sector_index, buf, false)
    }

    pub fn encrypt_range(&self, start_sector: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() % SECTOR_SIZE != 0 {
            return Err(anyhow!("encrypt_range requires sector-aligned buffer"));
        }
        for (i, sector) in buf.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            self.encrypt_sector(start_sector + i as u64, sector)?;
        }
        Ok(())
    }

    pub fn decrypt_range(&self, start_sector: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() % SECTOR_SIZE != 0 {
            return Err(anyhow!("decrypt_range requires sector-aligned buffer"));
        }
        for (i, sector) in buf.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            self.decrypt_sector(start_sector + i as u64, sector)?;
        }
        Ok(())
    }

    fn crypt_sector(&self, sector_index: u64, buf: &mut [u8], encrypt: bool) -> Result<()> {
        if buf.len() != SECTOR_SIZE {
            return Err(anyhow!(
                "invalid sector length {}, expected {}",
                buf.len(),
                SECTOR_SIZE
            ));
        }

        let mut tweak = tweak_for_sector(&self.tweak_cipher, sector_index);

        for block in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut ga = GenericArray::clone_from_slice(block);
            xor_in_place(ga.as_mut_slice(), &tweak);
            if encrypt {
                self.data_cipher.encrypt_block(&mut ga);
            } else {
                self.data_cipher.decrypt_block(&mut ga);
            }
            xor_in_place(ga.as_mut_slice(), &tweak);
            block.copy_from_slice(ga.as_slice());
            gf_mul_alpha(&mut tweak);
        }

        Ok(())
    }
}

fn tweak_for_sector(cipher: &Aes256, sector_index: u64) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_index.to_le_bytes());
    let mut block = GenericArray::clone_from_slice(&tweak);
    cipher.encrypt_block(&mut block);
    tweak.copy_from_slice(block.as_slice());
    tweak
}

fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
}

fn gf_mul_alpha(tweak: &mut [u8; 16]) {
    // XTS uses little-endian polynomial representation for tweak words.
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let next = (*byte >> 7) & 1;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sector() {
        let key = XtsKey::from_bytes([7u8; XTS_KEY_SIZE]);
        let xts = Aes256Xts::new(&key);

        let mut plain = [0u8; SECTOR_SIZE];
        for (idx, b) in plain.iter_mut().enumerate() {
            *b = (idx % 251) as u8;
        }

        let mut cipher = plain;
        xts.encrypt_sector(42, &mut cipher).unwrap();
        assert_ne!(cipher, plain);

        xts.decrypt_sector(42, &mut cipher).unwrap();
        assert_eq!(cipher, plain);
    }
}
