# AES-XTS Block Cipher Mode

## Sources

- NIST SP 800-38E: <https://csrc.nist.gov/pubs/sp/800/38/e/final>
- NIST SP 800-38E (PDF): <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
- IEEE Std 1619-2007 (standard behind SP 800-38E)
- Wikipedia - Disk encryption theory: <https://en.wikipedia.org/wiki/Disk_encryption_theory>
- Xilinx XTS mode internals: <https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/xts.html>
- NIST 2024 revision announcement: <https://www.nist.gov/news-events/news/2024/02/nist-revise-special-publication-800-38e-xts-aes-block-cipher-mode>

---

## Overview

XTS-AES (XEX-based Tweaked-codebook mode with Ciphertext Stealing, applied to
AES) is a block cipher mode designed for encrypting data on storage devices. It
is standardized in:

- **IEEE Std 1619-2007** -- developed by the Security in Storage Working Group
  (SISWG) of the IEEE P1619 Task Group. Updated in 2025 to add key scope
  limits.
- **NIST SP 800-38E** (January 2010) -- approves XTS-AES by reference to IEEE
  1619, subject to one additional requirement (a maximum data unit size of
  2^20 AES blocks, i.e. 2^24 bytes = 16 MiB).

XTS-AES provides confidentiality for fixed-size storage units (sectors). It does
**not** provide authentication -- there is no MAC or authentication tag. NIST
notes that "in the absence of authentication or access control, XTS-AES provides
more protection than the other approved confidentiality-only modes against
unauthorized manipulation of the encrypted data."

XTS is the mode used by dm-crypt, LUKS, BitLocker, FileVault 2, VeraCrypt,
TrueCrypt, FreeBSD geli, OpenBSD softraid, and most self-encrypting drives.

---

## Two-Key Structure

XTS uses two independent AES keys derived from a single combined key:

```
Key = Key1 || Key2
```

- **Key1** (the "data key") -- used for encrypting/decrypting plaintext blocks
  via standard AES (FIPS 197).
- **Key2** (the "tweak key") -- used solely for encrypting the tweak value
  (sector number) to produce the per-block tweak mask.

The two keys MUST be independent. If Key1 == Key2, the construction degenerates
and loses its security properties. (NIST's FIPS 140-3 Implementation Guidance
Annex C.I explicitly calls out this vulnerability.)

### Key Sizes

| Variant       | Key1 size | Key2 size | Total key size |
|---------------|-----------|-----------|----------------|
| AES-128-XTS   | 128 bits  | 128 bits  | 256 bits       |
| AES-256-XTS   | 256 bits  | 256 bits  | 512 bits       |

For AES-256-XTS, the caller must supply a 512-bit (64-byte) key. The first 256
bits are Key1 and the second 256 bits are Key2.

---

## XTS Mode Operation

### Core Idea

Each 128-bit plaintext block is encrypted as:

```
C = AES_enc(Key1, P XOR T) XOR T
```

where T is a tweak value that is unique per block position. The tweak
incorporates:

1. The **sector number** (also called the "data unit number"), encrypted once
   per sector with Key2.
2. A **block index** within the sector, incorporated via multiplication in
   GF(2^128).

This is the XEX (XOR-Encrypt-XOR) construction by Rogaway, extended with
ciphertext stealing for partial final blocks.

### Per-Block Encryption

Given:
- `i` = 128-bit tweak value (typically the sector number, zero-padded to 128 bits)
- `j` = sequential block index within the sector (0, 1, 2, ...)
- `P` = 128-bit plaintext block

Encryption of one block:

```
1.  T  <- AES_enc(Key2, i) * alpha^j       [in GF(2^128)]
2.  PP <- P XOR T
3.  CC <- AES_enc(Key1, PP)
4.  C  <- CC XOR T
```

Output: `C` (128-bit ciphertext block)

### Per-Block Decryption

Given `C` (128-bit ciphertext block), same `i` and `j`:

```
1.  T  <- AES_enc(Key2, i) * alpha^j       [in GF(2^128)]
2.  CC <- C XOR T
3.  PP <- AES_dec(Key1, CC)
4.  P  <- PP XOR T
```

Key observation: the tweak computation in step 1 uses **AES_enc** (not AES_dec)
even during decryption. Only step 3 differs -- it uses AES_dec instead of
AES_enc.

---

## Tweak Computation

The tweak for block `j` in sector `i` is:

```
T_j = AES_enc(Key2, i) * alpha^j    in GF(2^128)
```

In practice, the base tweak `T_0 = AES_enc(Key2, i)` is computed once per
sector, and subsequent tweaks are derived iteratively:

```
T_0     = AES_enc(Key2, i)
T_{j+1} = T_j * alpha                in GF(2^128)
```

The sector number `i` is encoded as a 128-bit little-endian integer. For a disk
with sector numbers that fit in 64 bits, the upper 64 bits are zero.

---

## GF(2^128) Multiplication

### The Field

XTS operates in GF(2^128) defined by the irreducible polynomial:

```
p(x) = x^128 + x^7 + x^2 + x + 1
```

The primitive element alpha corresponds to `x` (the polynomial with just the
x^1 term), which has the numeric value 2.

### Multiply by Alpha

Multiplying a 128-bit value by alpha (i.e., by `x` in the polynomial ring) is:

1. Left-shift the 128-bit value by 1 bit.
2. If the bit that was shifted out (the original bit 127) was 1, XOR the result
   with `0x87`.

The constant `0x87` is the low-order representation of the reduction polynomial
`x^128 + x^7 + x^2 + x + 1` with the x^128 term removed:

```
x^7 + x^2 + x + 1  =  0b10000111  =  0x87
```

### Implementation (C-like pseudocode)

```
function gf128_mul_alpha(T: u128) -> u128:
    carry = (T >> 127) & 1          // extract the high bit
    T = T << 1                      // left shift
    if carry:
        T = T XOR 0x87              // reduce modulo the polynomial
    return T
```

This operation is extremely efficient -- a single shift and a conditional XOR.
No general-purpose multiplication is needed because XTS only ever multiplies by
alpha (never by arbitrary field elements).

### Why This Works

Each block in a sector needs a distinct tweak. Multiplying by alpha in
GF(2^128) for each successive block index `j` produces a sequence of values
that are all distinct (since alpha is a primitive element, its powers cycle
through all 2^128 - 1 nonzero field elements before repeating). This guarantees
that identical plaintext blocks at different positions within a sector encrypt
to different ciphertext blocks, avoiding the ECB weakness.

---

## Ciphertext Stealing for Partial Final Blocks

XTS can encrypt data units whose length is not a multiple of 128 bits, as long
as the total length is at least 128 bits (one full block). When the final block
is partial (between 1 and 127 bits), ciphertext stealing is used.

### Encryption with Ciphertext Stealing

Let the plaintext be blocks `P_0, P_1, ..., P_{m-1}, P_m` where `P_0` through
`P_{m-1}` are full 128-bit blocks and `P_m` is a partial block of `s` bits
(1 <= s <= 127).

Steps:

1. Encrypt blocks `P_0` through `P_{m-2}` normally (XOR-encrypt-XOR with their
   respective tweaks).

2. Encrypt `P_{m-1}` normally to get a full intermediate ciphertext `CC`:
   ```
   CC = AES_enc(Key1, P_{m-1} XOR T_{m-1}) XOR T_{m-1}
   ```

3. **Steal** the first `s` bits of `CC` to form the final (partial) ciphertext
   block `C_m`. Set aside the remaining `(128 - s)` bits of `CC`.

4. **Pad** the partial plaintext `P_m` by appending the remaining `(128 - s)`
   bits from `CC`, forming a full 128-bit block `PP`.

5. Encrypt `PP` with the **next** tweak `T_m`:
   ```
   C_{m-1} = AES_enc(Key1, PP XOR T_m) XOR T_m
   ```

6. Output: `C_0, ..., C_{m-2}, C_{m-1} (full), C_m (s bits)`

The total ciphertext length exactly equals the plaintext length -- no expansion.

### Decryption with Ciphertext Stealing

Decryption reverses the process. The key insight is that you must decrypt the
second-to-last ciphertext block first (using tweak `T_m`) to recover the stolen
bits, then reassemble and decrypt the final block.

1. Decrypt blocks `C_0` through `C_{m-2}` normally.

2. Decrypt `C_{m-1}` using tweak `T_m` (not `T_{m-1}`) to get intermediate `PP`:
   ```
   PP = AES_dec(Key1, C_{m-1} XOR T_m) XOR T_m
   ```

3. Extract the last `(128 - s)` bits of `PP` -- these are the stolen bits.

4. Reconstruct the full block: concatenate `C_m` (the `s`-bit partial block)
   with the `(128 - s)` stolen bits from step 3.

5. Decrypt this reconstructed block using tweak `T_{m-1}`:
   ```
   P_{m-1} = AES_dec(Key1, reconstructed XOR T_{m-1}) XOR T_{m-1}
   ```

6. The first `s` bits of `PP` from step 2 are `P_m` (the partial plaintext).

### Note on Block Ordering

IEEE 1619 specifies that in the final ciphertext, the full block `C_{m-1}`
comes before the partial block `C_m`. Some implementations may swap their
physical storage order for convenience, since `C_m` is derived from `P_{m-1}`
and `C_{m-1}` is derived from `P_m`. The standard permits this as long as the
external interface presents them in the canonical order.

---

## Sector Size Considerations

| Sector size | Number of 128-bit blocks | Notes |
|-------------|--------------------------|-------|
| 512 bytes   | 32 blocks                | Traditional HDD sector size |
| 4096 bytes  | 256 blocks               | Modern "Advanced Format" / NVMe |

SP 800-38E limits a data unit to at most 2^20 AES blocks (2^24 bytes = 16 MiB).
In practice, the data unit is almost always one disk sector.

Larger sectors are generally preferable for XTS security:
- With 512-byte sectors, an attacker can observe that two sectors are identical
  (since XTS is deterministic per sector number).
- With 4096-byte sectors, the probability of two sectors being entirely
  identical is much lower.
- XTS's security bound degrades with the number of blocks encrypted under the
  same tweak key. Larger sectors mean fewer total data units for the same disk
  size.

---

## Pseudocode: encrypt_sector() and decrypt_sector()

### encrypt_sector()

```
function encrypt_sector(
    key1:          [u8; 32],      // AES-256 data key
    key2:          [u8; 32],      // AES-256 tweak key
    sector_number: u128,          // data unit number (e.g., LBA)
    plaintext:     [u8],          // sector data, length >= 16 bytes
) -> [u8]:                        // ciphertext, same length as plaintext

    block_size = 16               // 128 bits
    num_full_blocks = len(plaintext) / block_size
    remainder = len(plaintext) % block_size

    // If there is a partial final block, the last full block participates
    // in ciphertext stealing, so we process one fewer block in the main loop.
    if remainder > 0:
        main_blocks = num_full_blocks - 1
    else:
        main_blocks = num_full_blocks

    // Compute base tweak: encrypt sector number with Key2
    T = AES_enc(key2, sector_number as little-endian 128-bit)

    ciphertext = []

    // --- Main loop: encrypt full blocks ---
    for j in 0 .. main_blocks:
        PP = plaintext[j * 16 .. (j+1) * 16] XOR T
        CC = AES_enc(key1, PP)
        ciphertext.append(CC XOR T)
        T = gf128_mul_alpha(T)

    // --- Ciphertext stealing for partial final block ---
    if remainder > 0:
        // Encrypt the second-to-last block (block index = main_blocks)
        P_prev = plaintext[main_blocks * 16 .. (main_blocks + 1) * 16]
        PP = P_prev XOR T
        CC = AES_enc(key1, PP)
        CC = CC XOR T
        T_next = gf128_mul_alpha(T)

        // Steal: first 'remainder' bytes of CC become final partial ciphertext
        C_final = CC[0 .. remainder]

        // Pad: partial plaintext + tail of CC
        P_partial = plaintext[(main_blocks + 1) * 16 .. ]
        padded = P_partial || CC[remainder .. 16]

        // Encrypt padded block with next tweak
        PP2 = padded XOR T_next
        CC2 = AES_enc(key1, PP2)
        C_prev = CC2 XOR T_next

        // Output: full block, then partial block
        ciphertext.append(C_prev)
        ciphertext.append(C_final)

    return ciphertext
```

### decrypt_sector()

```
function decrypt_sector(
    key1:          [u8; 32],
    key2:          [u8; 32],
    sector_number: u128,
    ciphertext:    [u8],          // same length as original plaintext
) -> [u8]:

    block_size = 16
    num_full_blocks = len(ciphertext) / block_size
    remainder = len(ciphertext) % block_size

    if remainder > 0:
        main_blocks = num_full_blocks - 1
    else:
        main_blocks = num_full_blocks

    // Compute base tweak
    T = AES_enc(key2, sector_number as little-endian 128-bit)

    plaintext = []

    // --- Main loop: decrypt full blocks ---
    for j in 0 .. main_blocks:
        CC = ciphertext[j * 16 .. (j+1) * 16] XOR T
        PP = AES_dec(key1, CC)
        plaintext.append(PP XOR T)
        T = gf128_mul_alpha(T)

    // --- Ciphertext stealing ---
    if remainder > 0:
        T_m_minus_1 = T
        T_m = gf128_mul_alpha(T)

        // Decrypt the second-to-last ciphertext block with T_m (not T_{m-1})
        C_prev = ciphertext[main_blocks * 16 .. (main_blocks + 1) * 16]
        CC = C_prev XOR T_m
        PP = AES_dec(key1, CC)
        PP = PP XOR T_m

        // First 'remainder' bytes of PP are the partial plaintext P_m
        P_partial = PP[0 .. remainder]

        // Reconstruct full block from partial ciphertext + stolen bits
        C_final = ciphertext[(main_blocks + 1) * 16 .. ]
        reconstructed = C_final || PP[remainder .. 16]

        // Decrypt reconstructed block with T_{m-1}
        CC2 = reconstructed XOR T_m_minus_1
        PP2 = AES_dec(key1, CC2)
        P_prev = PP2 XOR T_m_minus_1

        plaintext.append(P_prev)
        plaintext.append(P_partial)

    return plaintext
```

### gf128_mul_alpha()

```
function gf128_mul_alpha(T: u128) -> u128:
    // T is treated as a 128-bit little-endian polynomial element.
    // Multiply by alpha = x in GF(2^128) with reducing polynomial
    // x^128 + x^7 + x^2 + x + 1.
    carry = (T >> 127) & 1
    result = T << 1
    if carry == 1:
        result = result XOR 0x87
    return result
```

---

## Security Properties and Limitations

**What XTS provides:**
- Confidentiality of data at rest.
- Each block position gets a unique tweak, so identical plaintext at different
  locations produces different ciphertext (unlike ECB).
- No block chaining -- corruption of one ciphertext block affects only that
  block's decryption (good for random-access storage).
- No ciphertext expansion -- ciphertext is exactly the same size as plaintext.

**What XTS does NOT provide:**
- No authentication. An attacker can flip ciphertext bits and the decryption
  will silently produce corrupted plaintext.
- No protection against block-level replay. An attacker can copy an old sector's
  ciphertext back, restoring old data without detection.
- The mode is deterministic: the same plaintext at the same sector number always
  produces the same ciphertext. This leaks equality information at the sector
  level.

**Birthday bound:** XTS security degrades after approximately 2^64 blocks are
encrypted under the same tweak key (Key2), due to the birthday bound on the
128-bit block cipher. For a 1 TB disk with 4096-byte sectors, this corresponds
to roughly 2^28 full disk rewrites -- not a practical concern for most
applications, but IEEE 1619-2025 added explicit key scope limits to address this
formally.
