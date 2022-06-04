# Cryptyrust encrypted file header format

The file start with the magic number 43 52 59 50. This allow to check if it's a cryptyrust file. Cryptyrust GUI automatically switch in decryption mode if the signature is good.

4 bytes for magic number
- 43 52 59 50

2 bytes for header version.
- DE 01 -> Version 1

2 bytes for used algorithm:
- 0E 01 -> XChaCha20Poly1305
- 0E 02 -> Aes256Gcm
- 0E 03 -> DeoxysII256
- 0E 04 -> Aes256GcmSiv

2 bytes for used argon2 strength:
- BE 01 -> Interactive
- BE 02 -> Moderate
- BE 03 -> Sensitive

16 bytes of random Salt. Example:
- 17 5B AF DA EF 71 3A AB C0 52 C1 6D E6 CE 9C D1

Padding 16 bytes of 0 for future usage.
- 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

The random nonce. Example with Aes256Gcm (8 bytes):
- 4B 11 E7 68 4E 51 FF 25

Padding some 0 to always have a 64 bytes header. With this example 64-(4+2+2+2+16+16+8)=16 bytes:
- 00 00 00 00 00 00 00 00 00 00 00 00 00 00

In this file we use Aes256Gcm (0E 02) with Sensitive derivation (BE 03). The nonce is 8 bytes with Aes256Gcm. For a 64 bytes header, 14 bytes of 0 are padded. The file look like:    
`43 52 59 50` `DE 01` `0E 02` `BE 03` `17 5B AF DA EF 71 3A AB C0 52 C1 6D E6 CE 9C D1` `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` `4B 11 E7 68 4E 51 FF 25` `00 00 00 00 00 00 00 00 00 00 00 00 00 00` XX XX XX XX XX.........

In this file we use XChaCha20Poly1305 (0E 01) with Interactive derivation (BE 01). The nonce is 20 bytes with XChaCha20Poly1305. For a 64 bytes header, 2 bytes of 0 are padded. The file look like:  
`43 52 59 50` `DE 01` `0E 01` `BE 01` `D4 51 9F E8 CC E4 AB 66 A8 17 7B 1C F0 A8 81 A9` `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` `68 81 A4 FC B1 C4 60 B1 66 EF 12 20 94 FE 56 72 21 00 A0 F1` `00 00` XX XX XX XX XX.........
