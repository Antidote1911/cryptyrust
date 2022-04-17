[![Build status](https://ci.appveyor.com/api/projects/status/3yludsnwm5a1jnsa/branch/master?svg=true)](https://ci.appveyor.com/project/Antidote1911/cryptyrust/branch/master)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)


# Cryptyrust
**Simple cross-platform gui and cli file encryption.**<br/>
Latest Windows x64 release is [here](https://github.com/Antidote1911/cryptyrust/releases/latest).

## Usage:
**Data Loss Disclaimer:** if you lose or forget your password, **your data cannot be recovered!** Use a password manager or another secure form of backup.<br/>

Exemples :
```bash
# encrypt the file test.mp4 with password 12345678 and décrypt it:
  ./cryptyrust_cli -e test.mp4 -p 12345678
  ./cryptyrust_cli -d test.mp4.crypty -p 12345678

# Or you can enter an output file name with -o flag if you want:
  ./cryptyrust_cli -e test.mp4 -p 12345678 -o myEncryptedFile
  ./cryptyrust_cli -d myEncryptedFile -p 12345678 -o myDecryptedFile
```

## Specifications:
Cryptyrust uses the `argon2` and `crypto_secretstream` crates of [Rust Crypto](https://github.com/RustCrypto).
(Password hash use Argon2id variant and encryption algorithm is xchacha20poly1305.)

## Linux Compilation instructions:
In the root folder run `cargo build --release`
Executable will be at `target/release/cryptyrust_cli'.

## Windows Compilation instructions:

- Install [Visual Studio Build Tools 2019](https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16)  
- Make sure rust use msvc. Run in command line :
`rustup default stable-x86_64-pc-windows-msvc`
- Build rust CLI App and core project : `cargo build --release`
