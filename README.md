[![Build Status](https://app.travis-ci.com/Antidote1911/cryptyrust.svg?branch=master)](https://app.travis-ci.com/Antidote1911/cryptyrust)
[![Build status](https://ci.appveyor.com/api/projects/status/3yludsnwm5a1jnsa/branch/master?svg=true)](https://ci.appveyor.com/project/Antidote1911/cryptyrust/branch/master)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)


# Cryptyrust
**Simple cross-platform cli file encryption.**<br/>
Latest release is [here](https://github.com/Antidote1911/cryptyrust/releases/latest).

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
Cryptyrust uses the `pwhash` and `secretstream` APIs of [libsodium](https://doc.libsodium.org/) via [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide).
(Password hash use Argon2id and encryption algorithm is xchacha20poly1305.)

## Linux Compilation instructions:
In the root folder run `cargo build --release`
Executable will be at `target/release/cryptyrust_cli'.

## Windows Compilation instructions:
On Windows, cryptyrust need MSVC compiler for libsodium compilation.
- Install [Visual Studio Build Tools 2019](https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16)  
- Make sure rust use msvc. Run in command line :
`rustup default stable-x86_64-pc-windows-msvc`
- Build rust CLI App and core project : `cargo build --release`

### Thanks to JetBrains for open source support

<a href="https://www.jetbrains.com/"><img src="./jetbrains.png" alt="jetbrains" width="150"></a>
<img src='https://www.gnu.org/graphics/gplv3-with-text-136x68.png'/>
