[![Build Status](https://www.travis-ci.com/Antidote1911/cryptyrust.svg?branch=master)](https://www.travis-ci.com/Antidote1911/cryptyrust)
[![Build status](https://ci.appveyor.com/api/projects/status/3yludsnwm5a1jnsa/branch/master?svg=true)](https://ci.appveyor.com/project/Antidote1911/cryptyrust/branch/master)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)


# Cryptyrust
**Simple cross-platform cli and gui file encryption.**

## Usage:
**Data Loss Disclaimer:** if you lose or forget your password, **your data cannot be recovered!** Use a password manager or another secure form of backup.

With gui, Just drop a file onto the window, set a password, and choose where to save it. To decrypt, drop the encrypted file on the window, enter the password, and choose the output location.

Exemples With CLI :
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
**You must build Rust CLI application and core before trying to build Qt/C++ GUI.**
In the root folder run `cargo build --release`
Executable will be at `target/release/cryptyrust_cli'.

GUI compilation need Qt6. After CLI was compiled, build the GUI Qt/C++ project. Open a terminal in gui folder and:

```bash
   cmake
   make
   make install
```

## Windows Compilation instructions:
On Windows, cryptyrust need MSVC compiler for libsodium compilation.
- Install Qt6 framework for msvc 2019 64 bits
- Install [Visual Studio Build Tools 2019](https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16)  
- Make sure rust use msvc. Run in command line :
`rustup default stable-x86_64-pc-windows-msvc`
- Build rust CLI App and core project : `cargo build --release`
- Open the gui folder with QtCreator and build it. (make sure QtCreator use msvc toolchain and not  MinGW)

### Thanks to JetBrains for open source support

<a href="https://www.jetbrains.com/"><img src="./jetbrains.png" alt="jetbrains" width="150"></a>
<img src='https://www.gnu.org/graphics/gplv3-with-text-136x68.png'/>
