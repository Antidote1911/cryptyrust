

# Cryptyrust
**Simple cross-platform cli and gui file encryption.**

## Usage:
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

**Data Loss Disclaimer:** if you lose or forget your password, **your data cannot be recovered!** Use a password manager or another secure form of backup.

## Specifications:
Cryptyrust uses the `pwhash` and `secretstream` APIs of [libsodium](https://doc.libsodium.org/) via [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide).
(Password hash use Argon2id and encryption algorithm is xchacha20poly1305.)

## CLI Compilation instructions:
```bash
   cargo build --release
   # Executable will be at `target/release/cryptyrust_cli`(`.exe`).
```

## GUI Compilation instructions:
**CLI must be compiled to generate the cryptyrust_core lib.**

After CLI was compiled, open `gui/cryptyrust.pro` in Qt Creator, make sure kit is 64bit, and build in release. Without Qt Creator, open a terminal in project folder and:

```bash
   qmake
   make
#if you want install :
   make install
```
### Thanks to JetBrains for open source support

<a href="https://www.jetbrains.com/"><img src="./jetbrains.png" alt="jetbrains" width="150"></a>
<img src='https://www.gnu.org/graphics/gplv3-with-text-136x68.png'/>
