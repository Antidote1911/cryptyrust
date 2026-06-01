[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

> [English version](README.md)

# Cryptyrust

**Chiffrement de fichiers cross-platform — GUI drag-and-drop, CLI, et bibliothèque C FFI.**

Binaires pré-compilés pour Linux, macOS (universal) et Windows disponibles sur la [page releases](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Fonctionnalités

- Format **Arsenic V1** (`.arsn`) — entièrement documenté dans [`arsenic/FORMAT.md`](arsenic/FORMAT.md)
- **Chiffrement hybride post-quantique** — X25519 + ML-KEM-768 ou ML-KEM-1024 (NIST FIPS 203). Résiste aux ordinateurs quantiques futurs (harvest-now-decrypt-later)
- **Signatures ML-DSA-65** (NIST FIPS 204) — signature optionnelle lors du chiffrement ; vérification automatique au déchiffrement
- **GUI drag-and-drop** — déposer des fichiers pour chiffrer ou déchiffrer ; mode auto-détecté
- **CLI** pour le scripting et l'automatisation
- **Gestion de clés** intégrée : keypairs de chiffrement (X25519 + ML-KEM) et clés de signature (ML-DSA-65)
- Trois **chiffrements AEAD** sélectionnables indépendamment pour l'en-tête et le payload
- **Argon2id** pour la dérivation de clé (Interactive 256 MiB / Sensitive 1 GiB)
- **Changement de mot de passe** sans re-chiffrer le payload
- **Benchmark** intégré — trouve le chiffrement le plus rapide pour votre machine
- Cross-platform : Linux, Windows, macOS

---

## Structure du projet

| Crate / Répertoire | Sortie | Description |
|---|---|---|
| [`arsenic/`](arsenic/) | bibliothèque | Core cryptographique — [README](arsenic/README.md) · [Spec format](arsenic/FORMAT.md) |
| [`cryptyrust/`](cryptyrust/) | `cryptyrust` | GUI + CLI + gestion de clés (binaire unique) — [README](cryptyrust/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | Couche FFI compatible C — [README](ffi/README.md) |

---

## GUI — utilisation

1. **Glisser-déposer** des fichiers sur la fenêtre, ou cliquer **Add files**.
2. Le mode est auto-détecté : `.arsn` → **Decrypt**, plaintext → **Encrypt**.
3. Cliquer **Encrypt** / **Decrypt** et entrer le mot de passe.

### Chiffrement pour des destinataires (sans mot de passe)

1. Ouvrir **Keys → Key Manager** → générer un keypair ou ajouter un contact.
2. Lors du chiffrement, sélectionner les destinataires dans la popup — le mot de passe devient optionnel.
3. Le destinataire déchiffre avec sa clé privée, sans connaître le mot de passe.

### Configuration

| Réglage | Options | Défaut |
|---|---|---|
| Argon2id strength | Interactive (256 MiB) · Sensitive (1 GiB) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |

---

## CLI — utilisation rapide

Le binaire `cryptyrust` fonctionne en CLI quand on lui passe des arguments, et ouvre la GUI sinon.

```bash
# Chiffrer avec mot de passe
cryptyrust -e document.pdf -p "ma phrase secrète"

# Chiffrer pour des destinataires (ML-KEM-768, défaut)
cryptyrust -e document.pdf -R alice -R bob

# Chiffrer avec ML-KEM-1024 (niveau NIST 5, ~256 bits quantiques)
cryptyrust -e document.pdf -R alice --kem-level 1024

# Chiffrer + signer avec ML-DSA-65
cryptyrust -e document.pdf -p "phrase" -S alice

# Déchiffrer (essai auto des clés, vérifie la signature si présente)
cryptyrust -d document.pdf.arsn

# Déchiffrer avec un fichier de clé spécifique
cryptyrust -d document.pdf.arsn -i ~/.config/cryptyrust/keys/alice.key

# Changer le mot de passe (ne re-chiffre pas le payload)
cryptyrust --rekey document.pdf.arsn

# Benchmark des chiffrements
cryptyrust --bench
```

---

## Gestion des clés

```bash
# Keypairs de chiffrement (X25519 + ML-KEM)
cryptyrust keygen -n alice --store           # générer et sauvegarder dans le keystore
cryptyrust keygen -n alice -o alice.key      # générer vers un fichier
cryptyrust keygen --list                     # lister les keypairs stockés
cryptyrust keygen -y alice.key               # afficher la clé publique d'un .key

# Clés de signature ML-DSA-65
cryptyrust keygen --sign -n alice --store    # générer une clé de signature → keystore
cryptyrust keygen --sign -n alice -o alice.sigkey
cryptyrust keygen --list-sign                # lister les clés de signature stockées
```

Le keystore est partagé entre la GUI et le CLI — une clé générée dans un mode est immédiatement disponible dans l'autre.

## Signature

```bash
cryptyrust -e document.pdf -S alice -p "phrase"       # chiffrement + signature
cryptyrust -d document.pdf.arsn -p "phrase"           # déchiffrement (vérifie la signature)
```

---

## Compilation

### Prérequis

- [Rust toolchain](https://rustup.rs/) stable
- **Linux uniquement** — paquets de développement X11 / Wayland :
  ```bash
  sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                   libxkbcommon-dev libssl-dev pkg-config
  ```

### Build

```bash
cargo build --release
# CLI → target/release/cryptyrust_cli
# GUI → target/release/cryptyrust
# keygen → target/release/crypty-keygen
```

### macOS universal binary

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create target/x86_64-apple-darwin/release/cryptyrust \
             target/aarch64-apple-darwin/release/cryptyrust \
             -output cryptyrust_universal
```

---

## Avertissement sur la perte de données

Si vous perdez ou oubliez votre mot de passe, **vos données ne peuvent pas être récupérées.** Il n'y a pas de porte dérobée ni de mécanisme de récupération. Utilisez un gestionnaire de mots de passe ou conservez une sauvegarde sécurisée de votre phrase de passe.

Si vous avez chiffré pour des destinataires asymétriques sans mot de passe, la perte de la clé privée `.key` est également irrécupérable.

---

## Bibliothèque et format

Toute la logique cryptographique est dans la crate [`arsenic`](arsenic/).  
Voir [`arsenic/README.md`](arsenic/README.md) pour l'API et [`arsenic/FORMAT.md`](arsenic/FORMAT.md) pour la spécification binaire complète du format Arsenic V1.
