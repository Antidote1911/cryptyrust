[![Cargo Build & Test](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Antidote1911/cryptyrust/actions/workflows/ci.yml)
[![License: GPL3](https://img.shields.io/badge/License-GPL3-green.svg)](https://opensource.org/licenses/GPL-3.0)

# Cryptyrust

**Chiffrement de fichiers cross-platform — GUI drag-and-drop, CLI, et bibliothèque C FFI.**

Binaires pré-compilés pour Linux, macOS (universal) et Windows disponibles sur la [page releases](https://github.com/Antidote1911/cryptyrust/releases/latest).

<img src='cryptyrust.png'/>

---

## Fonctionnalités

- Format **Arsenic V1** (`.arsn`) — entièrement documenté dans [`arsenic/FORMAT.md`](arsenic/FORMAT.md)
- **Chiffrement hybride post-quantique** — X25519 + ML-KEM-768 (NIST FIPS 203) pour les destinataires asymétriques. Résiste aux ordinateurs quantiques futurs (harvest-now-decrypt-later)
- **GUI drag-and-drop** — déposer des fichiers pour chiffrer ou déchiffrer ; mode auto-détecté
- **CLI** pour le scripting et l'automatisation
- **Gestion de clés** intégrée : générer des paires de clés hybrides, ajouter des contacts, chiffrer pour plusieurs destinataires
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
| [`cli/`](cli/) | `cryptyrust_cli` | Interface ligne de commande — [README](cli/README.md) |
| [`gui/`](gui/) | `cryptyrust` | GUI native (egui) — [README](gui/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | Couche FFI compatible C — [README](ffi/README.md) |
| [`crypty-keygen/`](crypty-keygen/) | `crypty-keygen` | Générateur de clés hybrides — [README](crypty-keygen/README.md) |

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

```bash
# Chiffrer avec mot de passe
cryptyrust_cli -e document.pdf -p "ma phrase secrète"

# Déchiffrer (essai auto des clés stockées, puis demande le mot de passe)
cryptyrust_cli -d document.pdf.arsn

# Chiffrer pour des destinataires (sans mot de passe)
cryptyrust_cli -e document.pdf -R alice -R bob

# Déchiffrer avec un fichier de clé spécifique
cryptyrust_cli -d document.pdf.arsn -i ~/.config/cryptyrust/keys/alice.key

# Changer le mot de passe (ne re-chiffre pas le payload)
cryptyrust_cli --rekey document.pdf.arsn

# Benchmark des chiffrements
cryptyrust_cli --bench
```

---

## crypty-keygen — gestion des clés

```bash
# Générer un keypair et l'afficher (stdout)
crypty-keygen -n alice

# Sauvegarder directement dans le keystore partagé (~/.config/cryptyrust/keys/)
crypty-keygen -n alice --store

# Lister les clés stockées
crypty-keygen --list

# Extraire la clé publique d'un fichier .key
crypty-keygen -y alice.key
```

Le keystore est partagé entre la GUI, le CLI et crypty-keygen — une clé générée par l'un est immédiatement disponible dans les autres.

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
