> [English version](README.md)

# arsenic

Bibliothèque cryptographique pure Rust implémentant le format de chiffrement de fichiers **Arsenic V1** (`.arsn`).

Utilisée par le binaire [`cryptyrust`](../cryptyrust) (GUI + CLI + gestion de clés) et la couche FFI C [`arsenic_ffi`](../ffi).

---

## Fonctionnalités

- **Chiffrement asymétrique hybride post-quantique** — X25519 + ML-KEM-768 ou ML-KEM-1024 (NIST FIPS 203). Chaque destinataire dispose d'un keyslot indépendant ; les fichiers restent déchiffrables par ordinateurs quantiques *et* classiques
- **Signatures ML-DSA-65 optionnelles** (NIST FIPS 204) — les fichiers peuvent être signés lors du chiffrement ; la signature est vérifiée automatiquement au déchiffrement
- **Trois chiffrements AEAD sélectionnables**, configurables indépendamment pour l'en-tête et le payload :
  - `Deoxys-II-256` — AEAD à blocs tweakables *(chiffrement d'en-tête par défaut)*
  - `XChaCha20-Poly1305` — nonce 192 bits, performant en logiciel *(chiffrement payload par défaut)*
  - `AES-256-GCM-SIV` — résistant au mésusage de nonce
- **Dérivation de clé Argon2id** avec deux préréglages (`Interactive` 256 Mio / `Sensitive` 1 Gio). Le HeaderMAC est chiffré avec le KEK complet — chaque tentative de mot de passe coûte la dérivation Argon2id entière, sans oracle rapide
- **Keyslot style LUKS** — le changement de mot de passe réécrit uniquement les 48 octets du wrapper DEK ; le payload n'est jamais re-chiffré
- **Arbre de Merkle BLAKE3** — intégrité à séparation de domaines sur tous les blocs chiffrés ; vérification complète avant toute écriture du plaintext
- **Traitement en blocs en streaming** — mémoire O(taille_bloc + N_blocs × 32) quelle que soit la taille du fichier
- **Rekey résistant aux pannes** — sauvegarde `.bak` écrite et fsyncée (y compris l'entrée du répertoire parent) avant toute écriture en place de l'en-tête
- **Keystore partagé** — paires de clés X25519 + ML-KEM stockées dans `{config}/cryptyrust/keys/` et partagées par la GUI, le CLI et l'outil keygen
- **Effacement du matériel de clé** — toutes les valeurs sensibles dans des wrappers `Secret<T>` (zeroizés à la destruction)

Pour la spécification complète du format binaire, voir [`FORMAT.md`](FORMAT.md).

---

## Démarrage rapide

```toml
[dependencies]
arsenic = { path = "../arsenic" }
```

### Chiffrement / déchiffrement symétrique

```rust
use std::io::Cursor;
use arsenic::{encrypt_arsenic, decrypt_arsenic, ArsenicParams, ArsenicStrength, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Chiffrement
let plaintext = b"hello world";
let password  = Secret::new("ma phrase secrète".to_string());
let params    = ArsenicParams::from(ArsenicStrength::Interactive);

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());
encrypt_arsenic(&mut input, &mut output, &password, &NoUi, plaintext.len() as u64, &params)?;
let ciphertext = output.into_inner();

// Déchiffrement
let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());
decrypt_arsenic(&mut input, &mut output, &password, &NoUi, ciphertext.len() as u64)?;
let plaintext_back = output.into_inner();
```

### Chiffrement / déchiffrement asymétrique (hybride post-quantique)

```rust
use arsenic::{
    encrypt_arsenic, decrypt_arsenic_with_key,
    ArsenicParams, ArsenicStrength, HybridRecipient,
    hybrid_recipient_from_privkey, Secret, Ui,
};
use std::io::Cursor;

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Le destinataire génère son keypair (une fois, stocké dans un fichier .key)
let privkey: [u8; 32] = arsenic::random_bytes_32();
let recipient: HybridRecipient = hybrid_recipient_from_privkey(&privkey);

// L'expéditeur chiffre pour le destinataire (sans mot de passe)
let plaintext = b"message secret";
let r = arsenic::random_bytes_32();
let random_kek: String = r.iter().map(|b| format!("{b:02x}")).collect();
let mut params = ArsenicParams::from(ArsenicStrength::Interactive);
params.recipients = vec![recipient];

let mut input  = Cursor::new(plaintext);
let mut output = Cursor::new(Vec::new());
encrypt_arsenic(
    &mut input, &mut output,
    &Secret::new(random_kek), &NoUi,
    plaintext.len() as u64, &params,
)?;
let ciphertext = output.into_inner();

// Le destinataire déchiffre avec sa clé privée
let mut input  = Cursor::new(&ciphertext);
let mut output = Cursor::new(Vec::new());
decrypt_arsenic_with_key(
    &mut input, &mut output,
    &Secret::new(privkey), &NoUi,
    ciphertext.len() as u64,
)?;
```

### Helpers au niveau fichier

```rust
use std::path::Path;
use arsenic::{arsenic_main_routine, arsenic_rekey, Direction, Secret, Ui};

struct NoUi;
impl Ui for NoUi { fn output(&self, _: i32) {} }

// Chiffrer fichier → fichier.arsn
arsenic_main_routine(
    &Direction::Encrypt, Some("fichier.txt"), Some("fichier.txt.arsn"),
    &Secret::new("phrase secrète".to_string()), Box::new(NoUi), None,
)?;

// Changer le mot de passe (réécrit uniquement le keyslot de 48 octets — instantané quelle que soit la taille)
arsenic_rekey(
    Path::new("fichier.txt.arsn"),
    &Secret::new("ancien mot de passe".to_string()),
    &Secret::new("nouveau mot de passe".to_string()),
    &NoUi,
)?;
```

---

## Vue d'ensemble de l'API

| Symbole | Description |
|---|---|
| `encrypt_arsenic` | Chiffrement en stream : `Read` → `Write + Seek` |
| `decrypt_arsenic` | Déchiffrement en stream : `Read + Seek` → `Write` ; deux passes (vérification Merkle, puis écriture) |
| `decrypt_arsenic_with_key` | Déchiffrement asymétrique en stream avec clé privée X25519 |
| `find_decrypting_key` | Sonde l'en-tête pour trouver quelle clé privée peut ouvrir un fichier |
| `arsenic_main_routine` | Chiffrement/déchiffrement au niveau fichier |
| `arsenic_main_routine_with_key` | Déchiffrement asymétrique au niveau fichier |
| `arsenic_rekey` | Changement de mot de passe en place résistant aux pannes |
| `arsenic_add_recipient` | Ajoute un keyslot hybride à un fichier existant |
| `arsenic_remove_recipient` | Supprime un keyslot par index |
| `arsenic_list_recipients` | Liste les clés X25519 éphémères de tous les keyslots |
| `arsenic_find_matching_key` | Trouve quelle clé stockée peut déchiffrer un fichier |
| `ArsenicParams` | IDs de chiffrements, coût Argon2id, destinataires |
| `HybridRecipient` | Clé publique hybride X25519 + ML-KEM-768 |
| `hybrid_recipient_from_privkey` | Construit un `HybridRecipient` depuis une clé privée |
| `hybrid_encapsulation_key` | Dérive la clé d'encapsulation ML-KEM depuis la clé privée X25519 |
| `ArsenicStrength` | `Interactive` (256 Mio) / `Sensitive` (1 Gio) |
| `CipherId` | `DeoxysII256` · `XChaCha20Poly1305` · `Aes256GcmSiv` |
| `EnvelopeMetadata` | Nom de fichier, commentaire, horodatage depuis l'en-tête déchiffré |
| `Secret<T>` | Wrapper zeroize-on-drop |
| `Ui` | Trait de callback de progression (0–100 %) |
| `bench_cipher_combinations` | Benchmark de tous les chiffrements, classés par débit |
| `keystore::load_keystore` | Charge les paires de clés hybrides depuis `{config}/cryptyrust/keys/` |
| `keystore::load_contacts` | Charge les contacts (clés publiques hybrides) |
| `keystore::resolve_recipient` | Résout un nom/chemin → `HybridRecipient` |
| `encode_pubkey` / `decode_pubkey` | Encodage bech32 des clés X25519 (`arsenic1…`) |
| `encode_mlkem_pubkey` / `decode_mlkem_pubkey` | Encodage bech32 des clés d'encapsulation ML-KEM (`arsenic1m…`) |
| `encode_privkey` / `decode_privkey` | Encodage bech32 des clés privées (`ARSENIC-SECRET-KEY-1…`) |

---

## Paramètres cryptographiques

### Préréglages Argon2id

| Préréglage | t | m (Ko) | p | RAM | Temps |
|---|---|---|---|---|---|
| `Interactive` *(défaut)* | 4 | 262 144 | 4 | 256 Mio | ~1–3 s |
| `Sensitive` | 12 | 1 048 576 | 4 | 1 Gio | ~10–30 s |

Le HeaderMAC est chiffré avec le KEK complet — chaque tentative de mot de passe coûte la dérivation Argon2id entière. Il n'existe aucun oracle moins coûteux.

### IDs de chiffrements (octet d'en-tête)

| Octet | Algorithme | Rôle par défaut |
|---|---|---|
| `0x02` | Deoxys-II-256 | Chiffrement d'en-tête |
| `0x03` | XChaCha20-Poly1305 | Chiffrement payload |
| `0x04` | AES-256-GCM-SIV | — |

### KEM hybride

Deux niveaux de sécurité disponibles, choisis par fichier au chiffrement :

| Niveau | ML-KEM | EK | CT | Sécurité quantique |
|---|---|---|---|---|
| **L768** *(défaut)* | ML-KEM-768 (niveau NIST 3) | 1184 o | 1088 o | ~180 bits |
| **L1024** | ML-KEM-1024 (niveau NIST 5) | 1568 o | 1568 o | ~256 bits |

X25519 + ML-KEM sont combinés via BLAKE3 hybrid KEM binding — le hybride est sécurisé si l'un des deux composants tient.

**Entropie indépendante (depuis v1.5.0) :** les seeds X25519 et ML-KEM sont générés indépendamment depuis le CSPRNG de l'OS. Le fichier `.key` stocke une graine X25519 (32 octets) et une graine ML-KEM séparée de 64 octets (`d||z`) sur la ligne `# mlkem-seed:`. Les anciens fichiers sans cette ligne dérivent le seed ML-KEM via BLAKE3 (compat).

### Signatures ML-DSA-65

Les fichiers peuvent être signés optionnellement avec une clé ML-DSA-65 (NIST FIPS 204, ~192 bits quantiques). La signature couvre les paramètres d'en-tête publics (`pre_mac[77]`). La vérification est automatique et obligatoire au déchiffrement si une signature est présente.

Les clés de signature sont stockées séparément dans des fichiers `.sigkey`.

---

## Résumé du format

```
┌──────────────────────────────────────────────┐  ← offset 0x00
│  Section pré-MAC   77 octets  (pre-MAC)       │  plaintext, protégé par intégrité
│  HeaderMAC         32 octets                  │  BLAKE3_keyed_hash(KEK, pre-MAC)
│  WrappedDEK        48 octets                  │  DEK chiffré AEAD (keyslot symétrique)
│  hybrid_768_count   4 octets                  │  nombre de keyslots ML-KEM-768
│  Keyslot_768_0   1180 octets  ┐               │  DEK wrappé X25519+ML-KEM-768 × N
│  hybrid_1024_count  4 octets  │               │  nombre de keyslots ML-KEM-1024
│  Keyslot_1024_0  1660 octets  │               │  DEK wrappé X25519+ML-KEM-1024 × M
│  ProtectedMeta    ≥66 octets  │               │  TLV AEAD chiffré (racine Merkle, taille…)
│  sig_present        1 octet   ┘               │  0x00=aucune / 0x01=ML-DSA-65
│  [clé+signature   5261 octets]                │  Clé vérif. + signature ML-DSA-65
└──────────────────────────────────────────────┘  ← offset = header_total_size (≥232 octets)
┌──────────────────────────────────────────────┐
│  Bloc 0 : ciphertext + tag AEAD 16 octets     │
│  Bloc 1 : ciphertext + tag AEAD 16 octets     │  blocs traités séquentiellement,
│  …                                            │  traitement parallèle au niveau fichier dans la GUI
└──────────────────────────────────────────────┘
  ↓ Arbre de Merkle BLAKE3 sur tous les blocs chiffrés (racine stockée dans ProtectedMeta)
```

Spécification complète : [`FORMAT.md`](FORMAT.md) · Rendu : [`FORMAT.html`](FORMAT.html).

---

## Licence

GPL-3.0-only — voir [`LICENSE`](../LICENSE).
