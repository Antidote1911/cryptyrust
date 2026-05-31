# Format de fichier Arsenic V1 — Spécification complète

> **Version du format** : `[0x00, 0x01]`  
> **Magic** : `41 52 53 4E` ("ARSN")  
> **Extension habituelle** : `.arsn`  
> Toutes les valeurs multi-octets sont en **little-endian** sauf mention contraire.

---

## 1. Vue d'ensemble

Un fichier Arsenic V1 est composé de deux parties consécutives :

```
┌───────────────────────────────────────────────┐  ← offset 0
│  En-tête  (taille variable)                   │  longueur = header_total_size
├───────────────────────────────────────────────┤  ← offset header_total_size
│  Payload chiffré (blocs AEAD consécutifs)     │  jusqu'à la fin du fichier
└───────────────────────────────────────────────┘
```

Le champ `header_total_size` (u32 LE à l'offset 0x09) encode la longueur exacte de l'en-tête. Le payload commence immédiatement après.

---

## 2. Structure de l'en-tête

```
┌─────────────────────────────────────────────┐  offset 0x00
│  Section pré-MAC          77 octets         │  couverts par le HeaderMAC
├─────────────────────────────────────────────┤  offset 0x4D
│  HeaderMAC                32 octets         │  HMAC-SHA256
├─────────────────────────────────────────────┤  offset 0x6D  (PUB_HEADER_LEN = 109)
│  Région d'enveloppe       variable          │  clés wrappées + métadonnées chiffrées
└─────────────────────────────────────────────┘  offset header_total_size
```

---

## 3. Section pré-MAC (octets 0x00 – 0x4C, 77 octets)

Ces 77 octets sont intégralement couverts par le HeaderMAC.

```
Offset  Taille  Champ                Description
──────────────────────────────────────────────────────────────────────────────
0x00      4     magic                Octets fixes : 41 52 53 4E  ("ARSN")
0x04      2     version              Octets fixes : 00 01
0x06      1     kdf_id               01 = Argon2id
0x07      1     hdr_cipher_id        Chiffrement enveloppe (voir §9)
0x08      1     pld_cipher_id        Chiffrement payload (voir §9)
0x09      4     header_total_size    u32 LE — taille totale de l'en-tête
0x0D     16     salt                 Sel Argon2id (16 octets aléatoires)
0x1D      4     t_cost               u32 LE — itérations Argon2id
0x21      4     m_cost               u32 LE — mémoire en Kio
0x25      4     p_cost               u32 LE — parallélisme Argon2id
0x29     24     file_base_nonce      Base des nonces de bloc (aléatoire)
0x41     12     kek_nonce            Nonce AEAD du keyslot symétrique
──────────────────────────────────────────────────────────────────────────────
                                     Total : 77 octets  (PRE_MAC_LEN = 0x4D)
```

---

## 4. HeaderMAC (octets 0x4D – 0x6C, 32 octets)

```
PreKey    = Argon2id(password, salt, t=1, m=8 192 Kio, p=1)  → 32 oct.
HeaderMAC = HMAC-SHA256( PreKey[32], pré_mac[77] )            → 32 oct.
```

Le `PreKey` utilise des paramètres **fixes** indépendants des paramètres KDF du fichier. Il permet de rejeter un mauvais mot de passe en ~2 ms, avant d'engager la dérivation coûteuse du KEK.

**Fin de l'en-tête public : 109 octets** (`PUB_HEADER_LEN = 0x6D`).

---

## 5. Région d'enveloppe (offset 0x6D, taille variable)

```
┌──────────────────────────────────────────────────────────────┐
│  WrappedDEK symétrique          48 octets  (offset 0x6D)     │
├──────────────────────────────────────────────────────────────┤
│  hybrid_count  (u32 LE)          4 octets  (offset 0x9D)     │
├──────────────────────────────────────────────────────────────┤
│  Keyslot hybride #0           1 180 octets  ┐                │
│  Keyslot hybride #1           1 180 octets  │  × N           │
│  …                                          ┘                │
├──────────────────────────────────────────────────────────────┤
│  ProtectedMetadata              variable   (TLV_len + 16)    │
└──────────────────────────────────────────────────────────────┘
```

### 5.1 WrappedDEK symétrique (48 octets)

```
WrappedDEK = AEAD_hdr( KEK[32], nonce_env(kek_nonce), [], DEK[32] )
           = ciphertext[32] || tag[16]
```

### 5.2 Compteur (4 octets)

`hybrid_count` (u32 LE) : nombre N de keyslots hybrides. Vaut 0 si aucun destinataire.

### 5.3 Keyslot hybride — 1 180 octets chacun

Chaque keyslot permet à un destinataire de déchiffrer le fichier **sans connaître le mot de passe**. Il utilise un KEM hybride post-quantique.

```
Offset  Taille  Champ                Description
──────────────────────────────────────────────────────────────────────────────
  0      32     ephemeral_x25519     Clé publique X25519 éphémère
 32    1088     mlkem_ciphertext     Ciphertext ML-KEM-768
1120     12     kek_nonce            Nonce AEAD
1132     48     wrapped_dek          AEAD(wrapping_key, kek_nonce, [], DEK)
──────────────────────────────────────────────────────────────────────────────
                                     Total : 1 180 octets
```

**Calcul de la clé de wrapping hybride :**

```
Chiffrement :
  ephemeral_x25519_sk  ← 32 octets aléatoires
  ephemeral_x25519_pk  ← X25519PublicKey(ephemeral_x25519_sk)
  ss_x25519            ← X25519_ECDH(ephemeral_x25519_sk, recipient.x25519)

  m[32]                ← 32 octets aléatoires
  (mlkem_ct, ss_mlkem) ← ML-KEM-768.Encaps(recipient.mlkem, m)

  wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM",
                   ephemeral_x25519_pk[32] || mlkem_ct[1088]
                   || ss_x25519[32] || ss_mlkem[32])

  wrapped_dek  ← AEAD_hdr(wrapping_key, kek_nonce, [], DEK)

Déchiffrement :
  ss_x25519  ← X25519_ECDH(recipient_x25519_sk, ephemeral_x25519_pk)
  ss_mlkem   ← ML-KEM-768.Decaps(recipient_x25519_sk_seed, mlkem_ct)
  wrapping_key ← même BLAKE3
  DEK        ← AEAD_hdr_decrypt(wrapping_key, kek_nonce, wrapped_dek)
```

**Clé ML-KEM dérivée de la clé X25519 :**

La clé secrète ML-KEM-768 est dérivée déterministiquement de la clé privée X25519 :
```
seed[64] = BLAKE3_derive_key("Arsenic ML-KEM d", x25519_sk)[32]
        || BLAKE3_derive_key("Arsenic ML-KEM z", x25519_sk)[32]

(dk_mlkem, ek_mlkem) ← ML-KEM-768.KeyGen_internal(seed)
```

Un seul fichier `.key` de 32 octets suffit ; les deux clés sont recalculées à l'usage.

### 5.4 ProtectedMetadata (taille variable)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce), [], meta_tlv )
                  = ciphertext[len(meta_tlv)] || tag[16]
```

**Champs TLV obligatoires (60 octets) :**

| Tag    | Longueur | Valeur                                 |
|--------|----------|----------------------------------------|
| `0x02` | 32       | MerkleRoot (racine BLAKE3)             |
| `0x03` | 8        | OriginalSize (u64 LE)                  |
| `0x04` | 8        | CompressedSize (u64 LE, = OriginalSize)|
| `0x05` | 1        | BlockSizeId                            |
| `0x06` | 1        | MerkleAlgoId = `0x01`                  |

**Champs TLV optionnels :**

| Tag    | Max  | Valeur                          |
|--------|------|---------------------------------|
| `0x10` | 255  | Filename (UTF-8)                |
| `0x11` | 255  | Comment (UTF-8)                 |
| `0x12` | 8    | TimestampSecs (u64 LE)          |

---

## 6. Taille de l'en-tête

```
header_total_size = PUB_HEADER_LEN(109)
                  + WRAPPED_DEK_LEN(48)
                  + ASYM_COUNT_LEN(4)
                  + N × HYBRID_KEYSLOT_LEN(1180)
                  + len(meta_tlv) + GCM_TAG(16)
```

| Configuration             | Taille de l'en-tête         |
|---------------------------|-----------------------------|
| Minimum (0 keyslot)       | **237 octets**              |
| 1 destinataire hybride    | 1 417 octets                |
| N destinataires hybrides  | 237 + N × 1 180 octets      |
| Maximum (256 keyslots)    | ~303 KiB                    |

Limite : `MAX_ASYM_KEYSLOTS = 256`, `MAX_HEADER_TOTAL_SIZE = 64 MiB`.

---

## 7. Payload chiffré

Le payload commence à l'offset `header_total_size` et s'étend jusqu'à la fin du fichier. Il est composé de **blocs AEAD indépendants**.

### 7.1 Taille de bloc

| BlockSizeId | Taille plaintext       | Condition        |
|-------------|------------------------|------------------|
| `0x01`      | 4 194 304 oct. (4 Mio) | Fichiers < 4 Gio |
| `0x02`      | 33 554 432 oct. (32 Mio)| Fichiers ≥ 4 Gio |

### 7.2 Dérivation des clés et nonces de bloc

Pour le bloc `i` (u64 LE, commence à 0) :

```
block_key_i[32]   ← BLAKE3_keyed_hash(key=DEK, data=i.to_le_bytes()[8])
material[32]      ← file_base_nonce[24] || i.to_le_bytes()[8]
block_nonce_i[24] ← BLAKE3_derive_key("Arsenic V1 Block Nonce", material)[0..24]
aad_i[8]          ← i.to_le_bytes()
```

### 7.3 Structure sur disque

Blocs concaténés sans séparateur :

```
bloc_0[ N₀ + 16 ] || bloc_1[ N₁ + 16 ] || … || bloc_k[ Nₖ + 16 ]
```

où `bloc_i = AEAD_pld(block_key_i, block_nonce_i_tronqué, aad_i, plaintext_i)`.

---

## 8. Arbre de Merkle

Calculé sur les **blocs chiffrés**, avant toute écriture du plaintext :

```
leaf_i[32]            ← BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1", bloc_chiffré_i)
node(gauche, droite)  ← BLAKE3_derive_key("Arsenic V1 Merkle Node v1", gauche || droite)
```

Construction : paires successives de bas en haut ; nœud impair promu tel quel. Racine stockée dans la ProtectedMetadata (tag `0x02`).

| Blocs | Racine        |
|-------|---------------|
| 0     | `[0u8; 32]`   |
| 1     | `leaf_0`      |
| N > 1 | Arbre récursif|

---

## 9. Chiffrements AEAD

Tous produisent un tag de **16 octets**. `hdr_cipher_id` et `pld_cipher_id` sont indépendants.

### 9.1 Identifiants

| cipher_id | Algorithme               | Nonce natif |
|-----------|--------------------------|-------------|
| `0x02`    | Deoxys-II-256            | 15 octets   |
| `0x03`    | XChaCha20-Poly1305       | 24 octets   |
| `0x04`    | AES-256-GCM-SIV          | 12 octets   |

### 9.2 Expansion du nonce d'enveloppe (kek_nonce de 12 octets)

| Algorithme         | Nonce effectif | Procédé |
|--------------------|----------------|---------|
| AES-256-GCM-SIV    | 12 oct.        | `kek_nonce[0..12]` directement |
| Deoxys-II-256      | 15 oct.        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce‖0×20)[0..15]` |
| XChaCha20-Poly1305 | 24 oct.        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20",   kek_nonce‖0×20)[0..24]` |

### 9.3 Troncature du nonce de bloc (24 octets dérivés)

| Algorithme         | Octets utilisés            |
|--------------------|----------------------------|
| AES-256-GCM-SIV    | `block_nonce_i[0..12]`     |
| Deoxys-II-256      | `block_nonce_i[0..15]`     |
| XChaCha20-Poly1305 | `block_nonce_i[0..24]`     |

---

## 10. Chaîne de dérivation — résumé

```
mot_de_passe
  │
  ├── Argon2id(t=1, m=8192Ki, p=1, salt)    → PreKey[32]
  │         └── HMAC-SHA256(PreKey, pré_mac[77])   → HeaderMAC[32]
  │
  └── Argon2id(t_cost, m_cost, p_cost, salt) → KEK[32]
            └── AEAD_hdr(KEK, nonce_env(kek_nonce), [], DEK) → WrappedDEK[48]

aléatoire → DEK[32]
  ├── BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)           → MetaKey[32]
  ├── BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]    → MetaNonce[12]
  ├── Pour bloc i :
  │     BLAKE3_keyed_hash(DEK, i.to_le_bytes())                   → block_key_i[32]
  │     BLAKE3_derive_key("Arsenic V1 Block Nonce",
  │                        file_base_nonce||i.to_le_bytes())[0..24] → block_nonce_i[24]
  └── Pour keyslot hybride j :
        aléatoire → ephemeral_x25519_sk[32] → ephemeral_x25519_pk[32]
        X25519_ECDH(ephemeral_x25519_sk, recipient.x25519)         → ss_x25519[32]
        aléatoire → m[32]
        ML-KEM-768.Encaps(recipient.mlkem, m)                      → (mlkem_ct[1088], ss_mlkem[32])
        BLAKE3_derive_key("Arsenic Hybrid KEM",
          eph_x25519_pk||mlkem_ct||ss_x25519||ss_mlkem)            → wrapping_key[32]
        AEAD_hdr(wrapping_key, kek_nonce_j, [], DEK)               → wrapped_dek_j[48]
```

---

## 11. Diagramme complet — fichier minimal (0 keyslot)

```
Offset     Taille  Contenu
─────────────────────────────────────────────────────────────────────────────
0x000000     4     magic            : 41 52 53 4E
0x000004     2     version          : 00 01
0x000006     1     kdf_id           : 01
0x000007     1     hdr_cipher_id    : ex. 02
0x000008     1     pld_cipher_id    : ex. 03
0x000009     4     header_total_size: ED 00 00 00  (237, u32 LE)
0x00000D    16     salt             : [16 oct. aléatoires]
0x00001D     4     t_cost           : 04 00 00 00
0x000021     4     m_cost           : 00 00 04 00  (262 144 Kio)
0x000025     4     p_cost           : 04 00 00 00
0x000029    24     file_base_nonce  : [24 oct. aléatoires]
0x000041    12     kek_nonce        : [12 oct. aléatoires]
──────── fin section pré-MAC : 77 octets ────────────────────────────────────
0x00004D    32     HeaderMAC        : HMAC-SHA256(PreKey, pré_mac[77])
──────── fin en-tête public : 109 octets ────────────────────────────────────
0x00006D    48     WrappedDEK       : AEAD_hdr(KEK, ...)
0x00009D     4     hybrid_count     : 00 00 00 00
0x0000A1    76     ProtectedMetadata: AEAD_hdr(MetaKey, ..., TLV[60]) + tag[16]
──────── fin en-tête : 237 octets ───────────────────────────────────────────
0x0000ED     ∞     Payload (blocs consécutifs)
─────────────────────────────────────────────────────────────────────────────
```

---

## 12. Changement de mot de passe (rekey)

Seul le `WrappedDEK` (48 octets) est re-chiffré. Le payload, la ProtectedMetadata et les keyslots hybrides ne changent pas. Atomicité garantie par un `.bak` fsynced avant l'écriture en place.

---

## 13. Identités des utilisateurs

| Composant               | Taille      | Stockage      |
|-------------------------|-------------|---------------|
| Clé privée X25519       | 32 octets   | `.key` (seed) |
| Clé publique X25519     | 32 octets   | dérivée       |
| Graine ML-KEM-768       | 64 octets   | dérivée de X25519 |
| Clé d'encapsulation EK  | 1 184 octets| dérivée       |
| Clé secrète DK          | 2 400 octets| calculée en RAM uniquement |

Un seul fichier `.key` (32 octets encodés en `ARSENIC-SECRET-KEY-1{bech32}`) suffit pour l'ensemble du keypair hybride.

---

## 14. Propriétés de sécurité

| Propriété                         | Mécanisme                                                       |
|-----------------------------------|-----------------------------------------------------------------|
| Confidentialité — DEK             | AEAD sous KEK (Argon2id) ; DEK aléatoire 32 oct.               |
| Confidentialité — métadonnées     | AEAD sous MetaKey = f(DEK)                                      |
| Confidentialité — payload         | AEAD sous clés par-bloc dérivées de DEK + index                 |
| Intégrité par bloc                | Tag AEAD 16 octets par bloc                                     |
| Intégrité fichier entier          | Racine Merkle BLAKE3 vérifiée avant toute écriture plaintext    |
| Ordre des blocs                   | Index lié comme AAD dans chaque AEAD de bloc                    |
| Intégrité de l'en-tête            | HMAC-SHA256 sur 77 octets (paramètres KDF + IDs chiffrement)   |
| Résistance oracle rapide          | PreKey via mini-Argon2id (~15 000 H/s sur GPU)                  |
| Résistance DoS (paramètres KDF)   | Paramètres forgés rejetés par MAC avant tout Argon2id           |
| Résistance quantique — payload    | Symmetric 256 bits : Grover exige 2¹²⁸ — déjà post-quantique   |
| Résistance quantique — keyslots   | ML-KEM-768 (NIST niveau 3) résiste à Shor                       |
| Défense en profondeur             | Hybride X25519+ML-KEM : une faille dans l'un ne compromet pas l'autre |
| Harvest-now-decrypt-later         | ML-KEM protège les fichiers chiffrés aujourd'hui                |
| Anonymat des destinataires        | Les keyslots ne révèlent pas la clé publique du destinataire    |
| Séparation des domaines Merkle    | BLAKE3_derive_key avec contextes distincts                      |
| Effacement mémoire                | `Secret<T>` appelle `zeroize` à la destruction                  |
