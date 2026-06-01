> [English version](FORMAT.md)

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
│  HeaderMAC                32 octets         │  BLAKE3_keyed_hash(KEK, pré-MAC)
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
KEK       = Argon2id(password, salt, t_cost, m_cost, p_cost)  → 32 oct.
HeaderMAC = BLAKE3_keyed_hash( clé=KEK[32], données=pré_mac[77] ) → 32 oct.
```

Le HeaderMAC est chiffré avec le KEK complet, donc chaque tentative de mot
de passe coûte la dérivation Argon2id entière. Un mauvais mot de passe produit
un KEK incorrect dont le MAC ne correspond pas — la non-concordance est
détectée avant toute tentative de déchiffrement AEAD.

**Protection DoS :** avant d'invoquer Argon2id, l'implémentation valide que les
paramètres KDF déclarés sont dans des bornes sûres
(`t_cost ≤ 64`, `m_cost ≤ 4 Gio`, `p_cost ≤ 16`). Un fichier falsifié avec des
paramètres absurdes est rejeté immédiatement sans aucun coût.

**Fin de l'en-tête public : 109 octets** (`PUB_HEADER_LEN = 0x6D`).

---

## 5. Région d'enveloppe (offset 0x6D, taille variable)

```
┌──────────────────────────────────────────────────────────────┐
│  WrappedDEK symétrique          48 octets  (offset 0x6D)     │
├──────────────────────────────────────────────────────────────┤
│  hybrid_768_count  (u32 LE)      4 octets  (offset 0x9D)     │
├──────────────────────────────────────────────────────────────┤
│  Keyslot ML-KEM-768 #0        1 180 octets  ┐               │
│  Keyslot ML-KEM-768 #1        1 180 octets  │  × N          │
│  …                                          ┘               │
├──────────────────────────────────────────────────────────────┤
│  hybrid_1024_count (u32 LE)      4 octets                    │
├──────────────────────────────────────────────────────────────┤
│  Keyslot ML-KEM-1024 #0       1 660 octets  ┐               │
│  Keyslot ML-KEM-1024 #1       1 660 octets  │  × M          │
│  …                                          ┘               │
├──────────────────────────────────────────────────────────────┤
│  ProtectedMetadata              variable   (TLV_len + 16)    │
├──────────────────────────────────────────────────────────────┤
│  sig_present                      1 octet  0x00 ou 0x01      │
│  [clé de vérif. ML-DSA-65]     1 952 octets  ┐ présents     │
│  [signature ML-DSA-65]          3 309 octets  ┘ si sig=0x01  │
└──────────────────────────────────────────────────────────────┘
```

L'expéditeur choisit **un seul** niveau KEM par fichier : soit tous les keyslots sont ML-KEM-768, soit tous sont ML-KEM-1024.

### 5.1 WrappedDEK symétrique (48 octets)

```
WrappedDEK = AEAD_hdr( KEK[32], nonce_env(kek_nonce),
                        "arsenic-v1-wrapped-dek", DEK[32] )
           = ciphertext[32] || tag[16]
```

### 5.2 Compteurs (4 octets chacun)

`hybrid_768_count` (u32 LE) : nombre N de keyslots ML-KEM-768.  
`hybrid_1024_count` (u32 LE) : nombre M de keyslots ML-KEM-1024.  
Les deux valent 0 si aucun destinataire asymétrique.

### 5.3 Keyslot ML-KEM-768 — 1 180 octets chacun

Chaque keyslot permet à un destinataire de déchiffrer le fichier **sans connaître le mot de passe**.

```
Offset  Taille  Champ                Description
──────────────────────────────────────────────────────────────────────────────
  0      32     ephemeral_x25519     Clé publique X25519 éphémère
 32    1088     mlkem_ciphertext     Ciphertext ML-KEM-768
1120     12     kek_nonce            Nonce AEAD
1132     48     wrapped_dek          AEAD(wrapping_key, kek_nonce, aad, DEK)
──────────────────────────────────────────────────────────────────────────────
                                     Total : 1 180 octets
```

**Calcul de la clé de wrapping hybride (ML-KEM-768) :**

```
Chiffrement :
  ephemeral_x25519_sk  ← CSPRNG OS [32]
  ephemeral_x25519_pk  ← X25519PublicKey(ephemeral_x25519_sk)
  ss_x25519            ← X25519_ECDH(ephemeral_x25519_sk, recipient.x25519_pk)

  m[32]                ← CSPRNG OS [32]
  (mlkem_ct, ss_mlkem) ← ML-KEM-768.Encaps(recipient.mlkem_768_ek, m)

  wrapping_key ← BLAKE3_derive_key("Arsenic Hybrid KEM",
                   ephemeral_x25519_pk[32] || mlkem_ct[1088]
                   || ss_x25519[32] || ss_mlkem[32])

  wrapped_dek  ← AEAD_hdr(wrapping_key, kek_nonce,
                            "arsenic-v1-hybrid-wrapped-dek", DEK)

Déchiffrement :
  ss_x25519    ← X25519_ECDH(recipient_x25519_sk, ephemeral_x25519_pk)
  ss_mlkem     ← ML-KEM-768.Decaps(recipient_mlkem_768_seed, mlkem_ct)
  wrapping_key ← même BLAKE3
  DEK          ← AEAD_hdr_decrypt(wrapping_key, kek_nonce, wrapped_dek)
```

**Seeds indépendants (depuis v1.5.0) :** les seeds X25519 et ML-KEM du destinataire sont **indépendants** — générés séparément depuis le CSPRNG de l'OS. Le fichier `.key` stocke le seed X25519 (32 octets) et un seed ML-KEM séparé de 64 octets (`d[32]||z[32]`). Les anciens fichiers sans `# mlkem-seed:` dérivent le seed ML-KEM via BLAKE3 (compat).

### 5.4 Keyslot ML-KEM-1024 — 1 660 octets chacun

Même structure que §5.3 mais avec ML-KEM-1024 (niveau NIST 5, ~256 bits quantiques) et un contexte BLAKE3 distinct.

```
Offset  Taille  Champ                Description
──────────────────────────────────────────────────────────────────────────────
  0      32     ephemeral_x25519     Clé publique X25519 éphémère
 32    1568     mlkem_ciphertext     Ciphertext ML-KEM-1024
1600     12     kek_nonce            Nonce AEAD
1612     48     wrapped_dek          AEAD(wrapping_key, kek_nonce, aad, DEK)
──────────────────────────────────────────────────────────────────────────────
                                     Total : 1 660 octets
```

Contexte BLAKE3 : `"Arsenic Hybrid KEM 1024"` (au lieu de `"Arsenic Hybrid KEM"`).

### 5.5 ProtectedMetadata (taille variable)

```
MetaKey[32]    ← BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK)
MetaNonce[12]  ← BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12]

ProtectedMetadata = AEAD_hdr( MetaKey, nonce_env(MetaNonce),
                               "arsenic-v1-protected-meta", meta_tlv )
                  = ciphertext[len(meta_tlv)] || tag[16]
```

### 5.6 Région de signature (taille variable)

```
sig_present[1]       0x00 = aucune signature
                     0x01 = signature ML-DSA-65 présente

[si sig_present == 0x01] :
  verifying_key[1952]  Clé de vérification ML-DSA-65
  signature[3309]      Signature ML-DSA-65

Message signé = pre_mac[77]  (couvre paramètres KDF, IDs chiffrements, nonces)
```

La vérification est automatique et obligatoire au déchiffrement. Les clés de signature sont des fichiers `.sigkey` séparés (seed ML-DSA de 32 octets).

**Champs TLV obligatoires (50 octets) :**

| Tag    | Longueur | Valeur                                 |
|--------|----------|----------------------------------------|
| `0x02` | 32  | MerkleRoot (racine BLAKE3) |
| `0x03` | 8   | OriginalSize (u64 LE)      |
| `0x05` | 1   | BlockSizeId                |
| `0x06` | 1   | MerkleAlgoId = `0x01`      |

Tag `0x04` (CompressedSize) supprimé — toujours égal à OriginalSize (pas de compression).

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
                  + ASYM_768_COUNT(4)  + N × KEYSLOT_768_LEN(1180)
                  + ASYM_1024_COUNT(4) + M × KEYSLOT_1024_LEN(1660)
                  + len(meta_tlv) + GCM_TAG(16)
                  + SIG_PRESENT(1)
                  [+ VK_LEN(1952) + SIG_LEN(3309)  si signé]
```

| Configuration                               | Taille             |
|---------------------------------------------|--------------------|
| Minimum (0 keyslot, sans signature)         | **232 octets**     |
| 1 destinataire ML-KEM-768, sans signature   | 1 412 octets       |
| N destinataires ML-KEM-768, sans signature  | 232 + N × 1 180    |
| 1 destinataire ML-KEM-1024, sans signature  | 1 892 octets       |
| M destinataires ML-KEM-1024, sans signature | 232 + M × 1 660    |
| + signature ML-DSA-65                       | + 5 261 octets     |
| Maximum (256 keyslots)                      | ~303 Kio           |

Limite : `MAX_ASYM_KEYSLOTS = 256`, `MAX_HEADER_TOTAL_SIZE = 64 Mio`.

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
| Deoxys-II-256      | 15 oct.        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce[12])[0..15]` |
| XChaCha20-Poly1305 | 24 oct.        | `BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20",   kek_nonce[12])[0..24]` |

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
  └── Argon2id(t_cost, m_cost, p_cost, salt) → KEK[32]
        ├── BLAKE3_keyed_hash(KEK, pré_mac[77])    → HeaderMAC[32]
        └── AEAD_hdr(KEK, nonce_env(kek_nonce),
                     "arsenic-v1-wrapped-dek", DEK) → WrappedDEK[48]

CSPRNG OS → DEK[32]
  ├── BLAKE3_derive_key("Arsenic V1 Metadata Key", DEK) → MetaKey[32]
  ├── BLAKE3_derive_key("Arsenic V1 Meta Nonce",   DEK)[0..12] → MetaNonce[12]
  ├── Pour bloc i :
  │     BLAKE3_keyed_hash(DEK, i.to_le_bytes())     → block_key_i[32]
  │     BLAKE3_derive_key("Arsenic V1 Block Nonce",
  │       file_base_nonce||i.to_le_bytes())[0..24]  → block_nonce_i[24]
  ├── Pour keyslot ML-KEM-768 j :
  │     CSPRNG → eph_x25519_sk[32] → eph_x25519_pk[32]
  │     X25519_ECDH(eph_x25519_sk, recipient.x25519_pk) → ss_x25519[32]
  │     CSPRNG → m[32]
  │     ML-KEM-768.Encaps(recipient.mlkem_768_ek, m) → (mlkem_ct[1088], ss_mlkem[32])
  │     BLAKE3_derive_key("Arsenic Hybrid KEM",
  │       eph_x25519_pk||mlkem_ct||ss_x25519||ss_mlkem) → wrapping_key_j[32]
  │     AEAD_hdr(wrapping_key_j, kek_nonce_j,
  │              "arsenic-v1-hybrid-wrapped-dek", DEK) → wrapped_dek_j[48]
  └── Pour keyslot ML-KEM-1024 k :
        (identique mais ML-KEM-1024, mlkem_ct[1568],
         contexte = "Arsenic Hybrid KEM 1024")

[optionnel — si clé de signature fournie] :
  ML-DSA-65.Sign(signing_key_seed[32], pré_mac[77]) → signature[3309]
  + verifying_key[1952] annexée à l'en-tête
```

---

## 11. Diagramme complet — fichier minimal (0 keyslot, sans signature)

```
Offset     Taille  Contenu
─────────────────────────────────────────────────────────────────────────────
0x000000     4     magic              : 41 52 53 4E
0x000004     2     version            : 00 01
0x000006     1     kdf_id             : 01
0x000007     1     hdr_cipher_id      : ex. 02
0x000008     1     pld_cipher_id      : ex. 03
0x000009     4     header_total_size  : E8 00 00 00  (232, u32 LE)
0x00000D    16     salt               : [16 oct. aléatoires]
0x00001D     4     t_cost             : 04 00 00 00
0x000021     4     m_cost             : 00 00 04 00  (262 144 Kio)
0x000025     4     p_cost             : 04 00 00 00
0x000029    24     file_base_nonce    : [24 oct. aléatoires]
0x000041    12     kek_nonce          : [12 oct. aléatoires]
──────── fin section pré-MAC : 77 octets ────────────────────────────────────
0x00004D    32     HeaderMAC          : BLAKE3_keyed_hash(KEK, pré_mac[77])
──────── fin en-tête public : 109 octets ────────────────────────────────────
0x00006D    48     WrappedDEK         : AEAD_hdr(KEK, "arsenic-v1-wrapped-dek", DEK)
0x00009D     4     hybrid_768_count   : 00 00 00 00
0x0000A1     4     hybrid_1024_count  : 00 00 00 00
0x0000A5    66     ProtectedMetadata  : AEAD_hdr(MetaKey, "arsenic-v1-protected-meta", TLV[50])
0x0000E7     1     sig_present        : 00  (aucune signature)
──────── fin en-tête : 232 octets ───────────────────────────────────────────
0x0000E8     ∞     Payload (blocs consécutifs)
─────────────────────────────────────────────────────────────────────────────
```

---

## 12. Changement de mot de passe (rekey)

Les champs suivants changent ; tout le reste est préservé à l'identique :

| Champ | Modification |
|---|---|
| `salt` | Nouvelle valeur aléatoire de 16 octets |
| `kek_nonce` | Nouvelle valeur aléatoire de 12 octets |
| `HeaderMAC` | Recalculé avec le nouveau KEK = Argon2id(nouveau\_mot\_de\_passe, nouveau\_salt) |
| `WrappedDEK` | Re-chiffré sous le nouveau KEK |
| Keyslots hybrides | **Inchangés** |
| `ProtectedMetadata` | **Inchangée** |
| Blocs payload | **Inchangés** |

Comme le KEK dépend à la fois du mot de passe et du sel, et que les deux changent,
la totalité de l'en-tête public (109 octets) est réécrite avec le WrappedDEK.
Le payload n'est jamais touché quelle que soit la taille du fichier — le rekey est O(1).

**Atomicité :** l'en-tête complet actuel est écrit dans `<fichier>.bak` et
fsynced (y compris l'entrée du répertoire parent sur POSIX) avant toute écriture
en place. En cas de succès, la sauvegarde est supprimée. En cas de crash,
l'en-tête original est restauré depuis la sauvegarde à la prochaine ouverture.

---

## 13. Identités des utilisateurs

### Keypair de chiffrement (fichier `.key`)

| Composant                       | Taille       | Stockage                                     |
|---------------------------------|--------------|----------------------------------------------|
| Clé privée X25519               | 32 octets    | ligne `ARSENIC-SECRET-KEY-1{bech32}`         |
| Graine ML-KEM (`d\|\|z`)       | 64 octets    | ligne `# mlkem-seed: ARSENIC-MLKEM-SEED-1{…}` |
| Clé publique X25519             | 32 octets    | ligne `# public key: arsenic1{…}`            |
| Clé d'encapsulation ML-KEM-768  | 1 184 octets | ligne `# mlkem-public-key: arsenic1m{…}`     |
| Clé de décapsulation ML-KEM-768 | 2 400 octets | Calculée en RAM, jamais stockée              |
| Clé d'encapsulation ML-KEM-1024 | 1 568 octets | Dérivée du même seed ML-KEM 64 octets        |
| Clé de décapsulation ML-KEM-1024| 3 168 octets | Calculée en RAM, jamais stockée              |

Les seeds X25519 et ML-KEM sont **indépendants** depuis v1.5.0 (chacun généré séparément par le CSPRNG de l'OS).

### Keypair de signature (fichier `.sigkey`)

| Composant                     | Taille       | Stockage                                         |
|-------------------------------|--------------|--------------------------------------------------|
| Seed ML-DSA-65                | 32 octets    | ligne `ARSENIC-SIGN-SEED-1{bech32}`              |
| Clé de vérification ML-DSA-65 | 1 952 octets | ligne `# verifying-key: ARSENIC-SIGN-PUB-1{…}`  |
| Clé de signature ML-DSA-65    | 4 032 octets | Reconstruite depuis le seed, jamais stockée      |

---

## 14. Propriétés de sécurité

| Propriété                           | Mécanisme                                                         |
|-------------------------------------|-------------------------------------------------------------------|
| Confidentialité — DEK               | AEAD sous KEK (Argon2id) ; DEK aléatoire 32 oct.                 |
| Confidentialité — métadonnées       | AEAD sous MetaKey = f(DEK)                                        |
| Confidentialité — payload           | AEAD sous clés par-bloc dérivées de DEK + index                   |
| Intégrité par bloc                  | Tag AEAD 16 octets par bloc                                       |
| Intégrité fichier entier            | Racine Merkle BLAKE3 vérifiée avant toute écriture plaintext      |
| Ordre des blocs                     | Index lié comme AAD dans chaque AEAD de bloc                      |
| Intégrité de l'en-tête              | BLAKE3_keyed_hash(KEK, 77 octets publics)                         |
| Résistance DoS (paramètres KDF)     | Paramètres forgés rejetés par bornes avant tout Argon2id          |
| Résistance quantique — payload      | Symétrique 256 bits : Grover exige 2¹²⁸ — déjà post-quantique    |
| Résistance quantique — keyslots L3  | ML-KEM-768 (NIST niveau 3, ~180 bits quantiques) résiste à Shor  |
| Résistance quantique — keyslots L5  | ML-KEM-1024 (NIST niveau 5, ~256 bits quantiques) résiste à Shor |
| Défense en profondeur               | Hybride X25519+ML-KEM : une faille dans l'un ne compromet pas l'autre |
| Harvest-now-decrypt-later           | ML-KEM protège les fichiers chiffrés aujourd'hui                  |
| Authentification de l'expéditeur    | Signature ML-DSA-65 optionnelle sur pré_mac (NIST FIPS 204)       |
| Entropie indépendante               | Seeds X25519 et ML-KEM générés séparément depuis le CSPRNG OS     |
| Anonymat des destinataires          | Les keyslots ne révèlent pas la clé publique du destinataire      |
| Séparation des domaines Merkle      | BLAKE3_derive_key avec contextes distincts                        |
| Effacement mémoire                  | `Secret<T>` appelle `zeroize` à la destruction                    |
