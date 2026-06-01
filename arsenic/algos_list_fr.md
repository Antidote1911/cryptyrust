> [English version](algos_list.md)

# Algorithmes cryptographiques utilisés dans Arsenic

Ce document liste et explique chaque algorithme cryptographique utilisé dans la bibliothèque
`arsenic`. Les algorithmes sont regroupés par rôle fonctionnel.

---

## Table des matières

1. [Dérivation de clé depuis un mot de passe — Argon2id](#1-argon2id)
2. [MAC d'en-tête — BLAKE3_keyed_hash](#2-blake3_keyed_hash-pour-le-headermac)
3. [Fonctions de hachage et dérivation interne — BLAKE3](#3-blake3)
4. [Chiffrements authentifiés (AEAD)](#4-chiffrements-aead)
   - 4a. Deoxys-II-256
   - 4b. XChaCha20-Poly1305
   - 4c. AES-256-GCM-SIV
5. [KEM hybride post-quantique](#5-kem-hybride-post-quantique)
   - 5a. X25519 (ECDH)
   - 5b. ML-KEM-768 / ML-KEM-1024 (CRYSTALS-Kyber, NIST FIPS 203)
6. [Arbre de Merkle](#6-arbre-de-merkle)
7. [Encodage des clés — Bech32](#7-bech32)
8. [Effacement sécurisé en mémoire — Zeroize](#8-zeroize)
9. [Vue d'ensemble des rôles et interactions](#9-vue-densemble)

---

## 1. Argon2id

**Rôle :** dériver une clé cryptographique à partir d'un mot de passe humain.

**Standard :** vainqueur du Password Hashing Competition (PHC) 2015,
recommandé par NIST SP 800-63B et OWASP.

**Pourquoi Argon2id et pas bcrypt / scrypt / PBKDF2 ?**

| Propriété | Argon2id | bcrypt | scrypt | PBKDF2 |
|---|---|---|---|---|
| Résistance GPU | ✓✓ (mémoire + temps) | ✓ | ✓✓ | ✗ |
| Résistance FPGA/ASIC | ✓✓ | ✗ | ✓ | ✗ |
| Protection côté canal | ✓ (hybride d | ✗ | ✗ | ✗ |
| Configurabilité | mémoire, temps, parallélisme | temps seulement | mémoire + temps | temps seulement |

Argon2id combine Argon2d (résistant aux attaques par canal latéral GPU) et
Argon2i (résistant aux compromis temps-mémoire). La variante `id` est la
meilleure par défaut.

**Usage unique dans Arsenic — dérivation du KEK :**

Génère le KEK (Key Encryption Key) qui protège le DEK et chiffre le HeaderMAC.
Chaque tentative de mot de passe paie le coût KDF complet ; il n'existe aucun
oracle de pré-authentification moins coûteux.

| Preset | `t_cost` | `m_cost` | `p_cost` | RAM | Temps typique |
|---|---|---|---|---|---|
| **Interactive** *(défaut)* | 4 | 262 144 Ko | 4 | 256 Mio | ~1–3 s |
| **Sensitive** | 12 | 1 048 576 Ko | 4 | 1 Gio | ~10–30 s |

Les paramètres sont stockés en clair dans l'en-tête du fichier, ce qui
permet de déchiffrer sans configuration externe. Ils sont intégrés au
`HeaderMAC` et ne peuvent donc pas être modifiés silencieusement.

**Résistance post-quantique :** Argon2id est une fonction à sens unique
classique. L'algorithme de Grover réduit la sécurité d'une clé symétrique
de 256 bits à 128 bits effectifs — Argon2id avec une sortie de 32 octets
(256 bits) reste donc sécurisé face aux ordinateurs quantiques.

---

## 2. BLAKE3_keyed_hash pour le HeaderMAC

**Rôle :** authentifier l'en-tête public du fichier (`HeaderMAC`).

BLAKE3 est déjà utilisé pour toutes les dérivations internes (clés de bloc, nonces, arbre de Merkle).
Le HeaderMAC l'adopte par cohérence, ce qui supprime les crates `sha2` et `hmac` en totalité.

**Construction :**

```
KEK = Argon2id(password, salt, t_cost, m_cost, p_cost) → 32 octets

HeaderMAC = BLAKE3_keyed_hash(
    clé    = KEK[32],
    données = pré_mac[77 octets]   ← tout l'en-tête public sauf le MAC lui-même
)
```

La comparaison `blake3::Hash::eq` est documentée comme à temps constant.

**Ce que le MAC protège :**
- Magic bytes et version du format
- Identifiants des chiffrements (header et payload)
- `header_total_size`
- Sel Argon2id et paramètres KDF (`t`, `m`, `p`)
- `file_base_nonce` et `kek_nonce`

**Propriété de sécurité :** la clé du HeaderMAC est le KEK complet dérivé avec
les paramètres Argon2id configurés (Interactive : 256 Mio / Sensitive : 1 Gio).
Un attaquant hors-ligne doit payer le coût KDF complet par tentative de mot de
passe — il n'existe aucun oracle plus rapide. Un mauvais mot de passe produit
un KEK incorrect dont le MAC ne correspond pas, avant toute tentative de
déchiffrement AEAD.

**Protection DoS contre les paramètres forgés :** avant de lancer Argon2id,
l'implémentation valide que les paramètres KDF déclarés sont dans des bornes
sûres (`t_cost ≤ 64`, `m_cost ≤ 4 Gio`, `p_cost ≤ 16`). Un fichier falsifié
avec des paramètres absurdes (ex. t=1000, m=10 Gio) est rejeté immédiatement
sans invoquer Argon2id.

**Résistance post-quantique :** BLAKE3 est symétrique avec une sortie de 256 bits ;
Grover réduit la sécurité à 128 bits effectifs — suffisant.

---

## 3. BLAKE3

**Rôle :** dérivation interne de sous-clés, de nonces, et calcul de l'arbre
de Merkle.

**Standard :** BLAKE3 (2020), successeur de BLAKE2. Implémenté via la crate
Rust `blake3`.

**Deux interfaces utilisées :**

### 3a. `blake3::keyed_hash(key, data) → [u8; 32]`

Hash BLAKE3 avec clé de 32 octets. Utilisé pour la dérivation des clés de
bloc :

```
block_key_i = blake3::keyed_hash(DEK, i.to_le_bytes())
```

La clé (`DEK`) garantit que les sorties sont pseudo-aléatoires même si
l'entrée (`i`) est prévisible. Chaque bloc `i` obtient une clé unique et
indépendante.

### 3b. `blake3::derive_key(context_string, material) → [u8; 32]`

Dérivation de clé à contexte fixe (KDF). Le contexte est une chaîne de
caractères ASCII unique qui sépare les domaines cryptographiques,
empêchant la réutilisation d'une sortie dans un rôle différent.

Utilisations dans Arsenic :

| Chaîne de contexte | Entrée | Sortie |
|---|---|---|
| `"Arsenic V1 Block Nonce"` | `file_base_nonce \|\| i.to_le_bytes()` | `block_nonce_i[24]` |
| `"Arsenic V1 Metadata Key"` | `DEK[32]` | `MetaKey[32]` |
| `"Arsenic V1 Meta Nonce"` | `DEK[32]` | `MetaNonce[12]` |
| `"Arsenic V1 Merkle Leaf v1"` | bloc chiffré | `leaf_i[32]` |
| `"Arsenic V1 Merkle Node v1"` | `left[32] \|\| right[32]` | `node[32]` |
| `"Arsenic V1 KEK Nonce XChaCha20"` | `kek_nonce[12] \|\| 0×20` | nonce étendu [24] |
| `"Arsenic V1 KEK Nonce DeoxysII256"` | `kek_nonce[12] \|\| 0×20` | nonce étendu [15] |
| `"Arsenic V2 X25519 Wrapping Key"` | `shared_secret_x25519[32]` | `wrapping_key[32]` |
| `"Arsenic Hybrid KEM"` | voir §5 | `wrapping_key[32]` |
| `"Arsenic ML-KEM d"` | `x25519_sk[32]` | `d[32]` (graine ML-KEM) |
| `"Arsenic ML-KEM z"` | `x25519_sk[32]` | `z[32]` (graine ML-KEM) |

**Pourquoi BLAKE3 plutôt que HKDF-SHA256 ou SHA3-KDF ?**
- Vitesse : BLAKE3 est ~3–5× plus rapide que SHA-256 sur les CPU modernes,
  grâce au parallélisme interne et à des optimisations SIMD (AVX2, NEON)
- Sécurité prouvée : construit sur une structure basée sur des permutations
  (Chacha-like), différente de la famille Merkle-Damgård
- API de dérivation native : `derive_key` intègre directement la séparation
  de domaines sans boilerplate HKDF

**Résistance post-quantique :** BLAKE3 est une fonction de hachage
symétrique. Grover réduit la sécurité de 256 bits à 128 bits effectifs —
suffisant pour une résistance post-quantique à long terme.

---

## 4. Chiffrements AEAD

Tous les chiffrements AEAD utilisés produisent un **tag d'authentification
de 16 octets** (`GCM_TAG = 16`). L'utilisateur peut choisir indépendamment
le chiffrement pour l'en-tête (clés, métadonnées) et pour le payload (blocs
de données).

### 4a. Deoxys-II-256

**Standard :** soumission au concours CAESAR 2013–2019, finaliste dans la
catégorie "usage défensif". Basé sur les permutations AES en mode tweakable
block cipher (TBC).

**Caractéristiques :**

| Propriété | Valeur |
|---|---|
| Type | Tweakable block cipher AEAD (TBAR) |
| Taille de clé | 256 bits |
| Nonce natif | 120 bits (15 octets) |
| Tag | 128 bits (16 octets) |
| Sécurité | ≥ 128 bits classique |
| Accélération matérielle | Oui (AES-NI) |

**Rôle par défaut :** chiffrement de l'en-tête (WrappedDEK, ProtectedMetadata,
keyslots hybrides).

**Pourquoi Deoxys-II-256 pour l'en-tête ?**
- Le mode TBC offre une sécurité "beyond-birthday-bound" : la sécurité est
  maintenue même après 2⁹⁶ appels (contrairement à AES-GCM classique qui se
  dégrade à 2⁶⁴ blocs)
- Basé sur AES, accéléré par AES-NI sur x86/ARM
- Résistant aux attaques par nonce réutilisé pour les keyslots (qui utilisent
  des nonces générés aléatoirement)

**Gestion du nonce pour l'enveloppe :**
Le `kek_nonce` de 12 octets stocké dans l'en-tête est étendu à 15 octets par
`BLAKE3_derive_key("Arsenic V1 KEK Nonce DeoxysII256", kek_nonce || 0×20)`.

Pour les blocs payload, le `block_nonce_i` de 24 octets est tronqué à 15 :
`block_nonce_i[0..15]`.

---

### 4b. XChaCha20-Poly1305

**Standard :** RFC 8439 (ChaCha20-Poly1305), extension XChaCha20 avec nonce
de 192 bits (draft IETF).

**Caractéristiques :**

| Propriété | Valeur |
|---|---|
| Type | Stream cipher + MAC (ARX) |
| Taille de clé | 256 bits |
| Nonce natif | 192 bits (24 octets) |
| Tag | 128 bits (16 octets) |
| Sécurité | ≥ 128 bits classique |
| Accélération matérielle | Non (mais rapide en pur logiciel) |

**Rôle par défaut :** chiffrement du payload (blocs de données).

**Pourquoi XChaCha20 pour le payload ?**
- L'extension "X" porte le nonce de 96 à 192 bits, éliminant pratiquement
  tout risque de collision de nonce sur des fichiers volumineux traités en
  parallèle
- Implémentation pure logiciel très rapide sur les CPU sans AES-NI
  (embarqué, mobile)
- Basé sur ChaCha20, construit sur des opérations ARX (Addition, Rotation,
  XOR) — différent structurellement d'AES, offrant une diversité
  algorithmique
- Poly1305 est un MAC à clé éphémère : même si un nonce est réutilisé, seul
  le bit d'authenticité est compromis, pas la confidentialité

**Gestion du nonce pour l'enveloppe :**
Le `kek_nonce` de 12 octets est étendu à 24 par
`BLAKE3_derive_key("Arsenic V1 KEK Nonce XChaCha20", kek_nonce || 0×20)`.

Pour les blocs, `block_nonce_i[0..24]` est utilisé directement (24 octets).

---

### 4c. AES-256-GCM-SIV

**Standard :** RFC 8452, conçu par Google et Shay Gueron.

**Caractéristiques :**

| Propriété | Valeur |
|---|---|
| Type | Synthetic IV AEAD (SIV) |
| Taille de clé | 256 bits |
| Nonce natif | 96 bits (12 octets) |
| Tag | 128 bits (16 octets) |
| Sécurité | ≥ 128 bits classique |
| Résistance nonce-misuse | Oui |
| Accélération matérielle | Oui (AES-NI + CLMUL) |

**Particularité :** AES-GCM-SIV est **résistant au mésusage de nonce**. Si
le même nonce est utilisé deux fois avec la même clé, la confidentialité
est préservée (seule l'authenticité peut être compromise). Standard AES-GCM
se brise catastrophiquement en cas de réutilisation de nonce.

**Gestion du nonce :**
Le `kek_nonce` de 12 octets est utilisé directement pour les keyslots et
métadonnées. Pour les blocs, `block_nonce_i[0..12]` est utilisé.

---

## 5. KEM hybride post-quantique

Le chiffrement asymétrique dans Arsenic utilise un **KEM hybride** combinant
X25519 (classique) et ML-KEM-768 ou ML-KEM-1024 (post-quantique). L'hybridation garantit
que la sécurité est maintenue tant qu'**au moins un** des deux composants
n'est pas compromis.

Deux niveaux de sécurité sont disponibles par fichier :

| Niveau | Variante ML-KEM | Niveau NIST | Sécurité quantique |
|---|---|---|---|
| **L768** *(défaut)* | ML-KEM-768 | 3 | ~180 bits |
| **L1024** | ML-KEM-1024 | 5 | ~256 bits |

### 5a. X25519 (ECDH)

**Standard :** RFC 7748, basé sur la courbe Curve25519 de Daniel J. Bernstein.

**Caractéristiques :**

| Propriété | Valeur |
|---|---|
| Type | Échange de clés Diffie-Hellman sur courbe elliptique |
| Courbe | Curve25519 (Montgomery) |
| Taille de clé | 32 octets (privée et publique) |
| Shared secret | 32 octets |
| Sécurité classique | ~128 bits (courbe 255 bits) |
| Sécurité post-quantique | ✗ (Shor casse ECDH en O(n³)) |

**Usage dans Arsenic :**
Chaque keyslot génère une paire X25519 **éphémère** à usage unique :

```
eph_sk ← random[32]
eph_pk ← X25519(eph_sk, G)   (multiplication scalaire sur Curve25519)
ss_x25519 ← X25519(eph_sk, recipient_pk_x25519)
```

La clé éphémère garantit la **forward secrecy** : même si la clé privée
du destinataire est compromise ultérieurement, les messages passés restent
confidentiels car `eph_sk` n'est jamais stocké.

**Pourquoi Curve25519 ?**
- Résistante aux attaques par canal latéral par construction (arithmétique
  à temps constant sur les implémentations correctes)
- Pas de paramètres potentiellement backdoorés (contrairement aux courbes
  NIST P-256/P-384 dont les constantes sont d'origine obscure)
- Largement adoptée (SSH, TLS 1.3, Signal, WireGuard)

---

### 5b. ML-KEM-768 (CRYSTALS-Kyber)

**Standard :** NIST FIPS 203 (août 2024) — premier algorithme KEM
post-quantique standardisé par le NIST.

**Caractéristiques :**

| Propriété | Valeur |
|---|---|
| Type | Key Encapsulation Mechanism (KEM) sur réseaux modulaires |
| Niveau de sécurité | NIST niveau 3 (≈ AES-192) |
| Clé d'encapsulation (publique) | 1 184 octets |
| Clé de décapsulation (secrète) | 2 400 octets (graine : 64 octets) |
| Ciphertext | 1 088 octets |
| Shared secret | 32 octets |
| Hypothèse de sécurité | Module-LWE (Module Learning With Errors) |
| Sécurité post-quantique | ✓ (Shor ne s'applique pas aux réseaux) |

**Différence avec X25519 — API KEM vs. Key Agreement :**

```
X25519 (ECDH) :
  Alice : (eph_sk, eph_pk) ← KeyGen()
  Alice → Bob : eph_pk
  Bob   : ss ← ECDH(bob_sk, eph_pk)
  Alice : ss ← ECDH(eph_sk, bob_pk)
  → ss identique des deux côtés

ML-KEM-768 (KEM) :
  Bob possède : (dk, ek) ← KeyGen()
  Alice : (ct, ss) ← Encaps(ek)   ← seul Alice connaît ss avant envoi
  Alice → Bob : ct
  Bob   : ss ← Decaps(dk, ct)
  → ss identique des deux côtés
```

**Seeds indépendants (depuis v1.5.0) :**

La graine ML-KEM est générée indépendamment de la clé privée X25519 —
chacune est produite séparément par le CSPRNG de l'OS. Le fichier `.key` stocke les deux :

```
x25519_sk[32]   ← CSPRNG OS  (encodé en ARSENIC-SECRET-KEY-1…)
mlkem_seed[64]  ← CSPRNG OS  (encodé en ARSENIC-MLKEM-SEED-1…, d[32]||z[32])

(dk_mlkem_768, ek_mlkem_768)   ← ML-KEM-768.KeyGen_internal(mlkem_seed)
(dk_mlkem_1024, ek_mlkem_1024) ← ML-KEM-1024.KeyGen_internal(mlkem_seed)
```

Les deux niveaux ML-KEM partagent le même seed 64 octets. Ce seed est indépendant
du seed X25519 — une faiblesse dans l'un ne peut pas se propager à l'autre.

Les anciens fichiers `.key` (sans `# mlkem-seed:`) dérivent le seed ML-KEM
depuis X25519 via BLAKE3 pour la compatibilité.

**Encapsulation déterministe :**
`m ← CSPRNG OS [32]` est fourni par l'appelant ; Arsenic utilise
`encapsulate_deterministic(m)` en interne.

---

### Construction hybride et binding

La clé de wrapping du keyslot combine les deux shared secrets pour éviter
toute attaque par substitution ou isolation d'un composant :

```
wrapping_key = BLAKE3_derive_key(
    "Arsenic Hybrid KEM",
    eph_x25519_pk[32]     ← public, lie la clé éphémère X25519
    || mlkem_ct[1088]     ← public, lie le ciphertext ML-KEM
    || ss_x25519[32]      ← secret X25519
    || ss_mlkem[32]       ← secret ML-KEM
)
```

Cette construction garantit :
1. **Bind-and-commit** : `wrapping_key` est cryptographiquement lié à
   tous les éléments publics ET secrets, rendant impossible toute
   attaque "key commitment"
2. **Domaine séparé** : la chaîne `"Arsenic Hybrid KEM"` empêche toute
   réutilisation de cette sortie pour un autre usage
3. **Défense en profondeur** : si X25519 est cassé (ordinateur quantique),
   ML-KEM maintient la sécurité. Si ML-KEM est vulnérable (faille
   algorithmique), X25519 maintient la sécurité classique

---

## 6. Arbre de Merkle

**Rôle :** vérifier l'intégrité de l'intégralité du fichier chiffré **avant**
d'écrire le moindre octet de plaintext.

**Construction :** arbre binaire BLAKE3, domaine-séparé, calculé sur les
**blocs chiffrés** (pas sur le plaintext).

```
leaf_i  = BLAKE3_derive_key("Arsenic V1 Merkle Leaf v1",  bloc_chiffré_i)
node(g, d) = BLAKE3_derive_key("Arsenic V1 Merkle Node v1", g[32] || d[32])
```

Les nœuds sont calculés de bas en haut par paires successives. Si le nombre
de nœuds est impair, le dernier est promu tel quel (sans duplication). La
racine est stockée dans la `ProtectedMetadata` chiffrée (tag TLV `0x02`).

**Pourquoi BLAKE3 et pas SHA-256 pour Merkle ?**
- BLAKE3 est ~5× plus rapide que SHA-256 pour les hachages de blocs
- `derive_key` avec des contextes distincts pour feuilles et nœuds
  élimine les **attaques de second préimage par confusion** (une feuille
  ne peut pas être confondue avec un nœud interne)
- Un arbre SHA-256 naïf sans séparation de domaines est vulnérable à ce
  type d'attaque

**Propriétés de sécurité :**
- Authentifie chaque bloc **et** leur ordre (l'index est lié comme AAD dans
  chaque AEAD de bloc)
- Empêche la troncature silencieuse (le nombre de blocs est implicite dans
  la racine)
- Calculé sur le texte chiffré → vérification sans déchiffrement en passe 1

---

## 7. Bech32

**Rôle :** encodage lisible par l'humain des clés publiques et privées.

**Standard :** adapté de BIP-0173 (Bitcoin), utilisant l'alphabet
`qpzry9x8gf2tvdw0s3jn54khce6mua7l` (32 caractères, 5 bits/char).

Arsenic utilise Bech32 **sans checksum** (les clés sont vérifiées
cryptographiquement lors de l'usage, pas à l'encodage).

| Type | Préfixe | Longueur | Exemple |
|---|---|---|---|
| Clé publique X25519 | `arsenic1` | 60 chars | `arsenic1ql3z7hjy…` |
| Clé privée | `ARSENIC-SECRET-KEY-1` | 72 chars | `ARSENIC-SECRET-KEY-1GQ9…` |
| Clé d'encapsulation ML-KEM-768 | `arsenic1m` | ~1 955 chars | `arsenic1mq…` |

**Calcul :**
32 octets × 8 bits = 256 bits → ⌈256/5⌉ = 52 caractères bech32 + préfixe.
Pour ML-KEM : 1 184 octets × 8 bits = 9 472 bits → 1 946 caractères.

**Pourquoi Bech32 plutôt que Base64/Hex ?**
- L'alphabet évite les caractères ambigus (O/0, I/l/1)
- Entièrement en minuscules pour X25519 (facile à copier sans erreur de casse)
- La convention MAJUSCULES pour la clé privée signale visuellement le danger

---

## 8. Zeroize

**Rôle :** effacer de façon sécurisée les valeurs sensibles en mémoire
quand elles ne sont plus nécessaires.

**Standard :** crate Rust `zeroize`, conforme aux recommandations de
sécurité mémoire (CERT C, MISRA, NIST).

**Problème résolu :** le compilateur C/Rust peut optimiser et supprimer
`memset(secret, 0, len)` s'il détecte que la mémoire n'est plus utilisée
après. `Zeroize` utilise des barrières mémoire et des écritures volatiles
pour garantir l'effacement effectif.

**Usage dans Arsenic :**
Le type `Secret<T>` est un wrapper autour de toute valeur sensible :

```rust
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();  // efface à zéro à la destruction
    }
}
```

Valeurs concernées :
- Mot de passe (`Secret<String>`)
- DEK — Data Encryption Key (`[u8; 32]` + `zeroize()` explicite)
- KEK — Key Encryption Key (`Secret<[u8; 32]>`)
- `dek_vec` intermédiaire lors du déchiffrement de l'enveloppe
- Vecteurs de clés privées dans les fonctions de dérivation

**Remarque :** la clé de décapsulation ML-KEM (2 400 octets) est calculée
en RAM à la demande et jamais stockée en dehors de la pile de la fonction
qui la crée. La crate `ml-kem` utilise la feature `zeroize` pour effacer
automatiquement les structures internes.

---

## 9. Vue d'ensemble

```
Mot de passe ──► Argon2id ──► KEK[32] ──► AEAD ──► WrappedDEK[48]
                                                          │
                  ┌───────────────────────────────────────┘
                  ▼
               DEK[32] (aléatoire par fichier)
                  │
                  ├──► BLAKE3_keyed_hash ──► block_key_i[32] ──► AEAD ──► bloc chiffré_i
                  ├──► BLAKE3_derive_key ──► block_nonce_i[24]
                  ├──► BLAKE3_derive_key ──► MetaKey/MetaNonce ──► AEAD ──► ProtectedMetadata
                  │
                  └──► (pour chaque destinataire)
                         X25519_ECDH ──┐
                         ML-KEM-768   ─┼──► BLAKE3 "Arsenic Hybrid KEM"      ──► wrapping_key → AEAD → wrapped_dek
                         ou ML-KEM-1024┘──► BLAKE3 "Arsenic Hybrid KEM 1024" ──► wrapping_key → AEAD → wrapped_dek

┌──────────────────────────────────────────────────────────┐
│ BLAKE3 Merkle tree  (sur tous les blocs chiffrés)         │
│   leaf_i = BLAKE3_derive_key("…Leaf…", bloc_chiffré_i)   │
│   root   → stockée dans ProtectedMetadata (déchiffrée)   │
│   Vérification complète avant toute écriture plaintext   │
└──────────────────────────────────────────────────────────┘

En-tête protégé par : BLAKE3_keyed_hash(KEK, en-tête_public[77 octets])
```

### Résumé de la résistance post-quantique

| Composant | Algorithme | PQ-safe ? | Raison |
|---|---|---|---|
| Chiffrement payload | XChaCha20 / Deoxys-II / AES-GCM-SIV | ✓ | Symétrique 256 bits, Grover → 128 bits |
| KDF mot de passe | Argon2id | ✓ | Symétrique, Grover → 128 bits |
| Header MAC | BLAKE3_keyed_hash | ✓ | Symétrique, Grover → 128 bits |
| Dérivation interne | BLAKE3 | ✓ | Symétrique |
| Keyslot X25519 | X25519 | ✗ | Shor casse ECDH |
| Keyslot ML-KEM-768 | ML-KEM-768 (NIST niveau 3) | ✓ | FIPS 203, ~180 bits quantiques |
| Keyslot ML-KEM-1024 | ML-KEM-1024 (NIST niveau 5) | ✓ | FIPS 203, ~256 bits quantiques |
| **Keyslot hybride** | **X25519 + ML-KEM-768/1024** | **✓** | Sécurisé si l'un des deux tient |
| Signature ML-DSA-65 | ML-DSA-65 (NIST FIPS 204) | ✓ | ~192 bits quantiques, auth expéditeur |

Le seul composant classiquement vulnérable est X25519, et il est **toujours
accompagné de ML-KEM** dans le keyslot hybride. Si un ordinateur
quantique suffisamment puissant venait à exister, il casserait X25519 mais
pas ML-KEM, laissant le DEK (et donc les données) protégé.
