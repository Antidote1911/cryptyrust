# arsenic_ffi

Couche FFI compatible C pour la bibliothèque `arsenic`. Expose toutes les opérations de chiffrement, gestion de clés et benchmark via une interface C stable.

Sorties : `libarsenic_ffi.so` (Linux), `libarsenic_ffi.dylib` (macOS), `arsenic_ffi.dll` (Windows), et l'archive statique `.a` / `.lib`.

---

## Compilation

```bash
cargo build --release -p arsenic_ffi
# → target/release/libarsenic_ffi.so  (Linux)
# → target/release/libarsenic_ffi.a
```

### Générer l'en-tête C

```bash
cargo install cbindgen
cbindgen --config ffi/cbindgen.toml --crate arsenic_ffi --output arsenic.h
```

---

## API — Vue d'ensemble

### Codes de retour

| Code | Valeur | Description |
|---|---|---|
| `ARSENIC_OK` | 0 | Succès |
| `ARSENIC_ERR_DECRYPT` | -1 | Mot de passe incorrect ou données corrompues |
| `ARSENIC_ERR_IO` | -2 | Erreur E/S |
| `ARSENIC_ERR_PARAMS` | -3 | Paramètre invalide |
| `ARSENIC_ERR_BAD_MAGIC` | -4 | Pas un fichier Arsenic valide |
| `ARSENIC_ERR_NULL_PTR` | -5 | Pointeur null inattendu |
| `ARSENIC_ERR_CANCELLED` | -6 | Opération annulée |
| `ARSENIC_ERR_NO_ASYM_KEY` | -7 | Aucun keyslot ne correspond à la clé fournie |

En cas d'erreur, `arsenic_last_error()` retourne un message descriptif.

### Types principaux

```c
// Paramètres de chiffrement
typedef struct { uint8_t hdr_cipher; uint8_t pld_cipher; uint8_t strength; } ArsParams;

// Buffer mémoire (à libérer avec arsenic_free_buffer)
typedef struct { uint8_t *ptr; size_t len; } ArsBuffer;

// Tableau de clés publiques éphémères (à libérer avec arsenic_free_pubkey_array)
typedef struct { uint8_t *data; size_t count; } ArsPubKeyArray;  // count × 32 bytes

// Résultats de benchmark (à libérer avec arsenic_free_bench_array)
typedef struct { uint8_t cipher_id; double encrypt_mibps; double decrypt_mibps; } ArsBenchResult;
typedef struct { ArsBenchResult *results; size_t count; } ArsBenchArray;
```

### Recipients hybrides

Chaque destinataire est représenté par **1 216 octets** : `x25519_pk[32] || mlkem_ek[1184]`.

Générer la clé publique hybride depuis une clé privée :
```c
uint8_t priv[32];  // clé privée 32 octets
uint8_t hybrid_pub[1216];
arsenic_hybrid_pubkey(priv, hybrid_pub);
```

### Chiffrement / Déchiffrement mémoire

```c
ArsBuffer ct = {0};
ArsParams p = arsenic_default_params();
// recipients: tableau plat de n × 1216 octets
int rc = arsenic_encrypt(plain, plain_len, "password", &p,
                          recipients, n_recipients, NULL, NULL, &ct);
arsenic_free_buffer(&ct);

ArsBuffer pt = {0};
rc = arsenic_decrypt(ct.ptr, ct.len, "password", NULL, NULL, &pt);
arsenic_free_buffer(&pt);

// Déchiffrement asymétrique
rc = arsenic_decrypt_with_key(ct.ptr, ct.len, priv_key_32, NULL, NULL, &pt);
```

### Chiffrement / Déchiffrement de fichiers

```c
rc = arsenic_encrypt_file("in.txt", "in.txt.arsn", "password", &p,
                           recipients, n_recipients, NULL, NULL);
rc = arsenic_decrypt_file("in.txt.arsn", "out.txt", "password", NULL, NULL);
rc = arsenic_decrypt_file_with_key("in.txt.arsn", "out.txt", priv_key_32, NULL, NULL);
```

### Gestion des keyslots

```c
// Ajouter un destinataire hybride (1216 octets)
rc = arsenic_add_recipient_file("file.arsn", "password", hybrid_pub_1216, NULL, NULL);

// Supprimer par index
rc = arsenic_remove_recipient_file("file.arsn", "password", 0, NULL, NULL);

// Lister les clés éphémères
ArsPubKeyArray arr = arsenic_list_recipients_file("file.arsn");
// arr.count keyslots, arr.data = count × 32 bytes
arsenic_free_pubkey_array(&arr);

// Trouver quelle clé privée déchiffre un fichier
// privkeys: tableau plat de n × 32 octets
int idx = arsenic_find_matching_key_file("file.arsn", privkeys, n_keys);
// returns 0-based index or -1
```

### Utilitaires de clés

```c
// Générer un keypair X25519
uint8_t priv[32], pub[32];
arsenic_generate_keypair(priv, pub);

// Dériver la clé publique hybride complète (1216 octets) depuis une clé privée
uint8_t hybrid[1216];
arsenic_hybrid_pubkey(priv, hybrid);

// Encodage bech32
char buf[128];
arsenic_encode_pubkey(pub, buf, sizeof(buf));      // arsenic1...  (60 chars)
arsenic_encode_privkey(priv, buf, sizeof(buf));    // ARSENIC-SECRET-KEY-1...  (72 chars)

// Décodage
uint8_t decoded[32];
int ok = arsenic_decode_pubkey("arsenic1...", decoded);
```

### Benchmark

```c
ArsBenchArray arr = arsenic_bench(32);  // 32 MiB, trié fastest-first
uint8_t best_hdr, best_pld;
arsenic_bench_best_combo(&arr, &best_hdr, &best_pld);
arsenic_free_bench_array(arr);
```

---

## Sécurité de la mémoire

Toutes les fonctions renvoyant un `ArsBuffer` ou un `ArsPubKeyArray` transfèrent la propriété au code appelant. Ces buffers **doivent** être libérés avec `arsenic_free_buffer` / `arsenic_free_pubkey_array` exactement une fois.

Le dernier message d'erreur est stocké dans un `thread_local` — il est valide jusqu'au prochain appel `arsenic_*` sur ce thread.

---

## Tests

```bash
cargo test -p arsenic_ffi
# 21 tests couvrant : round-trips mémoire et fichier symétriques/asymétriques,
# rekey, add/list/remove recipients, find_matching_key, encode/decode clés, benchmark
```
