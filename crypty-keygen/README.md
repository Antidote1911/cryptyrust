# crypty-keygen

Générateur de paires de clés hybrides **X25519 + ML-KEM-768** pour Arsenic V1.

Chaque paire de clés est entièrement dérivée d'une graine de 32 octets stockée dans un fichier `.key`. La clé ML-KEM-768 (1 184 octets) est calculée à la demande — le fichier `.key` reste compact.

---

## Installation

```bash
cargo build --release -p crypty-keygen
# → target/release/crypty-keygen
```

---

## Utilisation

### Générer et afficher (stdout)

```bash
crypty-keygen -n alice
```

Sortie :
```
# created: 2025-06-01T10:30:00Z
# name: alice
# public key: arsenic1ql3z7hjy…  (X25519, 60 chars)
# mlkem-public-key: arsenic1m…  (ML-KEM-768, ~1950 chars)
ARSENIC-SECRET-KEY-1GQ9778VQ…   (clé privée, 72 chars)
```

La clé publique est toujours affichée sur **stderr** (compatible avec la redirection stdout).

### Sauvegarder dans le keystore partagé

```bash
crypty-keygen -n alice --store
# Identity written to: /home/user/.config/cryptyrust/keys/alice.key
# Public key: arsenic1ql3z7hjy…
```

La clé est immédiatement disponible dans la GUI et le CLI.

### Sauvegarder dans un fichier spécifique

```bash
crypty-keygen -n alice -o alice.key
```

### Lister les clés du keystore

```bash
crypty-keygen --list
```

```
Name                 Public key
────────────────────────────────────────────────────────────────────────────────
alice                arsenic1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
bob                  arsenic1lggyhqrw…
```

### Extraire la clé publique d'un fichier .key existant

```bash
crypty-keygen -y alice.key
```

---

## Options complètes

```
  -n, --name <NOM>         Nom à intégrer dans le fichier de clé
      --store              Sauvegarder dans le keystore partagé
                           ({config}/cryptyrust/keys/). Requiert --name.
  -o, --output <FICHIER>   Écrire dans FICHIER (permissions 0600 sur Unix)
  -l, --list               Lister les clés du keystore et quitter
  -y, --to-public <FICHIER> Afficher la clé publique X25519 d'un fichier .key
```

---

## Format du fichier .key

```
# created: 2025-06-01T10:30:00Z
# name: alice
# public key: arsenic1{52 chars bech32}
# mlkem-public-key: arsenic1m{~1946 chars bech32}
ARSENIC-SECRET-KEY-1{52 chars BECH32}
```

| Encodage | Préfixe | Longueur | Description |
|---|---|---|---|
| `arsenic1…` | `arsenic1` | 60 chars | Clé publique X25519 |
| `arsenic1m…` | `arsenic1m` | ~1 955 chars | Clé d'encapsulation ML-KEM-768 |
| `ARSENIC-SECRET-KEY-1…` | `ARSENIC-SECRET-KEY-1` | 72 chars | Clé privée (graine 32 octets) |

La ligne `# mlkem-public-key:` est présente pour l'inspection humaine mais n'est pas lue au chargement — la clé ML-KEM est toujours re-dérivée de la clé privée.

---

## Keystore partagé

| Plateforme | Chemin |
|---|---|
| Linux | `~/.config/cryptyrust/keys/` |
| macOS | `~/Library/Application Support/cryptyrust/keys/` |
| Windows | `%APPDATA%\cryptyrust\keys\` |

Les fichiers `.key` sont créés avec les permissions **0600** (Unix) pour protéger la clé privée.
