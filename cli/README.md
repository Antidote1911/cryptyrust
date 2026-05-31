# cryptyrust_cli

Interface ligne de commande pour le chiffrement de fichiers **Arsenic V1** (`.arsn`).

---

## Installation

```bash
cargo build --release -p cryptyrust_cli
# → target/release/cryptyrust_cli
```

---

## Utilisation

### Chiffrement symétrique

```bash
# Mot de passe en ligne de commande (déconseillé — visible dans l'historique shell)
cryptyrust_cli -e fichier.txt -p "ma phrase secrète"

# Mot de passe dans un fichier (UTF-8, sans newline)
cryptyrust_cli -e fichier.txt -f /chemin/vers/motdepasse.txt

# Prompt interactif (recommandé)
cryptyrust_cli -e fichier.txt
```

### Chiffrement asymétrique (destinataires hybrides)

```bash
# Pour un contact par nom (cherché dans ~/.config/cryptyrust/contacts)
cryptyrust_cli -e fichier.txt -R alice

# Pour plusieurs destinataires
cryptyrust_cli -e fichier.txt -R alice -R bob

# Clé publique brute (X25519, arsenic1...) — nécessite aussi la clé ML-KEM
# Pour un fichier de clé .key
cryptyrust_cli -e fichier.txt -R /chemin/vers/alice.key

# Sans mot de passe (destinataires uniquement)
cryptyrust_cli -e fichier.txt -R alice
```

### Déchiffrement

```bash
# Auto-détection des clés stockées, puis demande le mot de passe si nécessaire
cryptyrust_cli -d fichier.txt.arsn

# Avec un fichier de clé spécifique
cryptyrust_cli -d fichier.txt.arsn -i ~/.config/cryptyrust/keys/alice.key

# Avec un mot de passe
cryptyrust_cli -d fichier.txt.arsn -p "ma phrase secrète"
```

Le déchiffrement **essaie automatiquement** toutes les clés du keystore partagé (`~/.config/cryptyrust/keys/`). Si une clé correspond, le fichier est déchiffré sans demander de mot de passe — comportement identique à la GUI.

### Changement de mot de passe

```bash
# Modifie uniquement le keyslot (48 octets) — le payload n'est pas re-chiffré
cryptyrust_cli --rekey fichier.txt.arsn
```

### Benchmark

```bash
cryptyrust_cli --bench
```

---

## Options complètes

```
MODES (un obligatoire) :
  -e, --encrypt <FILE>         Chiffrer FILE
  -d, --decrypt <FILE>         Déchiffrer FILE
  -k, --rekey   <FILE>         Changer le mot de passe d'un .arsn
      --bench                  Benchmarker les chiffrements AEAD

CHIFFREMENT :
  -R, --recipient <SPEC>       Destinataire hybride (répétable). SPEC peut être :
                                 • Un nom de contact stocké dans le keystore
                                 • Un chemin vers un fichier .key
  -p, --password <MOT_DE_PASSE>
  -f, --passwordfile <FICHIER>
  -o, --output <CHEMIN>
      --strength <FORCE>       interactive (défaut) | sensitive
      --hdr-cipher <CHIFFREMENT> deoxys-ii (défaut) | xchacha20 | aes-gcm-siv
      --pld-cipher <CHIFFREMENT> xchacha20 (défaut) | deoxys-ii | aes-gcm-siv

DÉCHIFFREMENT :
  -i, --identity <FICHIER_CLÉ> Fichier .key à utiliser (répétable).
                                Si absent, toutes les clés du keystore sont essayées.
```

---

## Keystore partagé

Les clés sont stockées dans `{config}/cryptyrust/keys/` (Linux : `~/.config/cryptyrust/keys/`).  
Ce répertoire est partagé entre la GUI, le CLI et `crypty-keygen` — une clé générée par l'un est immédiatement disponible dans les autres.

Pour générer une clé :
```bash
crypty-keygen -n alice --store
```

---

## Format de sortie

Par défaut, le fichier de sortie est généré dans le répertoire courant :
- Chiffrement : `fichier.txt` → `fichier.txt.arsn`
- Déchiffrement : `fichier.txt.arsn` → `fichier.txt`

Si un fichier du même nom existe déjà, un suffixe `(1)`, `(2)`, … est ajouté.
