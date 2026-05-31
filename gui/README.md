# cryptyrust GUI

Interface graphique native pour le chiffrement de fichiers Arsenic V1, construite avec [egui](https://github.com/emilk/egui) / [eframe](https://github.com/emilk/egui/tree/master/crates/eframe).

---

## Fonctionnalités

- **Drag-and-drop** — déposer des fichiers directement sur la fenêtre
- **Détection automatique du mode** — `.arsn` = déchiffrement, autres = chiffrement
- **Chiffrement multi-fichiers en parallèle** via Rayon
- **Annulation individuelle** de chaque opération en cours
- **Chiffrement hybride post-quantique** — sélectionner des destinataires (X25519 + ML-KEM-768)
- **Déchiffrement automatique par clé** — si une clé du keystore correspond au fichier, aucun mot de passe n'est demandé
- **Gestionnaire de clés** — générer des keypairs hybrides, gérer les contacts
- **Benchmark** intégré des chiffrements AEAD
- **Changement de mot de passe** en place (rekey)
- Thème clair / sombre ; paramètres persistés entre sessions

---

## Workflow de chiffrement symétrique

1. Déposer les fichiers ou cliquer **Add files**
2. Cliquer **Encrypt**, entrer le mot de passe (+ confirmation)
3. Les fichiers `.arsn` sont créés dans le même répertoire

## Workflow de chiffrement asymétrique (sans mot de passe)

1. Ouvrir **Keys → Key Manager**
2. Générer un keypair (`⚡ Generate`) ou ajouter un contact (clé publique X25519 + ML-KEM-768)
3. Cliquer **Encrypt** → sélectionner les destinataires dans la popup
4. Le mot de passe devient optionnel si au moins un destinataire est coché

## Workflow de déchiffrement

- **Avec clé stockée** : si une clé du keystore correspond au fichier, le déchiffrement démarre directement sans popup
- **Avec mot de passe** : si aucune clé ne correspond, la popup demande le mot de passe
- **Sélection manuelle** : dans la popup, choisir explicitement quelle clé utiliser

---

## Configuration

Menu **Config** :

| Réglage | Options | Défaut |
|---|---|---|
| Argon2id strength | Interactive (256 MiB, ~1-3 s) · Sensitive (1 GiB, ~10-30 s) | Interactive |
| Header cipher | Deoxys-II-256 · AES-256-GCM-SIV · XChaCha20-Poly1305 | Deoxys-II-256 |
| Payload cipher | XChaCha20-Poly1305 · AES-256-GCM-SIV · Deoxys-II-256 | XChaCha20-Poly1305 |
| Benchmark | ⏱ Benchmark ciphers… | — |

Les paramètres sont persistés entre sessions via le stockage eframe.

---

## Compilation

```bash
cargo build --release -p cryptyrust
```

### Dépendances Linux

```bash
sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                 libxkbcommon-dev libssl-dev pkg-config
```

---

## Structure du code

```
gui/src/
├── main.rs          Point d'entrée, initialisation eframe
├── app.rs           État de l'application, logique métier
├── job.rs           Gestion des jobs de chiffrement/déchiffrement (Rayon)
├── file_utils.rs    Détection du mode, génération des chemins de sortie
├── keystore.rs      Re-export de arsenic::keystore
└── ui/
    ├── mod.rs       Dispatching principal du rendu
    ├── layouts.rs   Barre de menu, barre d'action, panneau central
    └── components.rs Tableaux, popups, gestionnaire de clés
```
