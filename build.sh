#!/usr/bin/env bash
# =============================================================================
#  build.sh — Build complet du workspace
#  Usage : ./build.sh [--debug]
#
#  - Lit la version de référence dans [workspace.package] (Cargo.toml racine)
#  - Compile le workspace (arsenic, cryptyrust, ffi)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}ℹ ${RESET}$*"; }
success() { echo -e "${GREEN}✔ ${RESET}$*"; }
warn()    { echo -e "${YELLOW}⚠ ${RESET}$*"; }
error()   { echo -e "${RED}✖ ${RESET}$*" >&2; }
title()   { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}\n"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# ── Mode de compilation ───────────────────────────────────────────────────────
PROFILE="release"
CARGO_FLAGS=("--release" "--workspace")
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE="debug"
  CARGO_FLAGS=("--workspace")
fi

# ── 1. Lecture de la version de référence (Cargo.toml racine) ────────────────
title "Version de référence"

VERSION=$(awk '/^\[workspace\.package\]/{f=1; next} /^\[/{f=0} f && /^version[[:space:]]*=/{
  match($0, /"([^"]+)"/, m); print m[1]; exit
}' Cargo.toml)

if [[ -z "$VERSION" ]]; then
  error "Impossible de lire [workspace.package].version dans Cargo.toml"
  exit 1
fi
info "Version du workspace : ${BOLD}${VERSION}${RESET}"

# ── 2. Compilation du workspace ───────────────────────────────────────────────
title "Compilation du workspace (profil : ${PROFILE})"

info "cargo build ${CARGO_FLAGS[*]}"
if ! cargo build "${CARGO_FLAGS[@]}"; then
  error "La compilation a échoué."
  exit 1
fi

success "Workspace compilé avec succès (arsenic, cryptyrust, ffi) — version ${VERSION}"
echo ""
info "Binaires et bibliothèques disponibles dans : ${BOLD}target/${PROFILE}/${RESET}"
