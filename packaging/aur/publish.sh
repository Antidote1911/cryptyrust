#!/usr/bin/env bash
# Brings the two AUR packages (cryptyrust-bin, cryptyrust) to a published GitHub release and pushes them.
#
#   packaging/aur/publish.sh            the version of Cargo.toml
#   packaging/aur/publish.sh 3.1.0      this version
#   packaging/aur/publish.sh --no-push  only updates PKGBUILD and .SRCINFO here, pushes nothing
#   packaging/aur/publish.sh --yes      pushes without asking
#   packaging/aur/publish.sh --wait     waits for the files of the release (up to 40 minutes): to be
#                                       started right after "git push origin v3.1.0"
#
# To be run once the release exists on GitHub: the checksums are computed from its files (the
# AppImage for cryptyrust-bin, the archive of the tag for cryptyrust).
#
# For each package: pkgver set, pkgrel back to 1, checksums (updpkgsums), .SRCINFO; then its AUR
# repository is cloned into a temporary folder, the two files are copied into it, committed and
# pushed. Nothing secret is stored here: the push goes through SSH with the key registered in the
# AUR account of whoever runs the script (https://aur.archlinux.org → My Account → SSH Public Key).
#
# Needs: pacman-contrib (updpkgsums), git, curl.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
repo=Antidote1911/cryptyrust
packages=(cryptyrust-bin cryptyrust)

version=
push=1
yes=0
wait=0
for arg in "$@"; do
    case "$arg" in
        --no-push) push=0 ;;
        -y|--yes)  yes=1 ;;
        -w|--wait) wait=1 ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Option inconnue : $arg (voir packaging/aur/publish.sh --help)" >&2; exit 1 ;;
        *)  version=${arg#v} ;;
    esac
done
# The version of the workspace: [workspace.package] of the root Cargo.toml
[[ -n $version ]] || version=$(awk '/^\[workspace\.package\]/{f=1; next} /^\[/{f=0}
    f && /^version[[:space:]]*=/{gsub(/[^0-9.]/, ""); print; exit}' "$root/Cargo.toml")
[[ $version =~ ^[0-9]+(\.[0-9]+)+$ ]] || { echo "Version illisible : « $version »" >&2; exit 1; }
for tool in updpkgsums makepkg git curl; do
    command -v "$tool" >/dev/null || { echo "Outil manquant : $tool" >&2; exit 1; }
done

# The two files the packages download must be there.
appimage="https://github.com/$repo/releases/download/v$version/cryptyrust-$version-linux.AppImage"
tarball="https://github.com/$repo/archive/refs/tags/v$version.tar.gz"
present() { curl -fsIL -o /dev/null "$1"; }
echo "==> Release v$version"
tries=0
until present "$appimage" && present "$tarball"; do
    if (( !wait || ++tries > 80 )); then
        echo "Les fichiers de la release v$version ne sont pas (encore) sur GitHub :" >&2
        echo "  $appimage" >&2
        echo "Relancez quand le workflow « Release » est terminé, ou avec --wait." >&2
        exit 1
    fi
    (( tries == 1 )) && echo "    pas encore là : attente (workflow « Release »)…"
    sleep 30
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SRCDEST="$work/sources" BUILDDIR="$work/build" # downloads and builds stay out of the repository
mkdir -p "$SRCDEST" "$BUILDDIR"

for pkg in "${packages[@]}"; do
    dir="$here/$pkg"
    echo "==> $pkg : PKGBUILD et .SRCINFO"
    sed -i -e "s/^pkgver=.*/pkgver=$version/" -e "s/^pkgrel=.*/pkgrel=1/" "$dir/PKGBUILD"
    (cd "$dir" && updpkgsums >/dev/null && makepkg --printsrcinfo > .SRCINFO)
done

if (( !push )); then
    echo "==> OK : fichiers à jour dans packaging/aur/ (rien envoyé)"
    exit 0
fi

for pkg in "${packages[@]}"; do
    echo "==> $pkg : dépôt de l'AUR"
    git clone --quiet "ssh://aur@aur.archlinux.org/$pkg.git" "$work/$pkg"
    cp "$here/$pkg/PKGBUILD" "$here/$pkg/.SRCINFO" "$work/$pkg/"
    if git -C "$work/$pkg" diff --quiet && [[ -z $(git -C "$work/$pkg" status --porcelain) ]]; then
        echo "    déjà à jour"
        continue
    fi
    # git diff shows nothing for a package that is not in the AUR yet: its files are untracked
    git -C "$work/$pkg" add PKGBUILD .SRCINFO
    git -C "$work/$pkg" --no-pager diff --cached --stat
    if (( !yes )); then
        read -r -p "    Envoyer $pkg $version sur l'AUR ? [o/N] " answer
        [[ $answer == [oOyY]* ]] || { echo "    laissé tel quel"; continue; }
    fi
    git -C "$work/$pkg" commit --quiet --message "Version $version"
    git -C "$work/$pkg" push --quiet origin HEAD:master
    echo "    envoyé : https://aur.archlinux.org/packages/$pkg"
done
echo "==> OK. Pensez à valider packaging/aur/ dans le dépôt du projet (./git.sh)."
