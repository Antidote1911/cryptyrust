# Developing Cryptyrust

Build instructions and project layout. For what the application does and how
to use it, see [`README.md`](README.md).

---

## Project Structure

A Cargo workspace of three crates:

| Crate / Directory | Output | Description |
|---|---|---|
| [`arsenic/`](arsenic/) | library | Cryptographic core — [README](arsenic/README.md) · [Format spec](arsenic/FORMAT.md) |
| [`cryptyrust/`](cryptyrust/) | `cryptyrust` | GUI + CLI + key management — [README](cryptyrust/README.md) |
| [`ffi/`](ffi/) | `libarsenic_ffi.so/.a` | C-compatible FFI layer — [README](ffi/README.md) |

[`ffi_test/`](ffi_test/) is a C++ round-trip test of the FFI layer and
[`packaging/`](packaging/) holds the icons and installer scripts used by the
release workflow.

All cryptographic logic is in `arsenic`; `cryptyrust` only drives it.

---

## Prerequisites

- [Rust toolchain](https://rustup.rs/) stable
- **Linux only** — X11 / Wayland development packages:
  ```bash
  sudo apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                   libxkbcommon-dev libssl-dev pkg-config
  ```

---

## Build

```bash
cargo build --release              # whole workspace
cargo build --release -p cryptyrust
# Binary: target/release/cryptyrust
```

`./build.sh` (or `./build.sh --debug`) builds the whole workspace. The version
is set once, in `[workspace.package]` of the root `Cargo.toml`.

### macOS universal binary

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create target/x86_64-apple-darwin/release/cryptyrust \
             target/aarch64-apple-darwin/release/cryptyrust \
             -output cryptyrust_universal
```

### FFI library and its C++ test

```bash
cargo build --release -p arsenic_ffi
cmake -B ffi_test/build -S ffi_test && cmake --build ffi_test/build
```

---

## Tests and Checks

These are the commands run by CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

The tests run real Argon2id key derivations: the suite takes a few minutes.

`cargo bench -p arsenic` runs the cipher benchmarks.

---

## Code Structure of `cryptyrust`

```
cryptyrust/src/
├── main.rs          Entry point: GUI if no args, CLI otherwise
├── app.rs           Application state, business logic, job dispatch
├── cli.rs           Clap argument definitions
├── cli_runner.rs    CLI command implementations
├── job.rs           Encrypt/decrypt job management (worker threads)
├── file_utils.rs    Mode detection, output path generation
├── keystore.rs      Re-export of arsenic::keystore
├── i18n/
│   ├── mod.rs       Interface language: tr(), trf(), Lang
│   └── fr.rs        French strings
└── ui/
    ├── mod.rs       Main rendering dispatch, secondary windows
    ├── layouts.rs   Menu bar, action bar, central panel, status banners
    └── components.rs Tables, popups, settings, key manager, About window
```

---

## Translations

The code keeps its English strings. Text shown by the GUI goes through
`i18n::tr`, which returns it in the current language, or unchanged when there
is no translation:

```rust
ui.button(tr("Close"));
trf("A key named \"{name}\" already exists.", &[("name", &name)]);
```

- **New text** — wrap it in `tr(…)` (or `trf(…)` when it has `{name}`
  placeholders) and add the pair `("English", "Français")` to
  `cryptyrust/src/i18n/fr.rs`.
- **New language** — add a variant to `Lang` in `i18n/mod.rs`, a table next to
  `fr.rs`, and its branch in `tr_in` and `core_err`. The language list of the
  settings window follows `Lang::ALL`.

A test checks that each translation keeps the placeholders and line breaks of
its English text. The CLI is not translated: the language only changes when
the GUI sets it.

---

## Releases

Pushing a version tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds the files below, then publishes them with the format
specification. Started by hand (**Actions → Release → Run workflow**), it only
builds: the files are kept as artifacts of the run and no release is created.

| File | Built from |
|---|---|
| `cryptyrust-<version>-linux.AppImage` | linuxdeploy |
| `cryptyrust_<version>_amd64.deb` | [`packaging/debian/control`](packaging/debian/control) — the program in `/usr/bin` |
| `cryptyrust-<version>-linux.flatpak` | [`packaging/flatpak/`](packaging/flatpak/) — freedesktop runtime |
| `cryptyrust-<version>-macos-universal.dmg` | [`packaging/macos/`](packaging/macos/) |
| `cryptyrust-<version>-win-setup.exe`, `…-win-portable.zip` | [`packaging/windows/`](packaging/windows/) |

The Flatpak can be built locally:

```bash
flatpak-builder --user --install --force-clean build-flatpak \
    packaging/flatpak/io.github.antidote1911.cryptyrust.yml
```

### Arch Linux (AUR)

[`packaging/aur/`](packaging/aur/) holds the two packages, which replace each
other:

| Package | Content |
|---|---|
| `cryptyrust-bin` | The program taken from the AppImage of the release; nothing is built |
| `cryptyrust` | Built from the sources of the release |

Once the release is on GitHub:

```bash
packaging/aur/publish.sh             # version of Cargo.toml; asks before each push
packaging/aur/publish.sh --no-push   # only updates PKGBUILD and .SRCINFO here
packaging/aur/publish.sh --wait      # right after pushing the tag: waits for the release
```

The script sets `pkgver`, puts `pkgrel` back to 1, computes the checksums from
the files of the release, rebuilds `.SRCINFO`, then commits both files to the
AUR repository of each package. The push goes through SSH with the key of your
AUR account; a package that does not exist yet is created by its first push.
It needs `pacman-contrib` (`updpkgsums`), `git` and `curl`. Commit
`packaging/aur/` afterwards.
