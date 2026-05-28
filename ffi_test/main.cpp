// arsenic_test — minimal C++ CLI demo for arsenic_ffi
//
// Usage:
//   arsenic_test encrypt <file>       <password>   →  <file>.arsn
//   arsenic_test decrypt <file>.arsn  <password>   →  <file>
//   arsenic_test bench   [payload_mib]              (default: 32 MiB)

#include "cryptyrust.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

// ── Progress bar ──────────────────────────────────────────────────────────────

struct ProgressCtx {
    const char* label;
    int         last_pct = -1;
};

// Called by the Rust library during encrypt / decrypt / rekey.
// Runs on the same thread as the FFI call (no synchronisation needed).
static void on_progress(int32_t pct, void* user_data) {
    auto* ctx = static_cast<ProgressCtx*>(user_data);
    if (pct == ctx->last_pct) return;
    ctx->last_pct = pct;

    constexpr int W = 40;
    int filled = pct * W / 100;

    std::printf("\r  %-12s [", ctx->label);
    for (int i = 0; i < W; ++i)
        std::putchar(i < filled ? '#' : '-');
    std::printf("] %3d%%", pct);
    std::fflush(stdout);

    if (pct >= 100) std::putchar('\n');
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = static_cast<std::size_t>(f.tellg());
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(sz));
    return buf;
}

static bool write_file(const std::string& path, const uint8_t* data, std::size_t len) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return f.good();
}

static const char* cipher_name(uint8_t id) {
    switch (id) {
        case 0x02: return "Deoxys-II-256";
        case 0x03: return "XChaCha20-Poly1305";
        case 0x04: return "AES-256-GCM-SIV";
        default:   return "Unknown";
    }
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

static int do_encrypt(const std::string& path, const char* password) {
    auto plaintext = read_file(path);
    if (plaintext.empty()) {
        std::fprintf(stderr, "Error: cannot read '%s'\n", path.c_str());
        return 1;
    }

    ArsParams params = arsenic_default_params();
    std::printf("Input:    %s  (%zu bytes)\n", path.c_str(), plaintext.size());
    std::printf("Cipher:   %s (header)  /  %s (payload)\n",
                cipher_name(params.hdr_cipher), cipher_name(params.pld_cipher));
    std::printf("Strength: Interactive — 256 MiB Argon2id\n\n");
    std::printf("  (progress bar appears after the ~2 s Argon2id key derivation)\n\n");

    ArsBuffer ct{};
    ProgressCtx ctx{"Encrypting"};

    int32_t rc = arsenic_encrypt(
        plaintext.data(), plaintext.size(),
        password, &params,
        on_progress, &ctx,
        &ct
    );

    if (rc != ARSENIC_OK) {
        std::fprintf(stderr, "\nEncryption failed [%d]: %s\n",
                     rc, arsenic_last_error() ? arsenic_last_error() : "(no message)");
        return 1;
    }

    std::string out_path = path + ".arsn";
    if (!write_file(out_path, ct.ptr, ct.len)) {
        std::fprintf(stderr, "Error: cannot write '%s'\n", out_path.c_str());
        arsenic_free_buffer(&ct);
        return 1;
    }
    std::printf("Output:   %s  (%zu bytes)\n", out_path.c_str(), ct.len);
    arsenic_free_buffer(&ct);
    return 0;
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

static int do_decrypt(const std::string& path, const char* password) {
    if (!arsenic_is_arsenic_file(path.c_str())) {
        std::fprintf(stderr,
                     "Error: '%s' is not a valid Arsenic V1 file (.arsn)\n",
                     path.c_str());
        return 1;
    }

    auto ciphertext = read_file(path);
    if (ciphertext.empty()) {
        std::fprintf(stderr, "Error: cannot read '%s'\n", path.c_str());
        return 1;
    }

    std::printf("Input:    %s  (%zu bytes)\n\n", path.c_str(), ciphertext.size());
    std::printf("  (cipher params are read from the file header)\n");
    std::printf("  (progress bar appears after the ~2 s Argon2id key derivation)\n\n");

    ArsBuffer pt{};
    ProgressCtx ctx{"Decrypting"};

    int32_t rc = arsenic_decrypt(
        ciphertext.data(), ciphertext.size(),
        password,
        on_progress, &ctx,
        &pt
    );

    if (rc != ARSENIC_OK) {
        std::fprintf(stderr, "\nDecryption failed [%d]: %s\n",
                     rc, arsenic_last_error() ? arsenic_last_error() : "(no message)");
        return 1;
    }

    // Strip ".arsn" suffix for the output filename, fallback to "<name>.dec"
    std::string out_path = path;
    if (out_path.size() > 5 &&
        out_path.compare(out_path.size() - 5, 5, ".arsn") == 0)
        out_path.erase(out_path.size() - 5);
    else
        out_path += ".dec";

    if (!write_file(out_path, pt.ptr, pt.len)) {
        std::fprintf(stderr, "Error: cannot write '%s'\n", out_path.c_str());
        arsenic_free_buffer(&pt);
        return 1;
    }
    std::printf("Output:   %s  (%zu bytes)\n", out_path.c_str(), pt.len);
    arsenic_free_buffer(&pt);
    return 0;
}

// ── Bench ─────────────────────────────────────────────────────────────────────

static int do_bench(std::size_t payload_mib) {
    std::printf(
        "Benchmarking 3 AEAD ciphers on %zu MiB of data\n"
        "(one Interactive Argon2id key derivation — ~2 s — then cipher tests)...\n\n",
        payload_mib);

    ArsBenchArray arr = arsenic_bench(payload_mib);

    std::printf("  %-22s  %12s  %12s\n", "Cipher", "Encrypt", "Decrypt");
    std::printf("  %s\n", std::string(52, '-').c_str());

    for (std::size_t i = 0; i < arr.count; ++i) {
        const ArsBenchResult& r = arr.results[i];
        std::printf("  %-22s  %7.0f MiB/s  %7.0f MiB/s%s\n",
                    cipher_name(r.cipher_id),
                    r.encrypt_mibps, r.decrypt_mibps,
                    i == 0 ? "  * fastest" : "");
    }

    uint8_t hdr = 0, pld = 0;
    arsenic_bench_best_combo(&arr, &hdr, &pld);

    std::printf(
        "\n  Note: the header cipher encrypts only 32 bytes (the DEK) —\n"
        "  its choice has no measurable impact on throughput.\n"
        "  Both roles are set to the fastest payload cipher.\n\n"
        "  Recommended:  hdr_cipher = 0x%02X (%s)\n"
        "                pld_cipher = 0x%02X (%s)\n",
        hdr, cipher_name(hdr), pld, cipher_name(pld));

    arsenic_free_bench_array(arr);
    return 0;
}

// ── main ──────────────────────────────────────────────────────────────────────

static void usage(const char* prog) {
    std::printf(
        "Usage:\n"
        "  %s encrypt <file>       <password>   encrypt → <file>.arsn\n"
        "  %s decrypt <file>.arsn  <password>   decrypt → <file>\n"
        "  %s bench   [mib]                     benchmark ciphers (default 32 MiB)\n\n",
        prog, prog, prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    std::string cmd = argv[1];

    if (cmd == "encrypt") {
        if (argc < 4) { usage(argv[0]); return 1; }
        return do_encrypt(argv[2], argv[3]);
    }
    if (cmd == "decrypt") {
        if (argc < 4) { usage(argv[0]); return 1; }
        return do_decrypt(argv[2], argv[3]);
    }
    if (cmd == "bench") {
        std::size_t mib = (argc >= 3) ? std::stoul(argv[2]) : 32;
        return do_bench(mib);
    }

    std::fprintf(stderr, "Unknown command: %s\n\n", cmd.c_str());
    usage(argv[0]);
    return 1;
}
