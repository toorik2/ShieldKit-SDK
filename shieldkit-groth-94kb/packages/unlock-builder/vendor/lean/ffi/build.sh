#!/usr/bin/env bash
#
# ffi/build.sh — compile the secp256k1 shim and stage it where lakefile.toml expects it.
#
# WHY THIS IS A SHELL SCRIPT AND NOT A LAKE TARGET. Lake's TOML loader cannot declare an
# external library. Its decoder handles exactly four target kinds — LeanLib, LeanExe, InputFile,
# InputDir (Lake/Load/Toml.lean:429-432 in leanprover/lean4:v4.31.0); `ExternLibConfig` is absent
# from the `gen_toml_decoders%` list at Lake/Load/Toml.lean:400-418 and is reachable only from a
# `lakefile.lean`. Worse, it fails SILENTLY: decodeTomlConfig (Lake/Load/Toml.lean:358-365) drops
# unknown keys with a bare `else return cfg`, so a hand-written `[[extern_lib]]` block would look
# correct, produce no error, and do nothing. `moreLinkArgs` IS a real LeanConfig field
# (Lake/Config/LeanConfig.lean:219), inherited by lean_exe and decoded from TOML — so the shim is
# compiled here, out of band, and linked per-executable.
#
# WHAT IS PINNED. The trust claim this binding makes is not "elliptic-curve maths is correct" but
# "this binary, at this commit, agrees with what the network does". That is only meaningful against
# a NAMED artifact, so the archive's sha256 is asserted below and the build aborts on a mismatch.
# Re-pinning is a deliberate act: update EXPECTED_SHA256 and say why in the commit message.
#
# Usage:  ffi/build.sh
# Env:    SECP256K1_LIB_DIR      dir containing libsecp256k1.a   (default: BCHN build tree)
#         SECP256K1_INCLUDE_DIR  dir containing secp256k1.h      (default: BCHN source tree)
#         SECP256K1_ALLOW_UNPINNED=1  proceed despite a sha256 mismatch (prints a loud warning;
#                                     any result produced this way is NOT a pinned-artifact result)

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

BCHN_DEFAULT="/home/toorik/Projects/bchn-src"
SECP256K1_LIB_DIR="${SECP256K1_LIB_DIR:-$BCHN_DEFAULT/build/src/secp256k1}"
SECP256K1_INCLUDE_DIR="${SECP256K1_INCLUDE_DIR:-$BCHN_DEFAULT/src/secp256k1/include}"

# The pinned BCHN vendored-fork archive.
#   BCHN commit 864c53ee34924cca6c6b6d96607ff2cedcdccf02 ("Merge branch 'nits_pack_interpreter'
#   into 'master'"), libsecp256k1.a, 211898 bytes.
# This fork's Schnorr module is `schnorr` (secp256k1_schnorr_verify), NOT upstream's `schnorrsig`
# (BIP-340). `secp256k1_schnorrsig_verify` is absent from this archive by design — see the header
# comment of ffi/secp256k1_shim.c.
EXPECTED_SHA256="10b924cacd33111f260d62fee7d30cf7e2f360201207d05f1727080c22b13ed6"

ARCHIVE="$SECP256K1_LIB_DIR/libsecp256k1.a"

echo "== secp256k1 shim build =="
echo "   archive : $ARCHIVE"
echo "   headers : $SECP256K1_INCLUDE_DIR"

if [ ! -f "$ARCHIVE" ]; then
  echo "❌ libsecp256k1.a not found at $ARCHIVE" >&2
  echo "   Build BCHN first, or point SECP256K1_LIB_DIR at a directory containing it." >&2
  exit 1
fi
if [ ! -f "$SECP256K1_INCLUDE_DIR/secp256k1.h" ] || [ ! -f "$SECP256K1_INCLUDE_DIR/secp256k1_schnorr.h" ]; then
  echo "❌ secp256k1.h / secp256k1_schnorr.h not found in $SECP256K1_INCLUDE_DIR" >&2
  echo "   secp256k1_schnorr.h is specific to the BCHN vendored fork; upstream libsecp does not" >&2
  echo "   ship it. If it is missing you are pointing at the wrong (upstream) library." >&2
  exit 1
fi

ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  if [ "${SECP256K1_ALLOW_UNPINNED:-0}" = "1" ]; then
    echo "⚠  ARCHIVE IS NOT THE PINNED ONE — proceeding because SECP256K1_ALLOW_UNPINNED=1" >&2
    echo "   expected $EXPECTED_SHA256" >&2
    echo "   actual   $ACTUAL_SHA256" >&2
    echo "   Results produced against this build are NOT pinned-artifact results." >&2
  else
    echo "❌ libsecp256k1.a does not match the pinned sha256." >&2
    echo "   expected $EXPECTED_SHA256" >&2
    echo "   actual   $ACTUAL_SHA256" >&2
    echo "   The binding's whole claim is about a NAMED binary; an unpinned archive voids it." >&2
    echo "   Re-pin deliberately (edit EXPECTED_SHA256 here) or set SECP256K1_ALLOW_UNPINNED=1." >&2
    exit 1
  fi
else
  echo "   sha256  : $ACTUAL_SHA256 ✓ pinned"
fi

# Lean's own headers (lean/lean.h) live under the toolchain prefix.
if ! command -v lean >/dev/null 2>&1; then
  echo "❌ 'lean' not on PATH — source elan (e.g. export PATH=\"\$HOME/.elan/bin:\$PATH\")." >&2
  exit 1
fi
LEAN_INCLUDE="$(lean --print-prefix)/include"
if [ ! -f "$LEAN_INCLUDE/lean/lean.h" ]; then
  echo "❌ lean/lean.h not found under $LEAN_INCLUDE" >&2
  exit 1
fi

CC="${CC:-cc}"
OUT_DIR="$REPO_ROOT/.lake/ffi"
mkdir -p "$OUT_DIR"

echo "   cc      : $CC"
"$CC" -c "$REPO_ROOT/ffi/secp256k1_shim.c" \
  -o "$OUT_DIR/secp256k1_shim.o" \
  -I "$LEAN_INCLUDE" \
  -I "$SECP256K1_INCLUDE_DIR" \
  -O2 -fPIC -std=c11 -Wall -Wextra -Werror

# Stage the archive next to the object so lakefile.toml's moreLinkArgs stay machine-independent
# (relative paths in moreLinkArgs resolve from the package root). .lake/ is gitignored, so nothing
# machine-specific and nothing binary enters the repo.
cp "$ARCHIVE" "$OUT_DIR/libsecp256k1.a"

echo "✓ staged $OUT_DIR/secp256k1_shim.o and $OUT_DIR/libsecp256k1.a"
echo
echo "Next: lake build vmbconf   (or xcheck / xcheck_arg / xcheck_idx1 / xcheck_idxN)"
echo "Then: LEANBCH_SECP=native <runner>   — default stays 'reject', see LeanBCH/Crypto/Native.lean"
