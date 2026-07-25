/*
  ffi/secp256k1_shim.c — the ONLY C in LeanBCH, and the entire trusted binding surface.

  WHAT THIS IS. LeanBCH's `LeanBCH.Crypto.Secp256k1` is a two-field PARAMETER structure
  (LeanBCH/Oracle.lean); until this file existed, `Secp256k1.reject` — which rejects everything —
  was its only inhabitant. This shim provides the second one by delegating point verification to
  the libsecp256k1 built from BCHN's VENDORED fork.

  WHAT IS ASSUMED. Not "elliptic-curve maths is correct" — that is untestable and not the claim.
  The claim is "this binary, at this commit, agrees with what the network does", which is a
  DIFFERENTIAL statement about a pinned artifact (see ffi/build.sh, which asserts the archive's
  sha256 before compiling). Binding libsecp converts an untestable assumption into a tested
  dependency.

  THE BOUNDARY RULE. This file mirrors BCHN's own split EXACTLY rather than choosing its own.
  Everything BCHN does OUTSIDE libsecp (strict-DER, low-S, pubkey-encoding policy, sighash-type
  validity — all in its interpreter, src/script/sigencoding.cpp) is Lean's job and is deliberately
  NOT here. Everything BCHN DELEGATES to libsecp crosses this file. Copying the boundary rather
  than picking one buys minimum trusted surface and bit-exactness with the reference node at once.

  Consequently this file mirrors exactly two BCHN methods, both in src/pubkey.cpp:
    CPubKey::VerifySchnorr  pubkey.cpp:199-217  →  leanbch_schnorr_verify
    CPubKey::VerifyECDSA    pubkey.cpp:174-197  →  leanbch_ecdsa_verify

  BCH SCHNORR IS NOT BIP-340. pubkey.cpp:210 parses the pubkey with secp256k1_ec_pubkey_parse at
  its FULL SEC length (33 compressed / 65 uncompressed) and pubkey.cpp:215 calls
  secp256k1_schnorr_verify, from module src/secp256k1/src/modules/schnorr in the vendored fork.
  Upstream's BIP-340 entry point is the differently-named secp256k1_schnorrsig_verify (module
  schnorrsig) and takes a 32-byte X-ONLY key. That symbol is ABSENT from the pinned archive
  (verified: `nm --defined-only libsecp256k1.a | grep -c schnorrsig` → 0), and the fork's own
  header calls this a "custom EC-Schnorr-SHA256 construction"
  (src/secp256k1/include/secp256k1_schnorr.h:26-27). Binding the wrong one, or truncating a SEC
  key to 32 bytes to fit it, yields a verifier that disagrees with the network.

  ADVERSARIAL INPUT. Every byte reaching these functions is attacker-chosen: they are called from
  the VM's OP_CHECKSIG* arms on raw stack items of arbitrary length and content. A shim that can
  abort or read out of bounds here is a consensus-node DoS. Therefore: every length is checked
  before any pointer is dereferenced, and libsecp's illegal-argument/error callbacks are replaced
  with non-aborting ones (the stock callbacks call abort()). Every failure path returns false.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include <lean/lean.h>

#include "secp256k1.h"
#include "secp256k1_schnorr.h"

/* ------------------------------------------------------------------------------------------
   The verification context — created ONCE, lazily, thread-safely.

   secp256k1_context_create is expensive (it builds the ecmult tables); BCHN likewise creates one
   process-wide `secp256k1_context_verify`. Lean's runtime is multi-threaded (task pool), and
   nothing stops two threads from hitting OP_CHECKSIG concurrently, so the initialisation goes
   through pthread_once rather than a plain `if (ctx == NULL)` double-init race.

   A verify-only context is READ-ONLY once built, so concurrent verification through it is safe
   (it holds no secret state and libsecp only mutates contexts via the setters below, which we
   call exclusively from the pthread_once initialiser).
   ------------------------------------------------------------------------------------------ */

static secp256k1_context *g_leanbch_ctx = NULL;
static pthread_once_t g_leanbch_once = PTHREAD_ONCE_INIT;

/*
  libsecp's DEFAULT illegal-argument and error callbacks print to stderr and then call abort().
  Reaching one would turn a malformed stack item into a process kill. We never intend to trip
  them (every argument is length-checked below), but "never intend to" is not a safety argument
  when the input is adversarial, so we install non-aborting callbacks as a second line of defence.

  Returning from the illegal callback is well-defined and fail-closed: libsecp's ARG_CHECK macro
  is `if (!(cond)) { secp256k1_callback_call(&ctx->illegal_callback, ...); return 0; }`, i.e. the
  verification function returns 0 = "not verified" immediately after the callback returns.
*/
static void leanbch_secp_noabort(const char *msg, void *data) {
  (void)msg;
  (void)data;
}

static void leanbch_secp_init(void) {
  g_leanbch_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  if (g_leanbch_ctx != NULL) {
    secp256k1_context_set_illegal_callback(g_leanbch_ctx, leanbch_secp_noabort, NULL);
    secp256k1_context_set_error_callback(g_leanbch_ctx, leanbch_secp_noabort, NULL);
  }
}

static secp256k1_context *leanbch_secp_ctx(void) {
  pthread_once(&g_leanbch_once, leanbch_secp_init);
  return g_leanbch_ctx;
}

/* ------------------------------------------------------------------------------------------
   CPubKey's length discipline — mirror of BCHN src/pubkey.h.

   BCHN does NOT hand libsecp the raw stack bytes with the raw stack length. It first builds a
   CPubKey, whose Set() (pubkey.h:76-83) computes the length IMPLIED BY THE HEADER BYTE via
   GetLen() (pubkey.h:54-62) and Invalidate()s the key unless that equals the actual byte count;
   IsValid() (pubkey.h:145) is then `size() > 0`, and both VerifySchnorr and VerifyECDSA bail on
   `!IsValid()` before touching libsecp. Only then is secp256k1_ec_pubkey_parse called with
   size() — the header-implied length.

   Net effect, which is what we replicate: the key must be 33 bytes with header 0x02/0x03, or
   65 bytes with header 0x04/0x06/0x07. Anything else never reaches libsecp.

   Note 0x06/0x07 map to 65 here (a hybrid-encoding legacy) even though BCHN's interpreter-side
   IsCompressedOrUncompressedPubKey (sigencoding.cpp:274-288) rejects them earlier under
   SCRIPT_VERIFY_STRICTENC. That earlier rejection is Lean's job under the boundary rule, so this
   file keeps CPubKey's behaviour exactly and does not add a stricter check of its own — a shim
   that is stricter than the node it mirrors is just as wrong as one that is laxer.
   ------------------------------------------------------------------------------------------ */

/* Mirror of CPubKey::GetLen, BCHN src/pubkey.h:54-62. Returns 0 for an unrecognised header. */
static size_t leanbch_pubkey_len(uint8_t header) {
  if (header == 2 || header == 3) {
    return 33; /* CPubKey::COMPRESSED_PUBLIC_KEY_SIZE */
  }
  if (header == 4 || header == 6 || header == 7) {
    return 65; /* CPubKey::PUBLIC_KEY_SIZE */
  }
  return 0;
}

/* CPubKey::Set + IsValid + secp256k1_ec_pubkey_parse, as the two Verify* methods perform them. */
static int leanbch_parse_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *out,
                                const uint8_t *pk, size_t pklen) {
  if (pk == NULL || pklen == 0) {
    return 0;
  }
  if (leanbch_pubkey_len(pk[0]) != pklen) {
    return 0; /* Set() would Invalidate(); IsValid() is then false */
  }
  return secp256k1_ec_pubkey_parse(ctx, out, pk, pklen);
}

/* ------------------------------------------------------------------------------------------
   ecdsa_signature_parse_der_lax — VERBATIM from BCHN src/pubkey.cpp:29-172.

   This is deliberately NOT secp256k1_ecdsa_signature_parse_der. That function exists in the
   pinned archive and binding it would be a CONSENSUS BUG: it is strict, whereas BCHN parses with
   this local PERMISSIVE parser (negative integers, excessive padding, garbage at the end, overly
   long length descriptors) and enforces strict-DER separately, interpreter-side. Using the strict
   parser here would reject signatures the network accepts.

   Copied rather than reimplemented on purpose: every one of its length checks is load-bearing
   against adversarial input, and "I rewrote it and it looked equivalent" is not a claim worth
   making about a consensus parser. The only edits are C++-isms → C (`static_assert` dropped;
   it asserted sizeof(size_t) >= 4, which holds on every target Lean supports).
   ------------------------------------------------------------------------------------------ */
static int ecdsa_signature_parse_der_lax(const secp256k1_context *ctx,
                                         secp256k1_ecdsa_signature *sig,
                                         const uint8_t *input, size_t inputlen) {
  size_t rpos, rlen, spos, slen;
  size_t pos = 0;
  size_t lenbyte;
  uint8_t tmpsig[64] = {0};
  int overflow = 0;

  /* Hack to initialize sig with a correctly-parsed but invalid signature. */
  secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

  /* Sequence tag byte */
  if (pos == inputlen || input[pos] != 0x30) {
    return 0;
  }
  pos++;

  /* Sequence length bytes */
  if (pos == inputlen) {
    return 0;
  }
  lenbyte = input[pos++];
  if (lenbyte & 0x80) {
    lenbyte -= 0x80;
    if (lenbyte > inputlen - pos) {
      return 0;
    }
    pos += lenbyte;
  }

  /* Integer tag byte for R */
  if (pos == inputlen || input[pos] != 0x02) {
    return 0;
  }
  pos++;

  /* Integer length for R */
  if (pos == inputlen) {
    return 0;
  }
  lenbyte = input[pos++];
  if (lenbyte & 0x80) {
    lenbyte -= 0x80;
    if (lenbyte > inputlen - pos) {
      return 0;
    }
    while (lenbyte > 0 && input[pos] == 0) {
      pos++;
      lenbyte--;
    }
    if (lenbyte >= 4) {
      return 0;
    }
    rlen = 0;
    while (lenbyte > 0) {
      rlen = (rlen << 8) + input[pos];
      pos++;
      lenbyte--;
    }
  } else {
    rlen = lenbyte;
  }
  if (rlen > inputlen - pos) {
    return 0;
  }
  rpos = pos;
  pos += rlen;

  /* Integer tag byte for S */
  if (pos == inputlen || input[pos] != 0x02) {
    return 0;
  }
  pos++;

  /* Integer length for S */
  if (pos == inputlen) {
    return 0;
  }
  lenbyte = input[pos++];
  if (lenbyte & 0x80) {
    lenbyte -= 0x80;
    if (lenbyte > inputlen - pos) {
      return 0;
    }
    while (lenbyte > 0 && input[pos] == 0) {
      pos++;
      lenbyte--;
    }
    if (lenbyte >= 4) {
      return 0;
    }
    slen = 0;
    while (lenbyte > 0) {
      slen = (slen << 8) + input[pos];
      pos++;
      lenbyte--;
    }
  } else {
    slen = lenbyte;
  }
  if (slen > inputlen - pos) {
    return 0;
  }
  spos = pos;

  /* Ignore leading zeroes in R */
  while (rlen > 0 && input[rpos] == 0) {
    rlen--;
    rpos++;
  }
  /* Copy R value */
  if (rlen > 32) {
    overflow = 1;
  } else {
    memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
  }

  /* Ignore leading zeroes in S */
  while (slen > 0 && input[spos] == 0) {
    slen--;
    spos++;
  }
  /* Copy S value */
  if (slen > 32) {
    overflow = 1;
  } else {
    memcpy(tmpsig + 64 - slen, input + spos, slen);
  }

  if (!overflow) {
    overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
  }
  if (overflow) {
    /* Overwrite the result again with a correctly-parsed but invalid
       signature if parsing failed. */
    memset(tmpsig, 0, 64);
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
  }
  return 1;
}

/* ------------------------------------------------------------------------------------------
   The Lean entry points.

   ABI: Lean compiles `ByteArray` to a lean_sarray_object (lean.h:186-192) — header, size_t
   m_size, size_t m_capacity, then inline uint8_t m_data[]. Read it with lean_sarray_size
   (lean.h:1042) and lean_sarray_cptr (lean.h:1051). Arguments are BORROWED (b_lean_obj_arg), so
   there is no refcount work to do and nothing to free. `Bool` comes back as uint8_t 0/1.

   Both functions are total: every input, however malformed, produces 0 or 1 and no side effect.
   ------------------------------------------------------------------------------------------ */

/*
  BCH-2019 Schnorr — mirror of CPubKey::VerifySchnorr, BCHN src/pubkey.cpp:199-217.

    sig    the 64-byte signature BODY (the VM has already stripped the sighash-type byte)
    pubkey a full SEC point, 33 or 65 bytes
    digest the 32-byte sighash / message digest
*/
LEAN_EXPORT uint8_t leanbch_schnorr_verify(b_lean_obj_arg sig_o, b_lean_obj_arg pk_o,
                                           b_lean_obj_arg digest_o) {
  secp256k1_context *ctx = leanbch_secp_ctx();
  if (ctx == NULL) {
    return 0;
  }

  size_t siglen = lean_sarray_size(sig_o);
  size_t pklen = lean_sarray_size(pk_o);
  size_t digestlen = lean_sarray_size(digest_o);

  /* pubkey.cpp:204 — VerifySchnorr requires exactly 64 signature bytes. */
  if (siglen != 64) {
    return 0;
  }
  /* The digest is a uint256 in BCHN, so 32 is the only length the mirror is defined at.
     Nothing in the Lean model produces another length, but this is checked rather than
     assumed because secp256k1_schnorr_verify reads exactly 32 bytes through this pointer. */
  if (digestlen != 32) {
    return 0;
  }

  const uint8_t *sig = lean_sarray_cptr(sig_o);
  const uint8_t *pk = lean_sarray_cptr(pk_o);
  const uint8_t *digest = lean_sarray_cptr(digest_o);

  secp256k1_pubkey pubkey;
  if (!leanbch_parse_pubkey(ctx, &pubkey, pk, pklen)) {
    return 0;
  }

  /* Argument order is (sig64, msg32, pubkey) — secp256k1_schnorr.h:20-24. */
  return secp256k1_schnorr_verify(ctx, sig, digest, &pubkey) == 1 ? 1 : 0;
}

/*
  ECDSA — mirror of CPubKey::VerifyECDSA, BCHN src/pubkey.cpp:174-197.

  NOTE the name of the Lean field this backs, `verifyDERLowS`, is a MISNOMER inherited from
  Oracle.lean: libsecp does neither strict-DER nor low-S here. The parse is the LAX one above,
  and pubkey.cpp:194 explicitly NORMALISES high-S away before verifying, with the comment
  "libsecp256k1's ECDSA verification requires lower-S signatures, which have not historically
  been enforced in Bitcoin, so normalize them first." Strict-DER and low-S are enforced entirely
  interpreter-side (sigencoding.cpp:156-175; CPubKey::CheckLowS, pubkey.cpp:325) and are Lean's
  responsibility. Do NOT "fix" this by rejecting high-S here: that would double-enforce a check
  at the wrong layer and diverge from BCHN for the cases Lean has not yet gated.

    sig    the DER signature BODY (sighash-type byte already stripped by the VM)
    pubkey a full SEC point, 33 or 65 bytes
    digest the 32-byte sighash / message digest
*/
LEAN_EXPORT uint8_t leanbch_ecdsa_verify(b_lean_obj_arg sig_o, b_lean_obj_arg pk_o,
                                         b_lean_obj_arg digest_o) {
  secp256k1_context *ctx = leanbch_secp_ctx();
  if (ctx == NULL) {
    return 0;
  }

  size_t siglen = lean_sarray_size(sig_o);
  size_t pklen = lean_sarray_size(pk_o);
  size_t digestlen = lean_sarray_size(digest_o);

  if (digestlen != 32) {
    return 0;
  }

  const uint8_t *sig = lean_sarray_cptr(sig_o);
  const uint8_t *pk = lean_sarray_cptr(pk_o);
  const uint8_t *digest = lean_sarray_cptr(digest_o);

  secp256k1_pubkey pubkey;
  if (!leanbch_parse_pubkey(ctx, &pubkey, pk, pklen)) {
    return 0;
  }

  secp256k1_ecdsa_signature signature;
  if (!ecdsa_signature_parse_der_lax(ctx, &signature, sig, siglen)) {
    return 0;
  }

  /* pubkey.cpp:194 — normalise before verifying, exactly as BCHN does. */
  secp256k1_ecdsa_signature_normalize(ctx, &signature, &signature);

  return secp256k1_ecdsa_verify(ctx, &signature, digest, &pubkey) == 1 ? 1 : 0;
}
