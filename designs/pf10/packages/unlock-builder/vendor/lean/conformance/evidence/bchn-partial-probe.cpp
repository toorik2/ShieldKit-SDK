// bchn-partial-probe — a measurement instrument, NOT a consensus leg.
//
// WHY IT EXISTS. BCHN's VerifyScript (src/script/interpreter.cpp:2677) accumulates into a LOCAL
// `metrics` (:2691) and copies it to the caller's `metricsOut` at exactly two sites (:2745, :2794),
// both success returns. Every failure return leaves `metricsOut` untouched, so bch-conformance's
// bchn-leg — which reads a default-constructed object unconditionally (bchn-leg.cpp:315,323-325) —
// reports 0/0/0 for every rejected vector. That is an initializer, not a measurement, and it makes
// any sigCheck comparison on a rejected vector vacuous.
//
// This probe transcribes VerifyScript's body VERBATIM (same flags, same order, same EvalScript
// calls, same P2SH handling, same CLEANSTACK / INPUT_SIGCHECKS gates) with ONE change: the metrics
// object is the caller's, so whatever BCHN actually accrued before the error is observable. It
// therefore answers the question the leg cannot: how many sigChecks had BCHN's engine really
// tallied at the point it rejected?
//
// BCHN's own sources are NOT modified. This links the same static libs as bchn-leg. It is a probe:
// its accept/reject verdict is cross-checked against bchn-leg's for every vector, and any
// disagreement is reported as VERDICT_MISMATCH (which would invalidate the transcription).
//
// Output: NDJSON, one object per row:
//   {"ident":..,"ok":bool,"err":"..","sig_checks":N,"op_cost":N,"hash_iters":N,"phase":".."}

#include <coins.h>
#include <core_io.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/script_flags.h>
#include <script/script_metrics.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <version.h>

#include <cassert>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Identical to bchn-leg.cpp:77-89.
constexpr uint32_t kBlockFlags =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID |
    SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL | SCRIPT_VERIFY_SIGPUSHONLY |
    SCRIPT_VERIFY_CLEANSTACK | SCRIPT_ENABLE_SCHNORR_MULTISIG | SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_ENFORCE_SIGCHECKS | SCRIPT_ENABLE_TOKENS | SCRIPT_ENABLE_P2SH_32 |
    SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026;

constexpr uint32_t kCoinHeight = 1;

// Identical to bchn-leg.cpp:131-150 (see its comment for why AddCoin cannot be used).
class ScriptRefereeCoinsView : public CCoinsViewCache {
public:
    using CCoinsViewCache::CCoinsViewCache;
    void AddCoinUnpruned(const COutPoint &outpoint, Coin coin) {
        assert(!coin.IsSpent());
        auto [it, inserted] = cacheCoins.emplace(std::piecewise_construct,
                                                 std::forward_as_tuple(outpoint), std::tuple<>());
        if (!inserted) { cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage(); }
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        const bool fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
        it->second.coin = std::move(coin);
        it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
        cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
    }
};

// ---------------------------------------------------------------------------
// VerifyScriptKeepingMetrics — src/script/interpreter.cpp:2677-2796 transcribed verbatim, with
// `metrics` taken by reference from the caller instead of being a local that is copied only on
// success. `phase` records where it stopped, so a reject's accrual can be attributed.
// ---------------------------------------------------------------------------
bool VerifyScriptKeepingMetrics(const CScript &scriptSig, const CScript &scriptPubKey,
                                uint32_t flags, const BaseSignatureChecker &checker,
                                ScriptExecutionMetrics &metrics, ScriptError *serror,
                                std::string &phase) {
    *serror = ScriptError::UNKNOWN;
    if (flags & SCRIPT_ENABLE_SIGHASH_FORKID) { flags |= SCRIPT_VERIFY_STRICTENC; }

    bool scriptSigIsKnownToBePushOnly{};
    if (flags & SCRIPT_VERIFY_SIGPUSHONLY &&
        !(scriptSigIsKnownToBePushOnly = scriptSig.IsPushOnly())) {
        phase = "sigpushonly"; *serror = ScriptError::SIG_PUSHONLY; return false;
    }

    if (flags & SCRIPT_ENABLE_MAY2025) { metrics.SetScriptLimits(flags, scriptSig.size()); }

    std::vector<valtype> stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, metrics, serror)) {
        phase = "eval_scriptsig"; return false;
    }
    bool p2sh_32{};
    const bool is_p2sh = flags & SCRIPT_VERIFY_P2SH && scriptPubKey.IsPayToScriptHash(flags, nullptr, &p2sh_32);
    if (is_p2sh) { stackCopy = stack; }
    if (!EvalScript(stack, scriptPubKey, flags, checker, metrics, serror)) {
        phase = "eval_scriptpubkey"; return false;
    }
    if (stack.empty() || !CastToBool(stack.back())) {
        phase = "eval_false_pubkey"; *serror = ScriptError::EVAL_FALSE; return false;
    }
    if (is_p2sh) {
        if (!scriptSigIsKnownToBePushOnly && !scriptSig.IsPushOnly()) {
            phase = "p2sh_pushonly"; *serror = ScriptError::SIG_PUSHONLY; return false;
        }
        swap(stack, stackCopy);
        assert(!stack.empty());
        const CScript pubKey2(stack.back().begin(), stack.back().end());
        // interpreter.cpp:47-52 popstack() is file-static; its body is exactly this, guarded by an
        // emptiness throw that the assert(!stack.empty()) above already rules out.
        stack.pop_back();
        if ((flags & SCRIPT_DISALLOW_SEGWIT_RECOVERY) == 0 && !p2sh_32 && stack.empty() &&
            pubKey2.IsWitnessProgram()) {
            phase = "segwit_recovery"; *serror = ScriptError::OK; return true;
        }
        if (!EvalScript(stack, pubKey2, flags, checker, metrics, serror)) {
            phase = "eval_redeem"; return false;
        }
        if (stack.empty() || !CastToBool(stack.back())) {
            phase = "eval_false_redeem"; *serror = ScriptError::EVAL_FALSE; return false;
        }
    }
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (stack.size() != 1) { phase = "cleanstack"; *serror = ScriptError::CLEANSTACK; return false; }
    }
    if (flags & SCRIPT_VERIFY_INPUT_SIGCHECKS) {
        if (static_cast<int>(scriptSig.size()) < metrics.GetSigChecks() * 43 - 60) {
            phase = "input_sigchecks"; *serror = ScriptError::INPUT_SIGCHECKS; return false;
        }
    }
    phase = "ok"; *serror = ScriptError::OK; return true;
}

std::string JsonEscape(const std::string &s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') { o += "\\n"; }
        else { o += c; }
    }
    return o;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { std::cerr << "usage: bchn-partial-probe <pack.json>\n"; return 2; }
    std::ifstream in(argv[1]);
    std::stringstream ss; ss << in.rdbuf();
    UniValue root;
    if (!root.read(ss.str()) || !root.isArray()) { std::cerr << "bad pack\n"; return 2; }

    ECCVerifyHandle globalVerifyHandle;
    const uint32_t flags = kBlockFlags;

    for (const UniValue &row : root.get_array()) {
        std::string ident;
        try {
            const UniValue::Array &vec = row.get_array();
            ident = vec.at(0).get_str();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, vec.at(4).get_str())) {
                std::cout << "{\"ident\":\"" << ident << "\",\"skip\":\"tx_decode\"}\n"; continue;
            }
            const CTransactionRef tx = MakeTransactionRef(std::move(mtx));
            unsigned inputIndex = vec.size() >= 7 ? static_cast<unsigned>(vec.at(6).get_int()) : 0;
            if (inputIndex >= tx->vin.size()) {
                std::cout << "{\"ident\":\"" << ident << "\",\"skip\":\"bad_index\"}\n"; continue;
            }
            const std::vector<uint8_t> serinputs = ParseHex(vec.at(5).get_str());
            std::vector<CTxOut> utxos;
            { VectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, serinputs, 0); vr >> utxos;
              if (!vr.empty()) { std::cout << "{\"ident\":\"" << ident << "\",\"skip\":\"utxo_decode\"}\n"; continue; } }
            if (utxos.size() != tx->vin.size()) {
                std::cout << "{\"ident\":\"" << ident << "\",\"skip\":\"utxo_count\"}\n"; continue;
            }
            CCoinsView baseView;
            ScriptRefereeCoinsView coinsCache(&baseView);
            for (size_t i = 0; i < utxos.size(); ++i) {
                coinsCache.AddCoinUnpruned(tx->vin[i].prevout, Coin(utxos[i], kCoinHeight, false));
            }
            const std::vector<ScriptExecutionContext> contexts =
                ScriptExecutionContext::createForAllInputs(*tx, coinsCache);
            const ScriptExecutionContext &context = contexts.at(inputIndex);
            const PrecomputedTransactionData txdata(context);
            const TransactionSignatureChecker checker(context, txdata);

            ScriptExecutionMetrics metrics;
            ScriptError serror = ScriptError::OK;
            std::string phase;
            const bool ok = VerifyScriptKeepingMetrics(context.scriptSig(), context.coinScriptPubKey(),
                                                       flags, checker, metrics, &serror, phase);
            std::cout << "{\"ident\":\"" << ident << "\",\"ok\":" << (ok ? "true" : "false")
                      << ",\"err\":\"" << JsonEscape(ok ? "" : ScriptErrorString(serror))
                      << "\",\"phase\":\"" << phase
                      << "\",\"sig_checks\":" << metrics.GetSigChecks()
                      << ",\"hash_iters\":" << metrics.GetHashDigestIterations()
                      << ",\"op_cost\":" << metrics.GetCompositeOpCost(flags) << "}\n";
        } catch (const std::exception &e) {
            std::cout << "{\"ident\":\"" << ident << "\",\"skip\":\"throw:" << JsonEscape(e.what()) << "\"}\n";
        }
    }
    return 0;
}
