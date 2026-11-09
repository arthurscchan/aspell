/*
 * fuzz_word_lists — exercise the writable word-list file parsers and the
 * writable-list mutation API of libaspell.
 *
 * Threat model
 * ============
 * Untrusted input: personal word-list files (`.pws`) and replacement-list
 * files (`.prepl`). These files are routinely shared, synced between
 * machines, downloaded, or planted by an attacker in a profile directory;
 * applications additionally let users point the `personal` / `repl` config
 * keys at arbitrary paths. The bytes cross the trust boundary in
 * `WritableBase::load` (writable.cpp), which dispatches on a magic header
 * line and drives `WritableDict::merge` / `WritableReplDict::merge` —
 * hand-rolled text parsers with header field handling, `\`-escape decoding,
 * per-line conversion through arbitrary encodings, hash-table insertion
 * (vector_hash), and a save/round-trip encoder (`WritableDict::save`,
 * `WritableReplDict::save`). The mutation API (`aspell_speller_add_to_personal`,
 * `aspell_speller_add_to_session`, `aspell_speller_store_replacement`) feeds
 * further attacker-controlled words through the same conversion and storage
 * machinery.
 *
 * What counts as a real bug here: any sanitizer finding (OOB read/write,
 * overflow, use-after-free, leak, double free) reachable from the file bytes
 * or the mutation API. The harness always installs attacker-controlled bytes
 * as the fixture files, so any parse-reachable defect is in scope.
 *
 * Known upstream findings and routing (see findings/aspell-word-lists/):
 *  - aspell-1 (CWE-401 leak): SpellerImpl::setup (speller_impl.cpp:611/631,
 *    `use-other-dicts`, aspell's default) leaks the temporary writable dict
 *    whenever WritableBase::load fails; only the header magic token and the
 *    lang name can make the load fail (encoding errors are swallowed inside
 *    merge). Route: fixture files whose first line does not carry a valid
 *    magic + known lang are replaced by a minimal valid file, so the error
 *    return leak is not retriggered while everything after the header line
 *    stays fully attacker-controlled.
 *  - aspell-2 (CWE-476 null deref): WritableReplDict::merge v10 branch
 *    (writable.cpp:947) calls FStream::skipws on a null FILE*. Route: the
 *    legacy `personal_repl` (v10) magic is not accepted as a fixture header;
 *    the current `personal_repl-1.1` (v11) format stays fuzzed.
 *  - aspell-3 (abort, CWE-755): WritableDict::merge / WritableReplDict::merge
 *    discard the PosibErr returned by set_file_encoding (writable.cpp:565-568
 *    and :920-924); an unknown encoding name in the header therefore aborts
 *    in assertion builds ("Unhandled Error ... abort") instead of failing
 *    gracefully. Route: the header's encoding token is kept only when it
 *    names an encoding aspell actually ships; unknown tokens are dropped
 *    (the parser ignores the rest of the line, so this is coverage-neutral).
 *  - aspell-4 (CWE-476 SEGV): a speller whose only dictionary is a replacement
 *    dict has an empty check_ws list and SpellerImpl::check_simple (line 146)
 *    dereferences the end iterator of its do-while loop. Route: replacement
 *    dict masters (personal_repl-1.1 magic) are created parse-only.
 *  - aspell-5 (CWE-401 leak): a replacement dict loaded through the master
 *    path (add_data_set, DT_WritableRepl) leaks its dictionary object. Route:
 *    replacement-list master fixtures are not installed here at all; that
 *    surface belongs to the dict-files pair, which classifies and routes it.
 *  All findings remain detectable and reproducible standalone; this routing
 *  only stops re-triggering known defects so the rest of the surface can be
 *  fuzzed (no sanitizer muting, no suppressions).
 *
 * Input layout (sections separated by NUL bytes):
 *   [personal word-list file bytes] NUL [replacement-list file bytes] NUL [document]
 *
 * The harness writes the first two sections to fixed fixture paths, points
 * `personal-path` / `repl-path` at them (`use-other-dicts=true`, aspell's
 * default), and lets speller creation parse both files. It then drives the
 * writable lifecycle: add-to-personal/session, store-replacement, word-list
 * enumeration, save-all (encoder side), clears the session, tears the speller
 * down and creates a second one over the just-saved files (deterministic
 * in-iteration round-trip through the encoders and parsers), finally running
 * a document check + suggest loop like the incumbent aspell_fuzzer.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <aspell.h>
#include <algorithm>
#include <string>
#include <vector>

static int enable_diags;
static char data_dir[1024];
static char fixture_dir[256];
static char personal_path[512];
static char repl_path[512];
static char master_a_path[512];
static char master_b_path[512];

#define FUZZ_DEBUG(FMT, ...)                                                  \
        if (enable_diags) {                                                   \
          fprintf(stderr, FMT, ##__VA_ARGS__);                                \
          fprintf(stderr, "\n");                                              \
        }

// Bound the fixture files and the API-driving token sweep so that a single
// input cannot turn into pathological work (the parsers and suggest engine
// are the target, not throughput).
static const size_t MAX_FILE_SECTION = 256 * 1024;
static const size_t MAX_TOKENS = 16;
static const size_t MAX_TOKEN_LEN = 128;
static const size_t MAX_MISSPELLINGS = 64;

// True when the bytes carry the `personal_repl-1.1` magic: as a master file
// this loads as a replacement dict, whose speller has an empty check_ws
// list — SpellerImpl::check_simple then dereferences the end iterator
// (finding aspell-4). Such spellers are created parse-only.
static bool replacement_dict_master(const uint8_t *data, size_t len) {
  static const char MAGIC[] = "personal_repl-1.1";
  size_t mlen = sizeof(MAGIC) - 1;
  return len >= mlen && memcmp(data, MAGIC, mlen) == 0;
}

// Minimal, always-valid word-list files: used for the lifecycle speller's
// fixed fixtures and as the replacement for routed master fixtures.
static const char FALLBACK_PERSONAL[] = "personal_ws-1.1 en 1 UTF-8\nzzfuzz\n";
static const char FALLBACK_REPL[] = "personal_repl-1.1 en 0 UTF-8\nmis fix\n";
static const char FALLBACK_MASTER[] = "personal_ws-1.1 en 1 UTF-8\nzzfuzz\n";

// On startup, this function is called once. Use it to access argv.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  char *argv0_copy = strdup((*argv)[0]);

  // Create the data dir (dictionaries are installed next to the binary).
  snprintf(data_dir, sizeof(data_dir), "%s/dict", dirname(argv0_copy));

  // Create the fixture dir for the attacker-controlled word-list files.
  snprintf(fixture_dir, sizeof(fixture_dir), "/tmp/aspell_fuzz_word_lists");
  mkdir(fixture_dir, 0700); // EEXIST is fine
  snprintf(personal_path, sizeof(personal_path), "%s/personal", fixture_dir);
  snprintf(repl_path, sizeof(repl_path), "%s/repl", fixture_dir);
  snprintf(master_a_path, sizeof(master_a_path), "%s/master_a", fixture_dir);
  snprintf(master_b_path, sizeof(master_b_path), "%s/master_b", fixture_dir);

  // Fixed, always-valid fixtures for the lifecycle speller (personal_/repl_
  // attach through the use-other-dicts branch, whose load-error path leaks
  // — finding aspell-1 — so attacker bytes never go through it).
  {
    FILE *f = fopen(personal_path, "wb");
    if (f) { fwrite(FALLBACK_PERSONAL, 1, sizeof(FALLBACK_PERSONAL) - 1, f); fclose(f); }
    f = fopen(repl_path, "wb");
    if (f) { fwrite(FALLBACK_REPL, 1, sizeof(FALLBACK_REPL) - 1, f); fclose(f); }
  }

  // Free off the temporary variable.
  free(argv0_copy);

  printf("Init: data-dir: %s; fixture-dir: %s\n", data_dir, fixture_dir);

  return 0;
}

static void write_fixture(const char *path, const uint8_t *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    return; // speller creation will surface the error path
  }
  if (len != 0) {
    fwrite(data, 1, len, f);
  }
  fclose(f);
}

// Header policy for the known-finding routing (see the header comment):
// the first line must start with one of the allowed magics and carry a
// second field that is a lang name aspell can resolve; an encoding field is
// kept only when it names an encoding aspell actually ships (an unknown name
// makes set_file_encoding fail, and merge discards that PosibErr, which
// aborts in assertion builds — finding aspell-3). Bytes after the first
// line are always preserved verbatim. Returns false when the whole file
// must be replaced by the fallback (bad magic or lang).
//
// Encodings shipped by aspell's data package / recognised via
// fix_encoding_str (common/convert.cpp:936):
static const char *const KNOWN_ENCODINGS[] = {
    "utf-8", "utf-16", "utf-32",
    "iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5",
    "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10",
    "iso-8859-11", "iso-8859-13", "iso-8859-14", "iso-8859-15",
    "iso-8859-16", "koi8-r", "koi8-u",
    "cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256",
    "cp1257", "cp1258",
    "ucs-2", "ucs-4", "us-ascii", "ascii", "ansi_x3.4-1968",
    "machine unsigned 16", "machine unsigned 32"};

static bool known_encoding(const uint8_t *s, size_t n) {
  for (unsigned i = 0; i < sizeof(KNOWN_ENCODINGS) / sizeof(KNOWN_ENCODINGS[0]);
       ++i) {
    if (strlen(KNOWN_ENCODINGS[i]) == n &&
        memcmp(s, KNOWN_ENCODINGS[i], n) == 0) {
      return true;
    }
  }
  return false;
}

// Master-path fixture routing (findings aspell-2 and aspell-3; the master
// path frees load errors through the StackPtr owner, so aspell-1's leak does
// not apply here). Returns false when the caller must install FALLBACK_MASTER.
// `out` always receives the bytes to install otherwise.
static bool master_fixture(const uint8_t *data, size_t len,
                           std::vector<uint8_t> *out) {
  static const char REPL_PREFIX[] = "personal_repl";
  static const char *const TEXT_MAGICS[] = {
      "personal_ws-1.1", "personal_wl"};
  size_t repl_len_prefix = sizeof(REPL_PREFIX) - 1;
  if (len >= repl_len_prefix &&
      memcmp(data, REPL_PREFIX, repl_len_prefix) == 0) {
    // add_data_set sniffs ANY leading `personal_repl` prefix as a replacement
    // dict master, and that surface is defective upstream: aspell-2 (v10
    // parse null deref), aspell-5 (leak on successful load), aspell-6 (dtor
    // null deref on failed load — including junk-suffix magics like
    // `personal_replXYZ`). Route every such fixture to the fallback.
    return false;
  }
  int magic = -1;
  for (unsigned mi = 0; mi < sizeof(TEXT_MAGICS) / sizeof(TEXT_MAGICS[0]);
       ++mi) {
    size_t ml = strlen(TEXT_MAGICS[mi]);
    if (len >= ml && memcmp(data, TEXT_MAGICS[mi], ml) == 0) {
      magic = mi;
      break;
    }
  }
  if (magic < 0) {
    // readonly binary, multi/alias, or garbage: no file-encoding surface
    out->assign(data, data + len);
    return true;
  }
  // Writable text header: drop unknown encoding tokens (aspell-3 abort route).
  size_t line_len = 0;
  while (line_len < len && data[line_len] != '\n') ++line_len;
  size_t ts[5], tl[5];
  unsigned nt = 0;
  size_t i = 0;
  while (i < line_len && nt < 5) {
    while (i < line_len && (data[i] == ' ' || data[i] == '\t')) ++i;
    if (i >= line_len) break;
    ts[nt] = i;
    while (i < line_len && data[i] != ' ' && data[i] != '\t') ++i;
    tl[nt] = i - ts[nt];
    ++nt;
  }
  if (nt < 4 || known_encoding(data + ts[3], tl[3])) {
    out->assign(data, data + len);
    return true;
  }
  out->clear();
  out->insert(out->end(), data, data + ts[2] + tl[2]);
  out->push_back('\n');
  if (line_len < len) {
    out->insert(out->end(), data + line_len + 1, data + len);
  }
  return true;
}

// Split the document into alphanumeric tokens for the mutation API. Returns
// at most MAX_TOKENS tokens of length in [1, MAX_TOKEN_LEN].
static std::vector<std::string> split_tokens(const char *doc, size_t len) {
  std::vector<std::string> tokens;
  size_t i = 0;
  while (i < len && tokens.size() < MAX_TOKENS) {
    while (i < len && !isalnum((unsigned char)doc[i])) {
      ++i;
    }
    size_t start = i;
    while (i < len && isalnum((unsigned char)doc[i]) && i - start < MAX_TOKEN_LEN) {
      ++i;
    }
    if (i > start) {
      tokens.push_back(std::string(doc + start, i - start));
    }
  }
  return tokens;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  // Enable or disable diagnostics based on the FUZZ_VERBOSE environment flag.
  enable_diags = (getenv("FUZZ_VERBOSE") != NULL);

  // Split the input into its NUL-separated sections.
  const uint8_t *nul1 = (const uint8_t *)memchr(data, '\0', size);
  size_t personal_len = (nul1 != NULL) ? (size_t)(nul1 - data) : size;
  if (personal_len > MAX_FILE_SECTION) {
    personal_len = MAX_FILE_SECTION;
  }
  const uint8_t *repl_data = (nul1 != NULL) ? nul1 + 1 : data + size;
  size_t repl_avail = (nul1 != NULL) ? size - personal_len - 1 : 0;
  const uint8_t *nul2 = (const uint8_t *)memchr(repl_data, '\0', repl_avail);
  size_t repl_len = (nul2 != NULL) ? (size_t)(nul2 - repl_data) : repl_avail;
  if (repl_len > MAX_FILE_SECTION) {
    repl_len = MAX_FILE_SECTION;
  }
  const uint8_t *doc_data = (nul2 != NULL) ? nul2 + 1 : repl_data + repl_len;
  size_t doc_len = (nul2 != NULL) ? (size_t)(size - (doc_data - data)) : 0;

  std::vector<std::string> tokens = split_tokens(
      reinterpret_cast<const char *>(doc_data),
      std::min(doc_len, 8 * MAX_TOKEN_LEN * MAX_TOKENS));
  // Guarantee that the lifecycle ops always have words to work with.
  while (tokens.size() < 2) {
    tokens.push_back(std::string("zzfuzz") + std::to_string(tokens.size()));
  }

  // Install the attacker-controlled bytes as master fixtures, with the
  // known-finding routing (aspell-2, aspell-3). The master path parses
  // through add_data_set -> WritableBase/ReadOnlyDict load whose errors are
  // freed by the StackPtr owner, so malformed files cannot leak here.
  // The repl-section bytes are intentionally NOT master-fuzzed here: a
  // replacement dict loaded through the master path leaks its dictionary
  // (finding aspell-5, documented with reproducer). That surface belongs to
  // the dict-files pair, which classifies and routes it separately.
  std::vector<uint8_t> fixture_a;
  const char *fallback_a =
      master_fixture(data, personal_len, &fixture_a)
          ? NULL : FALLBACK_MASTER;
  if (fallback_a != NULL) {
    write_fixture(master_a_path,
                  reinterpret_cast<const uint8_t *>(fallback_a),
                  strlen(fallback_a));
  } else {
    write_fixture(master_a_path, fixture_a.data(), fixture_a.size());
  }

  AspellCanHaveError *possible_err = NULL;
  AspellSpeller *speller = NULL;
  AspellConfig *config = NULL;
  AspellDocumentChecker *doc_checker = NULL;
  AspellCanHaveError *doc_err = NULL;
  AspellToken token;
  AspellStringEnumeration *els = NULL;
  size_t misspellings = 0;

  // --- Speller A: parse the personal-section bytes through the master path.
  config = new_aspell_config();
  aspell_config_replace(config, "use-other-dicts", "false");
  aspell_config_replace(config, "master-path", master_a_path);
  aspell_config_replace(config, "data-dir", data_dir);
  possible_err = new_aspell_speller(config);
  if (aspell_error_number(possible_err) != 0) {
    FUZZ_DEBUG("speller A failed: %s", aspell_error_message(possible_err));
    delete_aspell_can_have_error(possible_err);
    possible_err = NULL;
  } else if (!replacement_dict_master(data, personal_len)) {
    // Replacement-dict masters are created parse-only: their speller has an
    // empty check_ws list and check_simple dereferences the end iterator
    // (finding aspell-4).
    speller = to_aspell_speller(possible_err);
    possible_err = NULL; // consumed by to_aspell_speller
    doc_err = new_aspell_document_checker(speller);
    if (aspell_error(doc_err) == 0) {
      doc_checker = to_aspell_document_checker(doc_err);
      doc_err = NULL; // consumed by to_aspell_document_checker
      aspell_document_checker_process(doc_checker,
                                      reinterpret_cast<const char *>(doc_data),
                                      (int)doc_len);
      misspellings = 0;
      for (token = aspell_document_checker_next_misspelling(doc_checker);
           token.len != 0 && misspellings < MAX_MISSPELLINGS;
           token = aspell_document_checker_next_misspelling(doc_checker)) {
        ++misspellings;
        aspell_speller_check(speller,
                             reinterpret_cast<const char *>(doc_data) + token.offset,
                             token.len);
      }
      delete_aspell_document_checker(doc_checker);
      doc_checker = NULL;
    } else {
      delete_aspell_can_have_error(doc_err);
    }
    doc_err = NULL;
    delete_aspell_speller(speller);
    speller = NULL;
  }
  delete_aspell_config(config);
  config = NULL;

  // --- Speller C: the writable lifecycle. personal_/repl_ attach through the
  // use-other-dicts branch from the fixed safe fixtures (the attacker bytes
  // never go through this branch: its load-error path leaks — aspell-1).
  config = new_aspell_config();
  aspell_config_replace(config, "use-other-dicts", "true");
  aspell_config_replace(config, "personal-path", personal_path);
  aspell_config_replace(config, "repl-path", repl_path);
  aspell_config_replace(config, "data-dir", data_dir);
  possible_err = new_aspell_speller(config);
  if (aspell_error_number(possible_err) != 0) {
    FUZZ_DEBUG("speller C failed: %s", aspell_error_message(possible_err));
    delete_aspell_can_have_error(possible_err);
    possible_err = NULL;
  } else {
    speller = to_aspell_speller(possible_err);
    possible_err = NULL; // consumed by to_aspell_speller
    // Drive the writable lifecycle with attacker-controlled words.
    aspell_speller_add_to_personal(speller, tokens[0].c_str(), -1);
    aspell_speller_add_to_session(speller, tokens[1].c_str(), -1);
    aspell_speller_store_replacement(speller, tokens[0].c_str(), -1,
                                     tokens[1].c_str(), -1);
    els = aspell_word_list_elements(
        aspell_speller_personal_word_list(speller));
    for (const char *word = aspell_string_enumeration_next(els);
         word != 0;
         word = aspell_string_enumeration_next(els)) {
      FUZZ_DEBUG("personal entry: %s", word);
    }
    delete_aspell_string_enumeration(els);
    els = NULL;
    els = aspell_word_list_elements(
        aspell_speller_session_word_list(speller));
    for (const char *word = aspell_string_enumeration_next(els);
         word != 0;
         word = aspell_string_enumeration_next(els)) {
      FUZZ_DEBUG("session entry: %s", word);
    }
    delete_aspell_string_enumeration(els);
    els = NULL;
    // Encoder side, then clear the session.
    aspell_speller_save_all_word_lists(speller);
    aspell_speller_clear_session(speller);
    delete_aspell_speller(speller);
    speller = NULL;
  }

  // --- Speller D: round-trip over the just-saved files (encoder output is
  // re-parsed, now carrying attacker-influenced words).
  possible_err = new_aspell_speller(config);
  if (aspell_error_number(possible_err) != 0) {
    FUZZ_DEBUG("speller D failed: %s", aspell_error_message(possible_err));
    delete_aspell_can_have_error(possible_err);
    possible_err = NULL;
  } else {
    speller = to_aspell_speller(possible_err);
    possible_err = NULL; // consumed by to_aspell_speller
    doc_err = new_aspell_document_checker(speller);
    if (aspell_error(doc_err) == 0) {
      doc_checker = to_aspell_document_checker(doc_err);
      doc_err = NULL; // consumed by to_aspell_document_checker
      aspell_document_checker_process(doc_checker,
                                      reinterpret_cast<const char *>(doc_data),
                                      (int)doc_len);
      misspellings = 0;
      for (token = aspell_document_checker_next_misspelling(doc_checker);
           token.len != 0 && misspellings < MAX_MISSPELLINGS;
           token = aspell_document_checker_next_misspelling(doc_checker)) {
        ++misspellings;
        auto word_list = aspell_speller_suggest(
            speller,
            reinterpret_cast<const char *>(doc_data) + token.offset,
            token.len);
        els = aspell_word_list_elements(word_list);
        for (const char *word = aspell_string_enumeration_next(els);
             word != 0;
             word = aspell_string_enumeration_next(els)) {
          FUZZ_DEBUG("D suggestion: %s", word);
        }
        delete_aspell_string_enumeration(els);
        els = NULL;
      }
      delete_aspell_document_checker(doc_checker);
      doc_checker = NULL;
    } else {
      delete_aspell_can_have_error(doc_err);
    }
    doc_err = NULL;
    delete_aspell_speller(speller);
    speller = NULL;
  }
  delete_aspell_config(config);
  config = NULL;

EXIT_LABEL:

  if (els != NULL) {
    delete_aspell_string_enumeration(els);
  }
  if (doc_checker != NULL) {
    delete_aspell_document_checker(doc_checker);
  }
  if (speller != NULL) {
    delete_aspell_speller(speller);
  }
  if (possible_err != NULL) {
    delete_aspell_can_have_error(possible_err);
  }
  if (config != NULL) {
    delete_aspell_config(config);
  }

  return 0;
}

