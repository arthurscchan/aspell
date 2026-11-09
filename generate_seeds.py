#!/usr/bin/env python3
"""Deterministic structured seed generator for the incumbent `aspell_fuzzer`.

The incumbent corpus exercises plain spelling documents with little
configuration variety; the public coverage report (20261108) shows the config
system (common/config.cpp, 309 dark lines), the filter chain construction
(lib/new_filter.cpp, 220 dark), encoding conversion (common/convert.cpp, 223
dark) and the suggestion tuning surface (suggest.cpp, 181 dark) largely dark.
Those paths are reachable from the harness's `key=value` configuration header.

This script emits structurally-valid inputs of the form

    key=value            (configuration lines; an empty line ends them)
    <document text>

covering the configuration dimensions (filters, modes, suggestion tuning,
encodings, languages) paired with documents shaped for each (URLs, TeX, SGML,
e-mail headers, markdown, accented text). Deterministic: no randomness, no
network, stable output ordering.
"""

import os
import sys

CORPUS_DIR = sys.argv[1] if len(sys.argv) > 1 else "aspell_fuzzer_corpus_config"

NL = chr(10)  # newline
BS = chr(92)  # backslash


SEEDS = [
    # --- filters: construction paths in lib/new_filter.cpp + modules/filter/* ---
    ("filter_url", "filter=url\n", "visit https://example.com/path?q=1 and http://10.0.0.1:8080/x#frag now"),
    ("filter_url_list", "filter=url\nurl-skip=www.bad.example\n", "see www.bad.example/page and https://ok.example zzz"),
    ("filter_email", "filter=email\n", "From: a@b.example\nTo: c@d.example\n\nplese fix the speling"),
    ("filter_tex", "filter=tex\n", "\\documentclass{article}\nbegin ${x+1} end $wurld$ \\TeXt{mispeled}"),
    ("filter_tex_commands", "filter=tex" + NL + "filter-command=" + BS + BS + NL,
             "doc with " + BS + "begin mispeled " + BS + "end wurld"),
    ("filter_sgml", "filter=sgml\n", "<html><body attr=\"mispeled value\">mispeled wurld</body></html>"),
    ("filter_sgml_attrs", "filter=sgml\nsgml-check-attr=c:class\nsgml-skip=p\n", "<p class=\"x\">mispeled</p> ok wurld"),
    ("filter_markdown", "filter=markdown\n", "# Headder\n*mispeled* and `wurld` [link](http://x.y) ok"),
    ("filter_two", "filter=url,sgml\n", "<a href=\"https://x.y/z\">mispeled</a> wurld"),
    ("filter_mode_url", "mode=url\n", "ftp://files.example.com/a.txt mispeled wurld"),
    ("filter_mode_email", "mode=email\n", "Subject: quik brown fox\n\nmispeled wurld here"),
    ("filter_mode_markdown", "mode=markdown\n", "## Sub *mispeled* _wurld_ ok"),
    ("filter_mode_none", "mode=none\n", "plain mispeled wurld with https://x.y inside"),
    ("filter_bad_then_ok", "filter=zzz\nfilter=url\n", "mispeled wurld https://x.y"),

    # --- suggestion tuning: suggest.cpp scoring paths ---
    ("sug_mode_ultra", "sug-mode=ultra\n", "mispeled wurld recieve seperate"),
    ("sug_mode_fast", "sug-mode=fast\n", "mispeled wurld recieve seperate"),
    ("sug_mode_normal", "sug-mode=normal\n", "mispeled wurld recieve seperate"),
    ("sug_mode_badspellers", "sug-mode=bad-spellers\n", "xyzzzy qqqq mispeled"),
    ("sug_edgedist", "sug-mode=normal\nsug-edit-dist=2\n", "mispeled qwert wurld"),
    ("sug_repl_table", "sug-mode=normal\n", "recieve:receive\nseperate:separate\n\nrecieve seperate mispeled"),

    # --- word handling: speller_impl state machine ---
    ("run_together", "run-together=true\n", "spellingerrors runtogetherwords everywhereplease"),
    ("run_together_min", "run-together=true\nrun-together-min=3\nrun-together-limit=4\n", "aa bbverylongruntogether mid dd"),
    ("camel_case", "camel-case=true\n", "CamelCaseWords MispeledWord ok"),
    ("ignore_case", "ignore-case=true\n", "MISPELED Wurld MiXeD ok"),
    ("ignore_accents", "ignore-accents=true\n", "cafe mispeled resumee"),
    ("ignore_repl", "ignore-repl=true\n", "mispeled wurld"),
    ("ignore_count", "ignore=3\n", "ab cde fgh ijkl mnopqrst mispeled"),

    # --- encodings / languages: convert.cpp + language selection ---
    ("enc_utf8", "encoding=utf-8\n", "café naïve résumé mispeled"),
    ("enc_iso", "encoding=iso-8859-1\n", "caf\xe9 na\xefve r\xe9sum\xe9 mispeled".encode("latin-1").decode("latin-1")),
    ("enc_none", "encoding=none\n", "plain ascii mispeled wurld"),
    ("lang_ptbr", "lang=pt_BR\n", "maçã correção errado mispeled"),
    ("lang_en_variant", "lang=en_GB\n", "colour centre realisation mispeled"),
    ("accents_stop", "stop-for-accents=true\nencoding=utf-8\n", "café mispeled naïve"),

    # --- document checker shapes: tokenizer + checker state ---
    ("doc_numbers", "", "test 123 45.67 1,000 mispeled wurld"),
    ("doc_apostrophes", "", "don't can't won't mispeled't wurld"),
    ("doc_punct", "", "(mispeled) [wurld] {ok} \"quoted\" 'single' — dash — ok"),
    ("doc_long_lines", "", ("mispeled " * 60).strip() + "\nwurld"),
    ("doc_empty", "", ""),

    # --- config edge shapes: config.cpp parsing paths ---
    ("cfg_unknown_keys", "zzz-unknown-key=1\nanother=vvv\n", "mispeled wurld"),
    ("cfg_empty_value", "encoding=\n", "mispeled wurld"),
    ("cfg_repeat_key", "sug-mode=fast\nsug-mode=ultra\n", "mispeled wurld"),
    ("cfg_spaces", "  filter = url  \n", "https://x.y mispeled"),
    ("cfg_bool_junk", "run-together=maybe\nignore-case=yes\n", "mispeled wurld"),
    ("cfg_int_junk", "ignore=xyz\nrun-together-limit=999\n", "mispeled wurld"),
    ("cfg_list_keys", "filter=url\ndict-alias=zz\nrem-filter=url\n", "mispeled wurld"),
]


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)
    for name, config, doc in SEEDS:
        data = config.encode("utf-8") + b"\n" + doc.encode("utf-8")
        with open(os.path.join(CORPUS_DIR, name), "wb") as f:
            f.write(data)
    print("generated %d seeds in %s" % (len(SEEDS), CORPUS_DIR))


if __name__ == "__main__":
    main()
