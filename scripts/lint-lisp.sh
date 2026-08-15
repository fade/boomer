#!/usr/bin/env bash
# lint-lisp.sh - run the mallet linter over this project's Lisp sources.
#
#   scripts/lint-lisp.sh              lint every tracked .lisp and .asd file
#   scripts/lint-lisp.sh --staged     lint only what is staged for commit
#   scripts/lint-lisp.sh <path>...    lint specific files or directories
#
# Exit 0 when nothing blocking was found, non-zero otherwise. Configuration is
# .mallet.lisp at the repository root.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Resolved by explicit path, never by PATH. A `mallet` on PATH is an unrelated
# topic-modelling toolkit of the same name: resolving by PATH would lint nothing
# and exit successfully, which reads as a clean run.
MALLET="${MALLET_BIN:-}"
if [ -z "$MALLET" ]; then
    for candidate in "$HOME/.local/share/mallet/mallet" \
                     "${LISP_WORKSPACE:-$HOME/SourceCode/lisp}/mallet/bin/mallet"; do
        [ -x "$candidate" ] && { MALLET=$candidate; break; }
    done
fi

# A missing linter must not block a commit: a fresh clone on a machine without
# the workspace checkout would otherwise be unable to commit at all. Say so on
# stderr and pass, so the absence is visible without being fatal.
if [ -z "$MALLET" ] || [ ! -x "$MALLET" ]; then
    printf 'lint-lisp: mallet not found; set MALLET_BIN or check it out under $LISP_WORKSPACE\n' >&2
    printf 'lint-lisp: skipping the Lisp lint for this run\n' >&2
    exit 0
fi

files=()
case "${1:-}" in
    --staged)
        # Added, copied or modified only: a staged deletion names a path that is
        # no longer on disk, and handing that to the linter is an error about
        # our own plumbing rather than about the code.
        while IFS= read -r f; do
            [ -n "$f" ] && [ -f "$ROOT/$f" ] && files+=("$ROOT/$f")
        done < <(git -C "$ROOT" diff --cached --name-only --diff-filter=ACM -- '*.lisp' '*.asd')
        ;;
    "")
        while IFS= read -r f; do
            [ -n "$f" ] && files+=("$ROOT/$f")
        done < <(git -C "$ROOT" ls-files -- '*.lisp' '*.asd')
        ;;
    *)
        files=("$@")
        ;;
esac

# Nothing to look at is a pass, not an error. This is the ordinary case for a
# commit that touches no Lisp.
if [ ${#files[@]} -eq 0 ]; then
    exit 0
fi

exec "$MALLET" --config "$ROOT/.mallet.lisp" --format line "${files[@]}"
