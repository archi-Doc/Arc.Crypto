#!/bin/sh
set -eu
# Usage: check-glibc.sh <max-glibc-version> <objdump> <library>...
# Fails if `objdump -T` shows a GLIBC_ symbol version newer than <max-glibc-version> (e.g. 2.17).
if [ $# -lt 3 ]; then
  echo "usage: $0 <max-glibc-version> <objdump> <library>..." >&2
  exit 2
fi

MAX="$1"
OBJDUMP="$2"
shift 2

STATUS=0
for LIB in "$@"; do
  SYMBOLS=$("$OBJDUMP" -T "$LIB")
  VERSIONS=$(printf '%s\n' "$SYMBOLS" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -uV || true)
  if [ -z "$VERSIONS" ]; then
    # A glibc build always has versioned symbols; none means objdump could not read the file.
    echo "$LIB: no GLIBC_ symbol versions found" >&2
    STATUS=1
    continue
  fi

  echo "$LIB: needs GLIBC" $VERSIONS
  for VERSION in $VERSIONS; do
    if [ "$(printf '%s\n%s\n' "$MAX" "$VERSION" | sort -V | tail -n 1)" != "$MAX" ]; then
      echo "$LIB: GLIBC_$VERSION is newer than GLIBC_$MAX:" >&2
      printf '%s\n' "$SYMBOLS" | grep -E "GLIBC_$(printf '%s' "$VERSION" | sed 's/\./\./g')([^.0-9]|\$)" >&2 || true
      STATUS=1
    fi
  done
done

exit $STATUS
