#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "Entering directory '$PWD'"
set -x
git="$(git describe --tags --always --dirty || true)"
clang \
    -Wall -Wextra -pedantic -std=gnu99 -fsanitize=address \
    -D PROGGIT="\"$git\"" \
    -o git2tar git2tar.c
