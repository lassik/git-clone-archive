#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "Entering directory '$PWD'"
set -x
git="$(git describe --tags --always --dirty 2>/dev/null || true)"
cc \
    -Wall -Wextra -pedantic -std=gnu99 -fsanitize=address -Og -g \
    -D PROGGIT="\"$git\"" \
    -o git-clone-archive git-clone-archive.c
