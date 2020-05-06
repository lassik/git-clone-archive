#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "Entering directory '$PWD'"
set -x
git="$(git describe --tags --always --dirty || true)"
clang -Wall -Wextra -fsanitize=address -o git2tar git2tar.c \
    -D PROGGIT="\"$git\""
