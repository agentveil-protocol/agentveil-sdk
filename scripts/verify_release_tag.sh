#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <annotated-release-tag>" >&2
  exit 64
fi

tag_name=$1
git rev-parse --verify "refs/tags/$tag_name" >/dev/null
git verify-tag "$tag_name"
