#!/usr/bin/env bash
set -o pipefail
set -eux

# only build on pull request
if [[ $GITHUB_EVENT_NAME == pull_request ]]; then
  # e.g. refs/pulls/1/merge -> refs-pulls-1-merge
  echo "::set-output name=tag::${GITHUB_REF//\//-}"
  echo "::set-output name=push::false"
  exit 0
fi

# push latest tag on master branch
if [[ $GITHUB_REF == refs/heads/master ]]; then
  echo "::set-output name=tag::latest"
  echo "::set-output name=push::true"
  exit 0
fi

# push the corresponding tag on tag push
if [[ $GITHUB_REF == refs/tags/* ]]; then
  echo "::set-output name=tag::${GITHUB_REF##*/}"
  echo "::set-output name=push::true"
  exit 0
fi

: unknown trigger
exit 1
