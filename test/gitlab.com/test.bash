#!/bin/bash

# Run the test suite in directory $1 if conditions are right (see below). Be
# aware of build cache populated by prior runs.

. "$(dirname "$0")"/base.bash

prefox=$1
export PATH=$prefox/bin:$PATH


# Test outside Git WD only if ch-image with cache enabled. If cache disabled,
# it’s too slow, and other builders we don’t need to test that hard.
if [[ ! (   -e $prefox/.git
         && $CH_TEST_BUILDER = ch-image
         && $CH_IMAGE_CACHE = enabled ) ]]; then
    exit 0
fi

# Validate configuration.
ch-test --is-pedantic all
if [[ -n $ci_sudo ]]; then
    ch-test --is-sudo all
fi

# Run test suite.
ch-test all
# Validate “rootemu” didn’t run (skipped by default in standard scope).
[[ $(cat "/tmp/ch-test.tmp.$(id -un)/rootemu") = no ]]

# Run rootemu; ch-image with an enabled cache is required. We only really need
# to do this once. Since all CI tests that use ch-image with an enabled cache
# take roughly the same amount of time, we arbitrarily chose squash-mount as
# the pack format.
if [[    $CH_TEST_BULDER == ch-image
      && $CH_IMAGE_CACHE = enabled
      && $CH_TEST_PACK_FMT = squash-mount ]]; then
    ch-test rootemu
    [[ $(cat "/tmp/ch-test.tmp.$(id -un)/rootemu") = yes ]]
fi
