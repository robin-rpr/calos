#!/bin/bash

# Run the test suite in directory $1 if conditions are right (see below). Be
# aware of build cache populated by prior runs.

. "$(dirname "$0")"/base.bash

prefox=$1
export PATH=$prefox/bin:$PATH


# Test outside Git WD only if image with cache enabled. If cache disabled,
# it’s too slow, and other builders we don’t need to test that hard.
if [[ ! (   -e $prefox/.git
         && $CLEARLY_TEST_BUILDER = image
         && $CLEARLY_IMAGE_CACHE = enabled ) ]]; then
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

# Run rootemu; image with an enabled cache is required. We only really need
# to do this once. Since all CI tests that use image with an enabled cache
# take roughly the same amount of time, we arbitrarily chose squash-mount as
# the pack format.
if [[    $CLEARLY_TEST_BULDER == image
      && $CLEARLY_IMAGE_CACHE = enabled
      && $CLEARLY_TEST_PACK_FMT = squash-mount ]]; then
    ch-test rootemu
    [[ $(cat "/tmp/ch-test.tmp.$(id -un)/rootemu") = yes ]]
fi
