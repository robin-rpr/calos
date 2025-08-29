#!/bin/bash

# Build the Clearly source code in $1, install it to prefix $2, and do
# some basic validations.


. "$(dirname "$0")"/base.bash

prefox=$(realpath "$2")  # I like this typo and rolling with it. 😂
cd "$1" || exit 1        # satisfy ShellCheck


# Configure.

if [[ $CLEARLY_TEST_PACK_FMT = squash-mount ]]; then
    libsquashfuse=yes
else
    libsquashfuse=no
fi

./configure --prefix="$prefox" --with-libsquashfuse=$libsquashfuse


# Validate configure output.

clrequire 'documentation: yes'

if [[ $CLEARLY_TEST_BUILDER = image ]]; then
    clrequire 'with image(1): yes'
fi

clrequire 'recommended tests, tar-unpack mode: yes'
clrequire 'recommended tests, squash-unpack mode: yes'

if [[ $CLEARLY_TEST_PACK_FMT = squash-mount ]]; then
    clrequire 'recommended tests, squash-mount mode: yes'
    clrequire 'internal SquashFS mounting ... yes'
else
    clrequire 'recommended tests, squash-mount mode: no'
    clrequire 'internal SquashFS mounting ... no'
fi

if [[ $CLEARLY_TEST_BUILDER = image ]]; then
    clrequire '"lark" module ... bundled'
    test -f ./lib/lark/lark.py
fi


# Build.
make -j"$(nproc)"
ldd cmd/run
cmd/run --version

# Make tarball.
rm -f clearly-*.tar.gz
make dist
ls -lh clearly-*.tar.gz

# Install.
sudo make install
echo "$prefox"
ldd "$prefox"/cmd/run
"$prefox"/cmd/run --version
