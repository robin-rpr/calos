#!/bin/bash

# Contents of the “test” job. This is a shell script so that it can be run
# interactively as well. Importantly, it must not assume a clean starting
# point (i.e., it might have ben run before in the same container) nor break
# the container for future runs (e.g. by deleting automake/autoconf).

. "$(dirname "$0")"/base.bash

# List proxy configuration.
env | grep -Ei '_proxy$' | sort

# Directory setup. Use /mnt because in gitlab.com CI that’s a big tmpfs.
df -h
export CLEARLY_IMAGE_STORAGE=/mnt/storage
export CLEARLY_TEST_IMGDIR=/mnt/img
export CLEARLY_TEST_TARDIR=/mnt/pack

# Target directory.
sudo rm -Rf /clearly
sudo mkdir /clearly
sudo chmod 1777 /clearly

# Build configure.
./autogen.sh

# Build and install from Git WD.
test/ci/install.bash . /clearly/from-git

# Build and install from tarball.
mkdir /clearly/src-tar
tar -C /clearly/src-tar --strip=1 -xf charliecloud-*.tar.gz
test/ci/install.bash /clearly/src-tar /clearly/from-tar

# Run test suite in various directories. Note these all use the same storage
# directory, including build cache.
test/ci/test.bash .             # source dir, Git
test/ci/test.bash /clearly/from-git  # installed from Git
test/ci/test.bash /clearly/src-tar   # source dir, tarball
test/ci/test.bash /clearly/from-tar  # installed from tarball
