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
sudo rm -Rf /ch
sudo mkdir /ch
sudo chmod 1777 /ch

# Build configure.
./autogen.sh

# Build and install from Git WD.
test/gitlab.com/install.bash . /ch/from-git

# Build and install from tarball.
mkdir /ch/src-tar
tar -C /ch/src-tar --strip=1 -xf charliecloud-*.tar.gz
test/gitlab.com/install.bash /ch/src-tar /ch/from-tar

# Run test suite in various directories. Note these all use the same storage
# directory, including build cache.
test/gitlab.com/test.bash .             # source dir, Git
test/gitlab.com/test.bash /ch/from-git  # installed from Git
test/gitlab.com/test.bash /ch/src-tar   # source dir, tarball
test/gitlab.com/test.bash /ch/from-tar  # installed from tarball
