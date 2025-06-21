#!/bin/bash

set -e

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --clean)
            clean=yes
            ;;
        *)
            help=yes
            ;;
    esac
    shift
done

if [[ $help ]]; then
    cat <<EOF
Usage:

  $ ./autogen.sh [OPTIONS]

Remove and rebuild Autotools files (./configure and friends). This script is
intended for developers; end users typically do not need it.

Options:

  --clean    remove only; do not rebuild
  --help     print this help and exit

EOF
    exit 0
fi

cat <<EOF
Removing and (maybe) rebuilding "configure" and friends.

NOTE 1: This script is intended for developers. End users typically do not
        need it.

NOTE 2: Incomprehensible error messages about undefined macros can appear
        below. This is usually caused by missing Autotools components.

See the install instructions for details on both.

EOF

cd "$(dirname "$0")"
set -x

# Remove all derived files if we can. Note that if you enabled maintainer mode
# in configure, this will run configure before cleaning.
[[ -f Makefile ]] && make maintainer-clean
# "maintainer-clean" target doesn't remove configure and its dependencies,
# apparently by design [1], so delete those manually.
#
# [1]: https://www.gnu.org/prep/standards/html_node/Standard-Targets.html
rm -Rf Makefile.in \
       ./*/Makefile.in \
       aclocal.m4 \
       cmd/config.h.in \
       build-aux \
       configure

# Install Python dependencies
pip3 install -r requirements.txt

# Create configure and friends.
if [[ -z $clean ]]; then
    autoreconf --force --install -Wall -Werror
    set +x
    echo
    echo 'Done. Now you can "./configure".'
    echo 'Note: You may need to install Python dependencies with: make install-deps'
fi

