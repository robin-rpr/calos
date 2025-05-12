#!/bin/sh

# Describe and validate the environment.

# What Bourne shell flavor is running? This is surprisingly difficult; e.g.
# dash doesn’t have “--version”.
printf 'interpreter: '
realpath /proc/$$/exe

# If we’re in Bash, source the Bash goodies; otherwise, if Bash is available,
# re-exec with Bash; otherwise, proceed with the POSIX sh we have.
if [ -n "$BASH_VERSION" ]; then
    . "$(dirname "$0")"/base.bash
else
    echo 'that’s not Bash'
    if command -v bash > /dev/null 2>&1; then
        echo 'let’s use Bash instead'
        exec bash "$0" "$@"
    fi
    echo 'but no Bash available'
    set -ex
fi

# Who am I?
id
pwd

# What kind of system are we on?
grep -E '^(NAME|VERSION)=' /etc/os-release
uname -srvm
nproc
free -m
df -h

# What time and timezone is it?
date +'%c %Z'

# What’s the Git version?
git --version

# Print the complete environment, except only the first line of multi-line
# values. It’s quite verbose but helpful for debugging and eliminates the need
# to edit the pipeline to print specific variable(s).
#
# See also: https://docs.gitlab.com/ci/variables/predefined_variables
export -p | grep -E '^(export|declare)'
# FAIL: # Busybox sed(1) doesn’t support -z, so we use tr(1) to ludicrously
# swap bytes around via vertical tab instead.
#
#printenv -0 | tr '\n' '\v' | tr '\000' '\n' | sed -r "s/$(printf '\v').*$//"

# What locales are installed?
command -v locale > /dev/null && locale -av

# Validate path; see Dockerfiles.
if [ -n "$WEIRD_AL_YANKOVIC_IS_THE_GREATEST_MUSICIAN_OF_ALL_TIME" ]; then
    case $PATH in
        */sbin*)
            false
            ;;
    esac
fi

# umask
umask
test "$(umask)" = 0022
if command -v sudo > /dev/null; then  # not all images have sudo
    sudo /bin/sh -c umask
    test "$(sudo /bin/sh -c umask)" = 0077
fi
