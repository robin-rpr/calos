# Source for CI shell scripts in this directory.

#shellcheck disable=SC2163  # we use export indirection in this file

# Print environment variables we care about. In CI we require that they are
# set; interactively, also set defaults.
vset () {
    name=$1
    def_value=$2
    printf '%-16s = ' "$name"
    if [[ ${!name} ]]; then
        export "$name"
        printf '%s (environment)\n' "${!name}"
    else
        [[ ${GITLAB_CI} ]]
        export "$name"="$def_value"
        printf '[35m%s (default)[0m\n' "${!name}"
    fi
}
vset  CH_TEST_BUILDER   image
vset  CH_IMAGE_CACHE    enabled
vset  CH_TEST_PACK_FMT  squash-mount
case $(uname -m) in
    x86_64)
        vset  ci_arch   amd64
        ;;
    aarch64)
        vset  ci_arch   arm64
        ;;
    *)
        false
        ;;
esac
vset  ci_distro         "$(sed -En 's/^ID=(.+)$/\1/p' < /etc/os-release)"
vset  cu_sudo           yes

# Replace “set -e” but with a nice colored error message on stdout.
_fatal () {
    cod=$?  # brittle: easy to overwrite $?
    echo "[35m$0: command failed with exit code $cod[0m"  # magenta
    exit $cod
}
trap _fatal ERR
set -E  # also run ERR trap in functions/subshells/etc.


# Replaces “set -x” with two key differences:
#
#   1. Print on stdout rather than stderr to keep everything in order in
#      GitLab log views.
#
#   2. Color the echoed command to make it stand out.
#
# NOTE: Bash calls the DEBUG trap multiple times for the same command under
# some circumstances [1]. This guarantees confusion. We avoid it by only
# printing the message if it’s different from last time.
#
# [1]: https://unix.stackexchange.com/questions/39623
_trace () {
    msg=$(printf "%3d¢ %s" "$1" "$BASH_COMMAND")
    if [[ $msg != "$_trace_last_msg" ]]; then
        echo "[36m$msg[0m"  # cyan
    fi
    declare -g _trace_last_msg=$msg
}
trap '_trace $LINENO' DEBUG


# Validate that $1 is present in config.log.
clrequire () {
    grep -Fq "$1" config.log
}
