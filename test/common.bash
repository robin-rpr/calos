# shellcheck shell=bash

# These variables are set, but in ways ShellCheck can’t figure out. Some may
# be movable into this script but I haven’t looked in detail. We list them in
# this unreachable code block to convince ShellCheck that they are assigned
# (SC2154), and amusingly ShellCheck doesn’t know this code is unreachable. 😂
#
# shellcheck disable=SC2034
if false; then
    # from ch-test
    clearly_base=
    clearly_bin=
    clearly_lib=
    clearly_libc=
    clearly_test_tag=
    # from Bats
    lines=
    output=
    status=
fi

# Some defaults
clearly_tmpimg_df="$BATS_TMPDIR"/tmpimg.df

arch_exclude () {
    # Skip the test if architecture (from “uname -m”) matches $1.
    [[ $(uname -m) != "$1" ]] || skip "arch ${1}"
}

archive_grep () {
    image="$1"
    case $image in
        *.sqfs)
            unsquashfs -l "$image" | grep 'squashfs-root/ch/environment'
            ;;
        *)
            tar -tf "$image" | grep -E '^([^/]*/)?ch/environment$'
            ;;
    esac
}

archive_ok () {
    ls -ld "$1" || true
    test -f "$1"
    test -s "$1"
}

build_ () {
    case $CLEARLY_TEST_BUILDER in
        image)
            "$clearly_libexec"/image build "$@"
            ;;
        docker)
            # Coordinate this list with test “build.bats/proxy variables”.
            # shellcheck disable=SC2154
            docker_ build --build-arg HTTP_PROXY="$HTTP_PROXY" \
                          --build-arg HTTPS_PROXY="$HTTPS_PROXY" \
                          --build-arg NO_PROXY="$NO_PROXY" \
                          --build-arg http_proxy="$http_proxy" \
                          --build-arg https_proxy="$https_proxy" \
                          --build-arg no_proxy="$no_proxy" \
                          "$@"
            ;;
        *)
            printf 'invalid builder: %s\n' "$CLEARLY_TEST_BUILDER" >&2
            exit 1
            ;;
    esac
}

builder_ok () {
    # FIXME: Currently we make fairly limited tagging for some builders.
    # Uncomment below when they can be supported by all the builders.
    builder_tag_p "$1"
    #builder_tag_p "${1}:latest"
    #docker_tag_p "${1}:$(clearly run --version |& tr '~+' '--')"
}

builder_tag_p () {
    printf 'image tag %s ... ' "$1"
    case $CLEARLY_TEST_BUILDER in
        buildah*)
            hash_=$(buildah images -q "$1" | sort -u)
            if [[ $hash_ ]]; then
                echo "$hash_"
                return 0
            fi
            ;;
        image)
            if [[ -d ${CLEARLY_IMAGE_STORAGE}/img/${1} ]]; then
                echo "ok"
                return 0
            fi
            ;;
        docker)
            hash_=$(docker_ images -q "$1" | sort -u)
            if [[ $hash_ ]]; then
                echo "$hash_"
                return 0
            fi
            ;;
    esac
    echo 'not found'
    return 1
}

chtest_fixtures_ok () {
    echo "checking chtest fixtures in: ${1}"
    # Did we raise hidden files correctly?
    [[ -e ${1}/.hiddenfile1 ]]
    [[ -e ${1}/..hiddenfile2 ]]
    [[ -e ${1}/...hiddenfile3 ]]
    # Did we remove the right /dev stuff?
    [[ -e ${1}/mnt/dev/dontdeleteme ]]
    ls -Aq "${1}/dev"
    [[ $(ls -Aq "${1}/dev") = '' ]]
    clearly run "$1" -- test -e /mnt/dev/dontdeleteme
    # Are permissions still good?
    ls -ld "$1"/maxperms_*
    [[ $(stat -c %a "${1}/maxperms_dir") = 1777 ]]
    [[ $(stat -c %a "${1}/maxperms_file") = 777 ]]
}

cray_ofi_or_skip () {
    if [[ $clearly_cray ]]; then
        [[ -n "$CLEARLY_TEST_OFI_PATH" ]] || skip 'CLEARLY_TEST_OFI_PATH not set'
        [[ -z "$FI_PROVIDER_PATH" ]] || skip 'host FI_PROVIDER_PATH set'
        if [[ $cray_prov == 'gni' ]]; then
            export CLEARLY_FROMHOST_OFI_GNI=$CLEARLY_TEST_OFI_PATH
            $clearly_mpirun_node ch-fromhost -v --cray-gni "$1"
        fi
        if [[ $cray_prov == 'cxi' ]]; then
            export CLEARLY_FROMHOST_OFI_CXI=$CLEARLY_TEST_OFI_PATH
            $clearly_mpirun_node ch-fromhost --cray-cxi "$1"
            # Examples use libfabric's fi_info to ensure injection works; when
            # replacing libfabric we also need to replace this binary.
            fi_info="$(dirname "$(dirname "$CLEARLY_TEST_OFI_PATH")")/bin/fi_info"
            [[ -x "$fi_info" ]]
            $clearly_mpirun_node ch-fromhost -v -d /usr/local/bin \
                                           -p "$fi_info" \
                                              "$1"
        fi
    else
        skip 'host is not a Cray'
    fi
}

env_require () {
    if [[ -z ${!1} ]]; then
        printf '$%s is empty or not set\n\n' "$1" >&2
        exit 1
    fi
}

image_ok () {
    test -d "$1"
    ls -ld "$1" || true
    byte_ct=$(du -s -B1 "$1" | cut -f1)
    echo "$byte_ct"
    [[ $byte_ct -ge 3145728 ]]  # image is at least 3MiB
    [[ -d $1/bin && -d $1/dev && -d $1/usr ]]

}

localregistry_init () {
    # Skip unless GitHub Actions or there is a listener on localhost:5000.
    if [[ -z $GITHUB_ACTIONS ]] && ! (   command -v ss > /dev/null 2>&1 \
                                      && ss -lnt | grep -F :5000); then
        skip 'no local registry'
    fi
    # Note: These will only stick if function is called *not* in a subshell.
    export CLEARLY_IMAGE_AUTH=yes
    export CLEARLY_IMAGE_USERNAME=charlie
    export CLEARLY_IMAGE_PASSWORD=test
}

multiprocess_ok () {
    [[ $clearly_multiprocess ]] || skip 'no multiprocess launch tool found'
    true
}

openmpi_or_skip () {
    [[ $clearly_mpi == 'openmpi' ]] || skip "openmpi only"
}

pedantic_fail () {
    msg=$1
    if [[ -n $clearly_pedantic ]]; then
        echo "$msg" 1>&2
        return 1
    else
        skip "$msg"
    fi
}

# If the two images (graphics, not container) are not “almost equal”, fail.
# The first argument is the reference image; the second is the test image. The
# third argument, if given, is the maximum number of differing pixels (default
# zero). Also produce a diff image, which highlights the differing pixels in
# red, based on the sample, e.g. foo.png -> foo.diff.png.
pict_assert_equal () {
    ref=$1
    sample=$2
    pixel_max_ct=${3:-0}
    sample_base=$(basename "${sample%.*}")
    sample_ext=${sample##*.}
    diff_dir=${BATS_TMPDIR}/"$(basename "$(dirname "$sample")")"
    ref_bind="${ref}:/a.png"
    sample_bind="${sample}:/b.png"
    diff_bind="${diff_dir}:/diff"
    diff_="/diff/${sample_base}.diff.${sample_ext}"
    echo "reference: $ref"
    echo "   bind: $ref_bind"
    echo "sample: $sample"
    echo "   bind: $sample_bind"
    echo "diff: $diff_"
    echo "   bind: $diff_bind"
    # See: https://imagemagick.org/script/command-line-options.php#metric
    pixel_ct=$(clearly run "$clearly_img" -b "$ref_bind" \
                                -b "$sample_bind" \
                                -b "$diff_bind" -- \
                      compare -metric AE /a.png /b.png "$diff_" 2>&1 || true)
    echo "diff count:  ${pixel_ct} pixels, max ${pixel_max_ct}"
    [[ $pixel_ct -le $pixel_max_ct ]]
}

# Check if the pict_ functions are usable; if not, pedantic-fail.
pict_ok () {
    if "$clearly_mpirun_node" clearly run "$clearly_img" -- compare > /dev/null 2>&1; then
        pedantic_fail 'need ImageMagick'
    fi
}

pmix_or_skip () {
    if [[ $srun_mpi != pmix* ]]; then
        skip 'pmix required'
    fi
}

prerequisites_ok () {
    if [[ -f $CLEARLY_TEST_TARDIR/${1}.pq_missing ]]; then
        skip 'build prerequisites not met'
    fi
}

scope () {
    if [[ -n $clearly_one_test ]]; then
        # Ignore scope if a single test is given.
        if [[ $BATS_TEST_DESCRIPTION != *"$clearly_one_test"* ]]; then
            skip 'per --file'
        else
            return 0
        fi
    fi
    case $1 in  # $1 is the test’s scope
        quick)
            ;;  # always run quick-scope tests
        standard)
            if [[ $CLEARLY_TEST_SCOPE = quick ]]; then
                skip "${1} scope"
            fi
            ;;
        full)
            if [[ $CLEARLY_TEST_SCOPE = quick || $CLEARLY_TEST_SCOPE = standard ]]; then
                skip "${1} scope"
            fi
            ;;
        skip)
            skip "developer-skipped; see comments and/or issues"
            ;;
        *)
            exit 1
    esac
}

unpack_img_all_nodes () {
    if [[ $1 ]]; then
        case $CLEARLY_TEST_PACK_FMT in
            squash-mount)
                # Lots of things expect no extension here, so go with that
                # even though it’s a file, not a directory.
                $clearly_mpirun_node ln -s "${clearly_tardir}/${clearly_tag}.sqfs" "${clearly_imgdir}/${clearly_tag}"
                ;;
            squash-unpack)
                $clearly_mpirun_node clearly convert -o dir "${clearly_tardir}/${clearly_tag}.sqfs" "${clearly_imgdir}/${clearly_tag}"
                ;;
            tar-unpack)
                $clearly_mpirun_node clearly convert -o dir "${clearly_tardir}/${clearly_tag}.tar.gz" "${clearly_imgdir}/${clearly_tag}"
                ;;
            *)
                false  # unknown format
                ;;
        esac
    else
        skip 'not needed'
    fi
}

# Do we need sudo to run docker?
if [[ -n $clearly_docker_nosudo ]]; then
    docker_ () {
        docker "$@"
    }
else
    docker_ () {
        sudo docker "$@"
    }
fi

# Podman wrapper (for consistency w docker)
podman_ () {
    podman "$@"
}

# Do we have what we need?
env_require CLEARLY_TEST_TARDIR
env_require CLEARLY_TEST_IMGDIR
env_require CLEARLY_TEST_PERMDIRS
env_require CLEARLY_TEST_BUILDER
if [[ $CLEARLY_TEST_BUILDER == image ]]; then
    env_require CLEARLY_IMAGE_STORAGE
fi

# User-private temporary directory in case multiple users are running the
# tests simultaneously.
btnew=$TMP_/bats.tmp
mkdir -p "$btnew"
chmod 700 "$btnew"
export BATS_TMPDIR=$btnew
[[ $(stat -c %a "$BATS_TMPDIR") = '700' ]]

# clearly run exit codes. (see also: clearly_misc.h, lib/build.py)
CLEARLY_ERR_MISC=31
CLEARLY_ERR_CMD=49
#CLEARLY_ERR_SQUASH=84 # Currently not used

clearly_bin="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC2034
clearly_base=${clearly_bin%/*}

clearly_lib=${clearly_bin}/../../lib
clearly_libexec=${clearly_bin}/../../libexec

# Run file.
clearly_runfile=${clearly_libexec}/run

# Clearly version.
. "${clearly_lib}/_version.sh"
clearly_version_base=$(echo "$clearly_version" | sed -E 's/~.+//')
clearly_version_docker=$(echo "$clearly_version" | tr '~+' '--')

# Separate directories for tarballs and images.
#
# Canonicalize both so the have consistent paths and we can reliably use them
# in tests (see issue #143). We use readlink(1) rather than realpath(2),
# despite the admonition in the man page, because it's more portable [1].
#
# We use “readlink -m” rather than “-e” or “-f” to account for the possibility
# of some directory anywhere the path not existing [2], which has bitten us
# multiple times; see issues #347 and #733. With this switch, if something is
# missing, readlink(1) returns the path unchanged, and checks later convert
# that to a proper error.
#
# [1]: https://unix.stackexchange.com/a/136527
# [2]: http://man7.org/linux/man-pages/man1/readlink.1.html
clearly_imgdir=$(readlink -m "$CLEARLY_TEST_IMGDIR")
clearly_tardir=$(readlink -m "$CLEARLY_TEST_TARDIR")

# Image information.
clearly_tag=${CLEARLY_TEST_TAG:-NO_TAG_SET}  # set by Makefile; many tests don’t need it
clearly_img=${clearly_imgdir}/${clearly_tag}
clearly_tar=${clearly_tardir}/${clearly_tag}.tar.gz
clearly_ttar=${clearly_tardir}/chtest.tar.gz
clearly_timg=${clearly_imgdir}/chtest

if [[ $clearly_tag = *'-mpich' ]]; then
    clearly_mpi=mpich
    # As of MPICH 4.0.2, using SLURM as the MPICH process manager requires two
    # configure options that disable the compilation of mpiexec. This may not
    # always be the case.
    clearly_mpi_exe=mpiexec
else
    clearly_mpi=openmpi
    clearly_mpi_exe=mpirun
fi

# Crays are special.
if [[ -f /etc/opt/cray/release/cle-release ]]; then
    clearly_cray=yes
    # Prefer gni provider on Cray ugni machines
    if [[ -d /opt/cray/ugni ]]; then
        cray_prov=gni
    elif [[ -f /opt/cray/etc/release/cos ]]; then
        cray_prov=cxi
    fi
else
    clearly_cray=
fi

# Multi-node and multi-process stuff. Do not use Slurm variables in tests; use
# these instead:
#
#   clearly_multiprocess    can run multiple processes
#   clearly_multinode       can run on multiple nodes
#   clearly_nodes           number of nodes in job
#   clearly_cores_node      number of cores per node
#   clearly_cores_total     total cores in job ($clearly_nodes × $clearly_cores_node)
#
#   clearly_mpirun_node     command to run one rank per node
#   clearly_mpirun_core     command to run one rank per physical core
#   clearly_mpirun_2        command to run two ranks per job launcher default
#   clearly_mpirun_2_1node  command to run two ranks on one node
#   clearly_mpirun_2_2node  command to run two ranks on two nodes (one rank/node)
#
if [[ $SLURM_JOB_ID ]]; then
    clearly_nodes=$SLURM_JOB_NUM_NODES
else
    clearly_nodes=1
fi
# One rank per hyperthread can exhaust hardware contexts, resulting in
# communication failure. Use one rank per core to avoid this. There are ways
# to do this with Slurm, but they need Slurm configuration that seems
# unreliably present. This seems to be the most portable way to do this.
clearly_cores_node=$(lscpu -p | tail -n +5 | sort -u -t, -k 2 | wc -l)
clearly_cores_total=$((clearly_nodes * clearly_cores_node))
clearly_mpirun_node=
clearly_mpirun_np="-np ${clearly_cores_node}"
clearly_unslurm=
if [[ $SLURM_JOB_ID ]]; then
    [[ -z "$CLEARLY_TEST_SLURM_MPI" ]] || srun_mpi="--mpi=$CLEARLY_TEST_SLURM_MPI"
    clearly_multiprocess=yes
    clearly_mpirun_node="srun $srun_mpi --ntasks-per-node 1"
    clearly_mpirun_core="srun $srun_mpi --ntasks-per-node $clearly_cores_node"
    clearly_mpirun_2="srun $srun_mpi -n2"
    clearly_mpirun_2_1node="srun $srun_mpi -N1 -n2"
    # OpenMPI 3.1 pukes when guest-launched and Slurm environment variables
    # are present. Work around this by fooling OpenMPI into believing it’s not
    # in a Slurm allocation.
    if [[ $clearly_mpi = openmpi ]]; then
        clearly_unslurm='--unset-env=SLURM*'
    fi
    if [[ $clearly_nodes -eq 1 ]]; then
        clearly_multinode=
        clearly_mpirun_2_2node=false
    else
        clearly_multinode=yes
        clearly_mpirun_2_2node="srun $srun_mpi -N2 -n2"
    fi
else
    clearly_multinode=
    clearly_mpirun_2_2node=false
    if command -v mpirun > /dev/null 2>&1; then
        clearly_multiprocess=yes
        clearly_mpirun_node='mpirun --map-by ppr:1:node'
        clearly_mpirun_core="mpirun ${clearly_mpirun_np}"
        clearly_mpirun_2='mpirun -np 2'
        clearly_mpirun_2_1node='mpirun -np 2 --host localhost:2'
    else
        clearly_multiprocess=
        clearly_mpirun_node=''
        clearly_mpirun_core=false
        clearly_mpirun_2=false
        clearly_mpirun_2_1node=false
    fi
fi

# Do we have and want sudo?
if    [[ $CLEARLY_TEST_SUDO ]] \
   && command -v sudo >/dev/null 2>&1 \
   && sudo true > /dev/null 2>&1; then
    # This isn’t super reliable; it returns true if we have *any* sudo
    # privileges, not specifically to run the commands we want to run.
    clearly_have_sudo=yes
fi
