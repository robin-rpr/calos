CLEARLY_TEST_TAG=$clearly_test_tag
load "${CHTEST_DIR}/common.bash"

setup () {
    scope full
    prerequisites_ok "$clearly_tag"
    pmix_or_skip
    if [[ $srun_mpi != pmix* ]]; then
        skip 'pmix required'
    fi
}

count_ranks () {
      echo "$1" \
    | grep -E '^0: init ok' \
    | tail -1 \
    | sed -r 's/^.+ ([0-9]+) ranks.+$/\1/'
}

@test "${clearly_tag}/guest starts ranks" {
    openmpi_or_skip
    # shellcheck disable=SC2086
    run clearly run $clearly_unslurm "$clearly_img" -- mpirun $clearly_mpirun_np /hello/hello
    echo "$output"
    [[ $status -eq 0 ]]
    rank_ct=$(count_ranks "$output")
    echo "found ${rank_ct} ranks, expected ${clearly_cores_node}"
    [[ $rank_ct -eq "$clearly_cores_node" ]]
    [[ $output = *'0: send/receive ok'* ]]
    [[ $output = *'0: finalize ok'* ]]
}

@test "${clearly_tag}/inject cray mpi ($cray_prov)" {
    cray_ofi_or_skip "$clearly_img"
    run clearly run "$clearly_img" -- fi_info
    echo "$output"
    [[ $output == *"provider: $cray_prov"* ]]
    [[ $output == *"fabric: $cray_prov"* ]]
    [[ $status -eq 0 ]]
}

@test "${clearly_tag}/validate $cray_prov injection" {
    [[ -n "$clearly_cray" ]] || skip "host is not cray"
    [[ -n "$CLEARLY_TEST_OFI_PATH" ]] || skip "--fi-provider not set"
    run $clearly_mpirun_node clearly run --join "$clearly_img" -- sh -c \
                    "FI_PROVIDER=$cray_prov FI_LOG_LEVEL=info /hello/hello 2>&1"
    echo "$output"
    [[ $status -eq 0 ]]
    if [[ "$cray_prov" == gni ]]; then
        [[ "$output" == *' registering provider: gni'* ]]
        [[ "$output" == *'gni:'*'gnix_ep_nic_init()'*'Allocated new NIC for EP'* ]]
    fi
    if [[ "$cray_prov" == cxi ]]; then
        [[ "$output" == *'cxi:mr:ofi_'*'stats:'*'searches'*'deletes'*'hits'* ]]
    fi
}

@test "${clearly_tag}/MPI version" {
    [[ -z $clearly_cray ]] || skip 'serial launches unsupported on Cray'
    # shellcheck disable=SC2086
    run clearly run $clearly_unslurm "$clearly_img" -- /hello/hello
    echo "$output"
    [[ $status -eq 0 ]]
    if [[ $clearly_mpi = openmpi ]]; then
        [[ $output = *'Open MPI'* ]]
    else
        [[ $clearly_mpi = mpich ]]
        if [[ $clearly_cray ]]; then
            [[ $output = *'CRAY MPICH'* ]]
        else
            [[ $output = *'MPICH Version:'* ]]
        fi
    fi
}

@test "${clearly_tag}/empty stderr" {
   multiprocess_ok
   output=$($clearly_mpirun_core clearly run --join "$clearly_img" -- \
                            /hello/hello 2>&1 1>/dev/null)
   echo "$output"
   [[ -z "$output" ]]
}

@test "${clearly_tag}/serial" {
    [[ -z $clearly_cray ]] || skip 'serial launches unsupported on Cray'
    # This seems to start up the MPI infrastructure (daemons, etc.) within the
    # guest even though there's no mpirun.
    # shellcheck disable=SC2086
    run clearly run $clearly_unslurm "$clearly_img" -- /hello/hello
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *' 1 ranks'* ]]
    [[ $output = *'0: send/receive ok'* ]]
    [[ $output = *'0: finalize ok'* ]]
}

@test "${clearly_tag}/host starts ranks" {
    multiprocess_ok
    echo "starting ranks with: ${clearly_mpirun_core}"

    guest_mpi=$(clearly run "$clearly_img" -- mpirun --version | head -1)
    echo "guest MPI: ${guest_mpi}"

    # shellcheck disable=SC2086
    run $clearly_mpirun_core clearly run --join "$clearly_img" -- /hello/hello 2>&1
    echo "$output"
    [[ $status -eq 0 ]]
    rank_ct=$(count_ranks "$output")
    echo "found ${rank_ct} ranks, expected ${clearly_cores_total}"
    [[ $rank_ct -eq "$clearly_cores_total" ]]
    [[ $output = *'0: send/receive ok'* ]]
    [[ $output = *'0: finalize ok'* ]]
}

@test "${clearly_tag}/Cray bind mounts" {
    [[ $clearly_cray ]] || skip 'host is not a Cray'

    clearly run "$clearly_img" -- mount | grep -F /dev/hugepages
    if [[ $cray_prov == 'gni' ]]; then
        clearly run "$clearly_img" -- mount | grep -F /var/opt/cray/alps/spool
    else
        clearly run "$clearly_img" -- mount | grep -F /var/spool/slurmd
    fi
}

@test "${clearly_tag}/revert image" {
    unpack_img_all_nodes "$clearly_cray"
}
