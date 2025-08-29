CLEARLY_TEST_TAG=$clearly_test_tag
load "${CLEARLYTEST_DIR}/common.bash"

setup() {
    scope full
    prerequisites_ok spack
    export PATH=/spack/bin:$PATH
}

@test "${clearly_tag}/version" {
    # Spack likes to write to $HOME/.spack; thus, we bind it.
    clearly run --home "$clearly_img" -- spack --version
}

@test "${clearly_tag}/compilers" {
    echo "spack compiler list"
    clearly run --home "$clearly_img" -- spack compiler list
    echo "spack compiler list --scope=system"
    clearly run --home "$clearly_img" -- spack compiler list --scope=system
    echo "spack compiler list --scope=user"
    clearly run --home "$clearly_img" -- spack compiler list --scope=user
    echo "spack compilers"
    clearly run --home "$clearly_img" -- spack compilers
}

@test "${clearly_tag}/find" {
    run clearly run --home "$clearly_img" -- spack find clearly
    echo "$output"
    [[ $status -eq 0 ]]
    [[ $output = *'clearly@'* ]]
}
