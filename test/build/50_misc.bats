load ../common

@test 'sotest executable works' {
    scope quick
    [[ $clearly_libc = glibc ]] || skip 'glibc only'
    export LD_LIBRARY_PATH=./sotest
    ldd sotest/sotest
    sotest/sotest
}
