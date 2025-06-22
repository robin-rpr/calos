load common

@test 'permissions test directories exist' {
    scope standard
    [[ $CLEARLY_TEST_PERMDIRS = skip ]] && skip 'user request'
    for d in $CLEARLY_TEST_PERMDIRS; do
        echo "$d"
        test -d "${d}"
        test -d "${d}/pass"
        test -f "${d}/pass/file"
        test -d "${d}/nopass"
        test -d "${d}/nopass/dir"
        test -f "${d}/nopass/file"
    done
}

@test 'clearly checkns' {
    scope quick
    run clearly checkns
}
