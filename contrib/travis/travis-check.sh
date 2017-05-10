#!/bin/bash

set -ev

print_test_logs() {
    echo ">>>> PRINT TEST LOGS $1 (start)"
    cat test-suite.log
    echo ">>>> PRINT TEST LOGS $1 (done)"
}

# travis is known to generate the settings doc differently.
# Don't compare.
export NMTST_NO_CHECK_SETTINGS_DOCS=yes

if ! make check -j 4 -k ; then

    print_test_logs "first-test"

    echo ">>>> RUN SECOND TEST (start)"
    NMTST_DEBUG=TRACE,no-expect-message make check -k || :
    echo ">>>> RUN SECOND TEST (done)"

    print_test_logs "second-test"

    exit 57
fi

