#!/bin/bash

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh

echo "Testing DefectDojo Service"

echo "Waiting max 60s for services to start"
# Wait for services to become available
COUNTER=0
while [  $COUNTER -lt 10 ]; do
    curl -s -o "/dev/null" "$DD_BASE_URL" -m 120
    CR=$(curl --insecure -s -m 10 -I "${DD_BASE_URL}login?next=/" | grep -E "^HTTP" | cut  -d' ' -f2)
    if [ "$CR" == 200 ]; then
        echo "Succesfully displayed login page, starting integration tests"
        break
    fi
    echo "Waiting: cannot display login screen; got HTTP code $CR"
    sleep 10
    (( a++ )) || true
done

if [ $COUNTER -gt 10 ]; then
    echo "ERROR: cannot display login screen; got HTTP code $CR"
    exit 1
fi

CHROMEDRIVER=$(find /opt/chrome-driver -name chromedriver)
export CHROMEDRIVER
CHROME_PATH=/opt/chrome/chrome
export CHROME_PATH

# Run available unittests with a simple setup
# All available Integrationtest Scripts are activated below
# If successsful, A successs message is printed and the script continues
# If any script is unsuccesssful a failure message is printed and the test script
# Exits with status code of 1

function fail() {
    printf 'Error: %s test failed\n' "$1"
    exit 1
}

function success() {
    printf 'Success: %s test passed\n' "$1"
}

echo "IT FILENAME: $DD_INTEGRATION_TEST_FILENAME"
if [[ -n "$DD_INTEGRATION_TEST_FILENAME" ]]; then
    if [[ "$DD_INTEGRATION_TEST_FILENAME" == "openapi-validatator" ]]; then
        test="OpenAPI schema validation"
        echo "Running: $test"
        if java -jar /usr/local/bin/openapi-generator-cli.jar validate -i "$DD_BASE_URL/api/v2/oa3/schema/?format=json" --recommend; then
            success "$test"
        else
            fail "$test"
        fi
    else
        test=$DD_INTEGRATION_TEST_FILENAME
        echo "Running: $test"
        if python3 "$DD_INTEGRATION_TEST_FILENAME"; then
            success "$test"
        else
            fail "$test"
        fi
    fi

else
    test="Finding integration tests"
    echo "Running: $test"
    if python3 tests/finding_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Report Builder tests"
    echo "Running: $test"
    if python3 tests/report_builder_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Notes integration tests"
    echo "Running: $test"
    if python3 tests/notes_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Regulation integration tests"
    echo "Running: $test"
    if python3 tests/regulations_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product type integration tests"
    echo "Running: $test"
    if python3 tests/product_type_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product integration tests"
    echo "Running: $test"
    if python3 tests/product_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Endpoint integration tests"
    echo "Running: $test"
    if python3 tests/endpoint_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Engagement integration tests"
    echo "Running: $test"
    if python3 tests/engagement_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Environment integration tests"
    echo "Running: $test"
    if python3 tests/environment_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Test integration tests"
    echo "Running: $test"
    if python3 tests/test_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="User integration tests"
    echo "Running: $test"
    if python3 tests/user_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Group integration tests"
    echo "Running: $test"
    if python3 tests/group_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product Group integration tests"
    echo "Running: $test"
    if python3 tests/product_group_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product Type Group integration tests"
    echo "Running: $test"
    if python3 tests/product_type_group_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product member integration tests"
    echo "Running: $test"
    if python3 tests/product_member_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Product type member integration tests"
    echo "Running: $test"
    if python3 tests/product_type_member_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Ibm Appscan integration test"
    echo "Running: $test"
    if python3 tests/ibm_appscan_test.py ; then
        success "$test"
    else
        fail "$test"
    fi


    test="Search integration test"
    echo "Running: $test"
    if python3 tests/search_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="File Upload tests"
    echo "Running: $test"
    if python3 tests/file_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Dedupe integration tests"
    echo "Running: $test"
    if python3 tests/dedupe_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Global Announcement Banner tests"
    echo "Running: $test"
    if python3 tests/announcement_banner_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Close Old Findings with dedupe integration tests"
    echo "Running: $test"
    if python3 tests/close_old_findings_dedupe_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="Close Old Findings without dedupe integration tests"
    echo "Running: $test"
    if python3 tests/close_old_findings_test.py ; then
        success "$test"
    else
        fail "$test"
    fi
    
    test="False Positive History tests"
    echo "Running: $test"
    if python3 tests/false_positive_history_test.py ; then
        success "$test"
    else
        fail "$test"
    fi

# The below tests are commented out because they are still an unstable work in progress
## Once Ready they can be uncommented.

    echo "Check Various Pages integration test"
    if python3 tests/check_various_pages.py ; then
        echo "Success: Check Various Pages tests passed"
    else
        echo "Error: Check Various Pages test failed"; exit 1
    fi


    # The below tests are commented out because they are still an unstable work in progress
    ## Once Ready they can be uncommented.

    # echo "Import Scanner integration test"
    # if python3 tests/import_scanner_test.py ; then
    #     echo "Success: Import Scanner integration tests passed"
    # else
    #     echo "Error: Import Scanner integration test failed"; exit 1
    # fi

    # echo "Zap integration test"
    # if python3 tests/zap.py ; then
    #     echo "Success: zap integration tests passed"
    # else
    #     echo "Error: Zap integration test failed"; exit 1
    # fi

    test="Tool Config integration tests"
    echo "Running: $test"
    if python3 tests/tool_config.py ; then
        success "$test"
    else
        fail "$test"
    fi

    test="OpenAPI schema validation"
    echo "Running: $test"
    if java -jar /usr/local/bin/openapi-generator-cli.jar validate -i "$DD_BASE_URL/api/v2/oa3/schema/?format=json" --recommend; then
        success "$test"
    else
        fail "$test"
    fi

    exec echo "Done Running all configured integration tests."
fi
