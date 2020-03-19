#! /bin/bash
#
# Script to setup virtual environment to run GD cert tests and devlop using IDE
#
# Usage
#  1. cd system/bt/gd
#  2. source cert/set_up_virtualenv.sh
#  4. [run tests, do development, hack] using vevn/bin/python
#
# Note: Just use the virtualized Python binary, no need to activate

## Android build main build setup script relative to top level android source root
BUILD_SETUP=./build/envsetup.sh

function UsageAndroidTree {
    cat<<EOF
Ensure invoked from within the android source tree
EOF
}

function UsageSourcedNotExecuted {
    cat<<EOF
Ensure script is SOURCED and not executed to persist the build setup
e.g.
source $0
EOF
}

function UpFind {
    while [[ $PWD != / ]] ; do
        rc=$(find "$PWD" -maxdepth 1 "$@")
        if [ -n "$rc" ]; then
            echo $(dirname "$rc")
            return
        fi
        cd ..
    done
}

function SetUpAndroidBuild {
    pushd .
    android_root=$(UpFind -name out -type d)
    if [[ -z $android_root ]] ; then
        UsageAndroidTree
        return
    fi
    echo "Found android root $android_root"
    cd $android_root && . $BUILD_SETUP
    echo "Sourced build setup rules"
    cd $android_root && lunch
    popd
}

function SetupPython38 {
    echo "Setting up python3.8"
    sudo apt-get install python3.8-dev
}

function SetupPip3 {
    echo "Setting up pip3"
    sudo apt-get install python3-pip
}

# Deactivate existing virtual environment, if any, ignore errors
deactivate > /dev/null 2>&1

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] ; then
    UsageSourcedNotExecuted
    return 1
fi

## Check python3.8 is installed properly
## Need Python 3.8 because bluetooth_packets_python3 is compiled against
## Python 3.8 headers
dpkg -l python3.8-dev > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
    SetupPython38
fi

## Check pip3 is installed properly
## Need pip3 for Python 3 support
dpkg -l python3-pip > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
    SetupPip3
fi

# Install and upgrade virtualenv to latest version
pip3 install --user --upgrade virtualenv > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
    echo "Error install and upgrade virtualenv"
    return 1
fi

# Set-up Android environment variables
if [[ -z "$ANDROID_BUILD_TOP" ]] ; then
    SetUpAndroidBuild
fi

## Compile and unzip test artifacts
echo "Compiling bluetooth_stack_with_facade ..."
$ANDROID_BUILD_TOP/build/soong/soong_ui.bash --build-mode --"all-modules" --dir="$(pwd)" dist bluetooth_stack_with_facade
if [[ $? -ne 0 ]] ; then
    echo "Failed to compile bluetooth_stack_with_facade"
    return 1
fi
if [[ ! -f "$ANDROID_BUILD_TOP/out/dist/bluetooth_cert_tests.zip" ]]; then
    echo "Cannot find bluetooth_cert_tests.zip after compilation"
    return 1
fi

CERT_TEST_VENV=$ANDROID_BUILD_TOP/out/dist/bluetooth_venv

rm -rf $CERT_TEST_VENV

python3.8 -m virtualenv --python `which python3.8` $CERT_TEST_VENV
if [[ $? -ne 0 ]] ; then
    echo "Error setting up virtualenv"
    return 1
fi

unzip -o -q $ANDROID_BUILD_TOP/out/dist/bluetooth_cert_tests.zip -d $CERT_TEST_VENV/acts
if [[ $? -ne 0 ]] ; then
    echo "Error unzipping bluetooth_cert_tests.zip"
    return 1
fi

$CERT_TEST_VENV/bin/python $CERT_TEST_VENV/acts/setup.py install
if [[ $? -ne 0 ]] ; then
    echo "Error installing GD libraries"
    return 1
fi

$CERT_TEST_VENV/bin/python -c "
import bluetooth_packets_python3 as bp3
bp3.BaseStruct
"
if [[ $? -ne 0 ]] ; then
  echo "Setup failed as bluetooth_packets_python3 cannot be imported"
  return 1
fi

echo ""
echo "Please mark GD root directory as \"Project Sources and Headers\" in IDE"
echo "If still seeing errors, invalidate cached and restart"
echo "virtualenv setup complete"
