#! /bin/bash
#
# Script to setup environment to execute bluetooth certification stack
#
# for more info, see go/acts

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

function SetupPython3 {
    echo "Setting up python3"
    sudo apt-get install python3-dev
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] ; then
    UsageSourcedNotExecuted
    exit 1
fi

if [[ -z "$ANDROID_BUILD_TOP" ]] ; then
    SetUpAndroidBuild
fi

## Check python3 is installed properly
dpkg -l python3-dev > /dev/null 2>&1
if [[ $? -ne 0 ]] ; then
    SetupPython3
fi

## All is good now so go ahead with the acts setup
pushd .
cd $ANDROID_BUILD_TOP/tools/test/connectivity/acts/framework/
sudo python3 setup.py develop
if [[ $? -eq 0 ]] ; then
    echo "cert setup complete"
else
    echo "cert setup failed"
fi
popd

