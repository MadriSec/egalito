#!/bin/bash
# Installs GTIRB in a barely-OS-agnostic way
# If able to be downloaded and installed from apt, it will do so
# Otherwise, it installs from source by cloning the GTIRB repo.
# Meant to be used as a part of the Dockerfile building process

set -ex

export DEBIAN_FRONTEND=noninteractive
GTIRB_RELEASE=${1:-"stable"}
OS_NAME=$(lsb_release -si)
OS_CODENAME=$(lsb_release -sc)

install_dependencies_common() {
    apt-get update -y
    apt-get install -y software-properties-common wget gnupg python3-launchpadlib libprotobuf-dev protobuf-compiler cmake git
}

install_gtirb_from_apt() {
    apt-get install -y software-properties-common wget gnupg
    wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add -
    echo "deb https://download.grammatech.com/gtirb/files/apt-repo $OS_CODENAME $GTIRB_RELEASE" | tee -a /etc/apt/sources.list

    apt-get update -y
    apt-get install -y libcapstone-dev libgtirb-pprinter ddisasm gtirb-pprinter libgtirb-dev libgtirb-dbg
}

build_and_install_gtirb_from_source() {
    local install_dir=$1
    local repo_url=${2:-"https://github.com/PhiliaTheCat/gtirb.git"}
    local lib_boost=${3:-"libboost1.67-dev"}

    apt-get install -y "$lib_boost"

    mkdir -p "$install_dir"
    git clone --recursive "$repo_url" "$install_dir/gtirb"
    mkdir "$install_dir/gtirb/build"
    cd "$install_dir/gtirb/build"
    cmake .. -DGTIRB_BUILD_SHARED_LIBS=OFF
    cmake --build . -- -j $(nproc)
    make install 
    cd -
    rm -rf "$install_dir"
}

build_and_install_capstone() {
    local install_dir=$1

    mkdir -p "$install_dir"
    git clone --recursive https://github.com/GrammaTech/capstone.git "$install_dir/capstone"
    cd "$install_dir/capstone"
    CAPSTONE_ARCHS='x86 aarch64' ./make.sh
    CAPSTONE_ARCHS='x86 aarch64' ./make.sh install
    cd -
    rm -rf "$install_dir"
}

main() {
    apt-get update -y

    if [[ $OS_NAME == "Ubuntu" ]]; then
        install_gtirb_from_apt
        exit
    elif [[ $OS_NAME == "Debian" && $OS_CODENAME == "bookworm" ]]; then
        install_dependencies_common
        build_and_install_gtirb_from_source /tmp/gtirb-installation "https://github.com/PhiliaTheCat/gtirb.git" "libboost1.74-dev"
        build_and_install_capstone /tmp/capstone-installation
    else
        install_dependencies_common
        build_and_install_gtirb_from_source /tmp/gtirb-installation "https://github.com/GrammaTech/gtirb.git"
        build_and_install_capstone /tmp/capstone-installation
    fi
}

main "$@"
