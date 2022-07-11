#!/bin/bash -ex
# Installs gtirb in a barely-os-agnostic way
# If able to be downloaded and installed from apt, it will do so
# Otherwise, it installs from source by cloaning the gtirb repo.
# Meant to be used as a part of the dockerfile building process
set -ex

export DEBIAN_FRONTEND=noninteractive
GTIRB_RELEASE=${1:-"stable"}

apt-get update -y
if [[ "$(lsb_release --short --id)" == "Ubuntu" ]]; then
    # If we're on ubuntu, attempt to install from apt
    apt-get install -y software-properties-common wget gnupg
    wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add -
    echo "deb https://download.grammatech.com/gtirb/files/apt-repo $(lsb_release --codename --short) $GTIRB_RELEASE" | tee -a /etc/apt/sources.list

    add-apt-repository -y ppa:mhier/libboost-latest
    apt-get update -y
    apt-get install -y libcapstone-dev libgtirb-dev libgtirb-dbg libgtirb-pprinter ddisasm gtirb-pprinter
    exit
fi
apt-get install -y software-properties-common
add-apt-repository ppa:mhier/libboost-latest
apt-get install -y libprotobuf-dev protobuf-compiler libboost1.67-dev cmake git

# Otherwise, install from source
# Build & install GTIRB
mkdir -p /tmp/gtirb-installation
cd /tmp/gtirb-installation
git clone --recursive https://github.com/GrammaTech/gtirb.git
cd gtirb
mkdir build
cd build
cmake .. -DGTIRB_BUILD_SHARED_LIBS=OFF
cmake --build . -- -j $(nproc)
make install
rm -r /tmp/gtirb-installation

# Build & install Capstone
mkdir -p /tmp/capstone-installation
cd /tmp/capstone-installation
git clone --recursive https://github.com/GrammaTech/capstone.git
cd capstone
CAPSTONE_ARCHS='x86 aarch64' ./make.sh
CAPSTONE_ARCHS='x86 aarch64' ./make.sh install
rm -r /tmp/capstone-installation
