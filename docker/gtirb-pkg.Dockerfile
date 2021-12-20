# Build a docker image with all dependencies, including gtirb
# Use the gtirb apt package to install gtirb
ARG BASE_IMAGE="ubuntu:18.04"

# Just the egalito dependencies installed
FROM ${BASE_IMAGE} AS egalito-dependencies
RUN apt-get update -y \
    && apt-get install -y make g++ libreadline-dev gdb lsb-release unzip libc6-dbg libstdc++6-7-dbg

# Install gtirb on top of egalito dependencies
FROM egalito-dependencies AS gtirb-installed
RUN apt-get update -y && apt-get install -y software-properties-common lsb-release wget gnupg
RUN wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add - \
    && echo "deb https://download.grammatech.com/gtirb/files/apt-repo $(lsb_release --codename --short) unstable" | tee -a /etc/apt/sources.list

RUN add-apt-repository ppa:mhier/libboost-latest \
    && apt-get update -y \
    && apt-get install -y ddisasm gtirb-pprinter libgtirb-dev libgtirb-dbg python3-gtirb

# Install utilities for testing and development
# (python, git, etc) on top of gtirb installation
FROM gtirb-installed AS gtirb-test
RUN apt-get install -y python3-pip lcov coreutils git clang-format-6.0
RUN python3 -m pip install pre-commit
