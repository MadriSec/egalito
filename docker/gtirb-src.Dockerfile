# Build a docker image with all dependencies, including gtirb
# Build gtirb from source (for use when no apt package is available)
ARG BASE_IMAGE="debian:buster"

# Just the egalito dependencies installed
FROM ${BASE_IMAGE} AS egalito-dependencies
RUN apt-get update -y && apt-get install -y make g++ libreadline-dev gdb lsb-release unzip libc6-dbg libstdc++6-7-dbg

FROM egalito-dependencies AS gtirb-dependencies
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:mhier/libboost-latest && apt-get install -y libprotobuf-dev protobuf-compiler libboost1.67-dev cmake git

# Install gtirb on top of egalito dependencies
FROM gtirb-dependencies AS gtirb-installed
RUN mkdir -p /gtirb-installation && \
        cd /gtirb-installation && \
        git clone --recursive https://github.com/GrammaTech/gtirb.git && \
        cd gtirb && \
        mkdir build && \
        cd build && \
        cmake .. -DGTIRB_BUILD_SHARED_LIBS=OFF && \
        cmake --build . -- -j 8 \
        && make install \
        && cd / \
        && rm -r /gtirb-installation

# Install utilities necessary for for testing and development
# (python, git, etc) on top of gtirb installation
FROM gtirb-installed AS gtirb-test
RUN apt-get install -y python3-pip lcov coreutils git clang-format-6.0
RUN python3 -m pip install pre-commit
