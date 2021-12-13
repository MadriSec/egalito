#!/bin/bash

######
# Build and run a dev-container that uses the remote ubuntu:18 image
# with gtirb installed as a base.
#
# Mounts your local filesystem into a container with common dev dependencies installed
# on top of a static base image
#
# Requires that `dev-container` is mapped to the the `dev.sh` executable here:
# https://git.grammatech.com/research/development-tools/dev-container
######

dev-container --base-image registry.gitlab.com/metis/egalito/egalito/gtirb/ubuntu:18.04 --tag egalito-gtirb-ubuntu-18.04 "$@"
