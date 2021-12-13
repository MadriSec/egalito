#!/bin/bash

######
# Build and run a dev-container that uses the cache-friendly dockerfile definition
# located in thuis directory as a base.
#
# Mounts your local filesystem into a container with common dev dependencies installed
# on top of a static base image
#
# Requires that `dev-container` is mapped to the the `dev.sh` executable here:
# https://git.grammatech.com/research/development-tools/dev-container
######

dev-container -f $(dirname $0)/gtirb-pkg.Dockerfile --target gtirb-test --tag egalito-with-gtirb
