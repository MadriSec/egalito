#!/bin/bash -e

REGISTRY_BASE="registry.gitlab.com/egalito/egalito"
DOCKERFILE="Dockerfile_x86_64"
BUILT_IMAGES=()

for BASE_IMAGE in "ubuntu:20.04" "ubuntu:18.04" "debian:buster"; do {
    # Gives test image based on ubuntu:20.04 the tag test/ubuntu-20.04
    # (Tags within the registry can be used for versioning)
    TAG="${REGISTRY_BASE}/test/${BASE_IMAGE//:/-}"
    set -x
    if docker build \
            --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
            --network=host \
            --target=test \
            --tag "${TAG}" \
            -f "${DOCKERFILE}" \
            .; then
        BUILT_IMAGES+=( "$TAG" )
    fi
    set +x
} done

echo "===== Use the following commands to push images:"

for IMAGE in ${BUILT_IMAGES[@]}; do
    echo "docker push $IMAGE"
done
