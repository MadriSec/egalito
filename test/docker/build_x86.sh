#!/bin/bash -e

#REGISTRY_BASE="registry.gitlab.com/egalito/egalito"
REGISTRY_BASE="registry.gitlab.com/madrisec/egalito"
DOCKERFILE="Dockerfile_x86_64"
BUILT_IMAGES=()

for BASE_IMAGE in "ubuntu:20.04" "debian:buster" "debian:bookworm"; do {
    # Gives test image based on BASE_IMAGE the appropriate tag
    # (Tags within the registry can be used for versioning)
    TAG="${REGISTRY_BASE}/test/${BASE_IMAGE//:/-}:gtirb"
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

