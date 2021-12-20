#!/bin/bash -ex



set -x
for BASE_IMAGE in "ubuntu:20.04" "ubuntu:18.04"; do
    docker build --build-arg "BASE_IMAGE=$BASE_IMAGE" --network=host --target gtirb-test --tag registry.gitlab.com/grammatech/egalito/egalito/gtirb-test/$BASE_IMAGE - < gtirb-pkg.Dockerfile;
done
BASE_IMAGE="debian:buster"
docker build --build-arg "BASE_IMAGE=$BASE_IMAGE" --network=host --target gtirb-test --tag registry.gitlab.com/grammatech/egalito/egalito/gtirb-test/$BASE_IMAGE - < gtirb-src.Dockerfile;
set +x

echo "===== Use the following commands to push images:"

for BASE_IMAGE in "ubuntu:20.04" "ubuntu:18.04" "debian:buster"; do
    echo "docker push registry.gitlab.com/grammatech/egalito/egalito/gtirb-test/$BASE_IMAGE"
done
