# README
This directory includes the Dockerfiles for egalito images. There is one for each supported architecture.
When cross-compiling, QEMU is required. Depending on your distro you will need the corresponding `qemu-$ARCH-static` for which you are trying to cross-compile.

### Arch Link
`yaourt -S qemu-user-static`

### Debian
`apt-get install qemu-user-static`

## Docker images for CI
Gitlab CI uses 3 x86-based docker images for building and running tests.
All of those images can be built with the script:
```shell
./build_x86.sh
```
which will also echo the necessary commands to push the images to gitlab's docker registry
