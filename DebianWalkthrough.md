# Egalito Debian Bookworm Walkthrough 

## Pulling SysPartCode & Egalito
```shell
git clone git@github.com:MadriSec/egalito.git
git checkout metis-main-syspart # May not be needed later
git submodule update --init --recursive
cd egalito
```

## Building Egalito (branch metis-main-syspart)

### Building GTIRB & Capstone
```shell
# install related packages that are in readme there 
sudo bash ./testscript/get-gtirb.sh
```


#### You may run into the error:
```shell
# AttributeError: 'NoneType' object has no attribute 'people'
# Installing the following solved this error
$ sudo apt-get install python3-launchpadlib
```

#### You may run into the error:
```bash
# E: Package 'libboost1.67-dev' has no installation candidate
# check if you have any other libboost:
$ dpkg -l | grep libboost
# if you dont have libboost<version>-dev:
$ apt-cache search libboost 
# and install available libboost<version>-dev.
```
Then edit the `get-gtirb.sh` script to disable libboost installation. We have edited it as follows:
```diff
- apt-get install -y libprotobuf-dev protobuf-compiler libboost1.67-dev cmake git
+ apt-get install -y libprotobuf-dev protobuf-compiler cmake git #libboost1.67-dev cmake git
```
#### You may run into the error: 
```bash
#Ign:4 http://ppa.launchpad.net/mhier/libboost-latest/ubuntu bookworm InRelease
#Err:5 http://ppa.launchpad.net/mhier/libboost-latest/ubuntu bookworm Release
#  404  Not Found [IP: 
```
This error is due to the repository not having a release for bookworm. But this repository was added for libboost and we already installed libboost. Remove the repository from `/etc/apt/sources.list.d/` then edit `get_gtirb.sh`:
```diff
-add-apt-repository ppa:mhier/libboost-latest
+#add-apt-repository ppa:mhier/libboost-latest
```

#### You may run into the error:
```
# /tmp/gtirb-installation/gtirb/build/googletest-src/googletest/src/gtest-death-test.cc:1301:24: error: ‘dummy’ may be used uninitialized [-Werror=maybe-uninitialized]
```
if so, go to the error file (`gtest-death-test.cc`) and initialize `int dummy = 0;`. [In latest version of googletest,](https://github.com/google/googletest/blob/35d0c365609296fa4730d62057c487e3cfa030ff/googletest/src/gtest-death-test.cc#L1242) that variable it is initialized. So hopefully we are not breaking anything. After doing this comment out `git clone gtirb` and mkdir build lines in get-gtirb, and run again:
```diff
-git clone --recursive https://github.com/GrammaTech/gtirb.git
+#git clone --recursive https://github.com/GrammaTech/gtirb.git
...
-mkdir build
+#mkdir build
```
```
./test/scripts/get-gtirb.sh
```
this time it should run

### Building Egalito

```
$ make -j $(nproc) # build egalito itself
# Then test it following Readme
```
