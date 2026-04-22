#! /usr/bin/env bash
for location in /lib /usr/lib /usr/local/lib; do
libgtirb_location=$location/libgtirb.so
if [[ -f $libgtirb_location ]]; then
    libgtirb_entry=$(ls -l $libgtirb_location)
    libgtirb=${libgtirb_entry##*-> }
    echo ${libgtirb##*so.}
    exit 0
fi
done
echo "libgtirb.so not found!"
exit 1