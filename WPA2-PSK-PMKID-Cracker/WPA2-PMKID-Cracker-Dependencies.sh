#!/bin/bash

apt-get install python3 aircrack-ng hashcat opencl-headers libz-dev libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev -y
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools/
make
make install
path=`pwd`
cp -s $path/hcxpcapngtool /usr/bin/
cd ../
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool/
make
make install
cd ../
