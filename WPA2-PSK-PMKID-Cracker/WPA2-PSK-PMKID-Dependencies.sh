#!/bin/bash

apt-get install hashcat opencl-headers libz-dev -y
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools/
make
make install
cd ../
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool/
make
make install
cd ../