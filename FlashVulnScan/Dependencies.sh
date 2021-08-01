#!/bin/bash
#
apt-get install python
apt-get install git
apt-get install ant
git clone https://github.com/jindrapetrik/jpexs-decompiler.git
cd /jpexs-decompiler/
ant build
cd /dist
chmod 755 ffdec.jar
path1=`pwd`
path2="/dist/ffdec.jar"
jpexspath="$path1$path2"
echo "$jpexspath"
ln -s $jpexspath /usr/local/bin/ffdec
