# FlashVulnScan
Currently in the cyber worl, flash (.swf) apps are no longer very common and has been prevented from working in common web browsers like Google Chrome; however, that being said, they still exist. With SWFInvestigator no longer being readily available, I have written this quick script in accordance with OWASP's testing methods to help search for common, flash-related vulnerabilties.

The program works by taking in a .swf file and decompiling is into ActionScript (.as) files, through the use of JPEXS decompiler, available on GitHub [here](https://github.com/jindrapetrik/jpexs-decompiler.git). From there, the script searches through all .as files for the aforementioned vulnerabilities, and outputs them to a .txt file. In order for it to all work properly, please install all dependencies, using the `Dependencies.sh` bash script. This program is designed for debian-based, linux systems. For other distributions, please alter the packages and package manager in `dependencies.sh` accordingly.

Usage: FlashVulnScan.py [-h] [-d DECOMPILE] [-l LOCATION]

FlashVulnScan is a tool that checks for possible vulnerable variables and
methods in a decompiled .swf application.

optional arguments:
  -h, --help            show this help message and exit
  -d DECOMPILE, --decompile DECOMPILE
                        This option is used to specify a .swf file that needs
                        to be decompiled before scanning can commence.
                        ./FlashVulnScan.py -d file.swf
  -l LOCATION, --location LOCATION
                        This option will specify the output folder of the
                        decompiled files when used in accordance with the -d option.
                        Otherwise this option specifies the location of pre-
                        decompiled files when used alone. ./FlashVulnScan.py
                        -d file.swf -l /root/Downloads/folder-to-decompile-to/
