NOTE:
The python3.11 executable **will** try to look in your system directories for python dependencies, and will throw an error if it is incompatible. For best results and to prevent any unexpected surprise, unless you are using Python 3.11 with Debian 12 (what the docker is using, and what i used to write the chal), please please use the docker provided.

Also, a tip: you can install `libc6-dbg` package to get debugging symbol with your libc in the docker image.