# Installation and compilation on Linux

All utilities require OpenSSL library

> sudo apt update
> sudo apt install libssl-dev

Than u can compile the utility with this command

> g++ -Wall -pedantic -g \<filename\>.cpp -lcrypto

