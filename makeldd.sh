#! /bin/sh
gcc -fno-common -g -O3 -Wall -D_WIN32_WINNT=0x501 -c libntldd.c -o libntldd.o
ar rs libntldd.a libntldd.o
gcc -fno-common -g -O3 -Wall -L. ntldd.c -lntldd -limagehlp -o ntldd.exe