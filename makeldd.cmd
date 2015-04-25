gcc -fno-common -g -O3 -Wall -D__USE_MINGW_ANSI_STDIO=1 -D_WIN32_WINNT=0x501 -c libntldd.c -o libntldd.o
ar rs libntldd.a libntldd.o
gcc -fno-common -g -O3 -Wall -D__USE_MINGW_ANSI_STDIO=1 -L. ntldd.c -lntldd -limagehlp -o ntldd.exe