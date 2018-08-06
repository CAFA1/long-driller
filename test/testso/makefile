testso : testso.c libmatch.so
	gcc -g -o testso testso.c -I ./ -L ./ -lmatch
libmatch.so : match.c match.h
	gcc -fpic -shared -o libmatch.so match.c
