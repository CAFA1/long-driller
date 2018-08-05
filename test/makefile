all:
	gcc -g -o two_read two_read.c
	gcc -g -o vul vul.c
	gcc -g -o vul_while vul_while.c
	gcc -g -o control_dependency control_dependency.c
	gcc -g -o hash_crc hash_Crc.c -lz
two_read : two_read.c
	gcc -g -o two_read two_read.c
vul : vul.c
	gcc -g -o vul vul.c
vul_while : vul_while.c
	gcc -g -o vul_while vul_while.c

