#include <stdio.h>
#include <unistd.h>
#include <string.h>
int check(char*x,char*y)
{
	if(!strcmp(x,y))
		return 1;
	else
		return 0;
}
int main(int argc, char*argv[])
{
	char x[100];
	read(0,x,100);
	if(check(x,"pwd")==1)
		printf("pwd cmd\n");
	else
		printf("no pwd cmd\n");
	if(check(x,"cwd")==1)
		printf("cwd cmd\n");
	else
		printf("no cwd cmd\n");
}