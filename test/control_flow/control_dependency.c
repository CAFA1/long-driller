#include <stdio.h>
#include <unistd.h>
#include <string.h>
int check(char*x,char*y)
{
	if(strcmp(x,y))
		return 0;
	else
		return 1;
}
int main(int argc, char*argv[])
{
	char x[100];
	read(0,x,100);
	if(check(x,"pwd")==1)
		printf("pwd cmd\n");
	else
		printf("no pwd cmd\n");
	if(check(x,"dir")==1)
		printf("dir cmd\n");
	else
		printf("no dir cmd\n");
}