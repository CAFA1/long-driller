#include <stdio.h>
#include <unistd.h>
#include <string.h>
char check(char*x,char*y)
{
	if(strcmp(x,y))
		return 0+strcmp(x,y);
	else
		return 1+strcmp(x,y);
}
int main(int argc, char*argv[])
{
	char x[100];
	read(0,x,100);
	if(check(x,"pwd\n")==1)
		printf("pwd cmd\n");
	else
		printf("no pwd cmd\n");
	if(check(x,"cwd\n")==1)
		printf("cwd cmd\n");
	else
		printf("no cwd cmd\n");
	return 1;
}