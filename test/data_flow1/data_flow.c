#include <stdio.h>
#include <unistd.h>
#include <string.h>
char check(char*x,char*y)
{
	int this_bool=(x[0]==y[0]&&x[1]==y[1]&&x[2]==y[2]);
	if(this_bool)
		return this_bool;
	else
		return this_bool;
}
int main(int argc, char*argv[])
{
	char x[100];
	read(0,x,100);
	if(check(x,"pwd\n")==1)
		printf("pwd cmd\n");
	else
		printf("no pwd cmd\n");
	if(check(x,"dir\n")==1)
		printf("dir cmd\n");
	else
		printf("no dir cmd\n");
	return 1;
}