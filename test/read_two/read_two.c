#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char*argv[])
{
	char x[20];
	char magic[20];
	read(0,x,10);
	read(0,magic,10);
	if(strcmp(x,"dir\n")==0)
	{
	    printf("%s\n","dir");
	}
	else
	{
		printf("%s\n","nodir");
	}
	if(strcmp(magic,"pwd\n")==0)
	{
		printf("%s\n","pwd");
	}
	else
	{
		printf("%s\n","nopwd");
	}
	return 0;
}