#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char*argv[])
{
	char x[100];
	int magic;
	read(0,x,10);
	read(0,&magic,10);
	if(strcmp(x,"command")==0)
	{
	    printf("%s\n","command");
	}
	if(magic==0x41414141)
	    printf("%s\n","magic");
    return 0;
}