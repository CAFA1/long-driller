#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char*argv[])
{
	char x[20];
	char magic[20];
	read(0,x,10);
	read(0,magic,10);
	if(strcmp(x,"command\n")==0)
	{
	    printf("%s\n","command");
	}
	if(strcmp(magic,"hello\n")==0)
	    printf("%s\n","hello");
    return 0;
}