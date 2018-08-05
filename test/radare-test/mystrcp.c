#include <stdio.h>
#include <unistd.h>
#include <string.h>
void mystrcpy(char*a,char*b)
{
	strcpy(a,b);
	return;
}
int main(int argc, char*argv[])
{
	char x[100];
	char y[100];
	
	read(0,x,100);
	mystrcpy(y,x);
	if(strcmp(x,"command")==0)
	{
	    printf("%s\n","command");
	}
	
    return 0; 
}