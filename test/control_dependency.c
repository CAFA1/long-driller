#include <stdio.h>
#include <unistd.h>
#include <string.h>
int check(char*x,char*y)
{
    if(!strcmp(x,y))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main(int argc, char*argv[])
{

	char x[100];

	read(0,x,100);


	if(check(x,"pwd")==1)
	{
	    printf("check pwd pass\n");

	}
	else
	{
	    printf("no check pwd pass\n");
	}
	if(check(x,"cwd")==1)
	{
	    printf("check cwd pass\n");

	}
	else
	{
	    printf("no check cwd pass\n");

	}
}