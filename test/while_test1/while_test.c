#include <stdio.h>
#include <unistd.h>
#include <string.h>
int check(char*x,int depth)
{
    if(depth>=100)
    {
        return 0;
    }
    else
    {
        int count = (*x=='B') ? 1 : 0;
        count += check(x+1,depth+1);
        return count;
    }
}
int main(int argc, char*argv[])
{
	char y[104];
	char x[100];
	int magic;
	read(0,y,104);
	memcpy(x,y,100);
	memcpy((char*)&magic,(char*)&x[100],4);
	if(check(x,0)==25)
	{
	    printf("check pass\n");
	    if(magic==0x42d614f8)
	    {
	        printf("magic pass\n");
	    }
	}
}