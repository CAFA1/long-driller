#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char*argv[])
{
	char x[100];
	int a,b,c;
	read(0,x,100);
	a=*(int*)&x[0];
	b=*(int*)&x[1];
	c=a>>2&b<<2;
	printf("%x\n",c);
	return 1;
}