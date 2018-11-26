#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
char user_command[0x20];
void cmd1()
{
	printf("first_cmd\n");
}
void cmd2()
{
	printf("second_cmd\n");
}

void cmd3()
{
	printf("crash_cmd\n");
}


int static_strcmp(char*a,char*b)
{
	for(;*a;a++,b++)
	{
		if(*a!=*b)
			break;
	}
	return *a-*b;
}


int main(int argc, char*argv[])
{
	read ( 0 , user_command , 16) ;
	if ( static_strcmp("first_cmd\n",user_command) == 0)
		cmd1( );
	else if (static_strcmp("second_cmd\n" , user_command ) == 0)
		cmd2( ) ;
	else if (static_strcmp("crash_cmd\n" , user_command ) == 0)
		cmd3( ) ;
	else
		printf("no cmd\n");
	return 0;
}