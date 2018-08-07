#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
void cmd1()
{
	printf("cmd1\n");
}
void cmd2()
{
	printf("cmd2\n");
}
int static_strcmp(char*a,char*b)
{
	
	return a[0]==b[0];
}
/*
int static_strcmp(char*a,char*b)
{
	for(;*a;a++,b++)
	{
		if(*a!=*b)
			break;
	}
	return *a-*b;
}
*/

int main(int argc, char*argv[])
{
	char user_command[20];
	read ( 0 , user_command , 10) ;

	if ( static_strcmp("first_cmd" , user_command ) == 0)
		cmd1( );

	else if (static_strcmp("second_cmd" , user_command ) == 0)
		cmd2 ( ) ;

	else if (static_strcmp("crash_cmd" , user_command ) == 0)
		abort ( ) ;
	return 0;
}