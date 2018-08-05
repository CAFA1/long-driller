#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <match.h>
int main(int argc, char **argv)
{
	char  buffer[28] = {0};
	int crc_code;
	int crcfile; 
	read(0, buffer, 24); 
	crcfile = *(  int*)((char*)(&buffer[0]));
	crc_code = *(  int*)((char*)(&buffer[4])); 
	if(match(crc_code,0x12345678))
	{
		printf("match 1\n");
		if(match(crcfile,0x12345678))
		{
			printf("match 2\n");
		}
	}
	return 0;
  
}