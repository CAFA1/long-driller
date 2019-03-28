#include<stdio.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
  int  fd;
  char  buff[260] = {0};
  //fd = open("serial.txt", O_RDONLY);
  printf("%s\n%s\n", argv[0], argv[1]);
  fd = open(argv[1], O_RDONLY);
  read(fd, buff, 256);
  close(fd);
  if (buff[0] != 'a')
{
printf("Bad boy:a\n");
return 1;
}
  if (buff[1] != 'b') 
{
printf("Bad boy:b\n");
return 1;
}
  if (buff[2] != 'c')
{
printf("Bad boy:c\n");
return 1;
}
  if (buff[3] != 'd')
{
printf("Bad boy:d\n");
return 1;
}
  if (buff[4] != 'e')
{
printf("Bad boy:e\n");
return 1;
}
  printf("Good boy\n");
  return 0;
}
