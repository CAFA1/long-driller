#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>  
struct mm{
  int crc1;
  int crc2;
};
int match(int a,int b)
{
  return a==b;
}
int main(int argc, char **argv)
{
  int fd;
  char  buffer[28] = {0};
  char buffer_png[] = {0x49,0x48,0x44,0x52,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x28,0x08,0x03,0x00,0x00,0x00};
  struct mm mm1;
    //fd = open("serial.txt", O_RDONLY);
   int crc_code;
   int crcfile;
   int i;
   int buffer_sz;  
   //printf("%s\n%s\n", argv[0], argv[1]);
    
    
  //fd = open(argv[1], O_RDONLY);
  read(0, buffer, 24);
   //buffer_sz = strlen(buffer);  
   crcfile = *(long unsigned int*)((char*)(&buffer[20]));
   crc_code = crc32(0, (const Bytef*)buffer, 20);  
   //for(i=0;i<20;i++) 
  // {
   // crc_code = crc_code + (int)(buffer[i]);
   //}
  mm1.crc2=crc_code;
  printf("crc_code : %x\n", crc_code);  
  printf("crc_code_file : %x\n", crcfile); 

  if(crc_code==0x12345678)
  {
    printf("match\n");
    
  }
 
  //close(fd);  
    
  return 0;
  
}