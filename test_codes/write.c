#include <stdio.h>         // printf()
#include <string.h>        // strlen()
#include <fcntl.h>         // O_WRONLY
#include <unistd.h>        // write(), close()

int main()
{
   char  *temp = "badayak.com\n";
   int    fd;


   printf("Write program executed\n");

   if ( 0 < ( fd = open( "./test.txt", O_WRONLY | O_CREAT | O_EXCL, 0644))){
      write( fd, temp, strlen( temp));
      close( fd);
   } else {
      printf( "파일 열기에 실패했습니다.\n");
   }
   return 0;
}


