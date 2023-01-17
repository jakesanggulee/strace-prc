#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

extern char **environ;

int main(int argc, char *argv[])
{
    char **new_argv;
    char command[]  = "./write";
    int  idx;

    new_argv = (char **)malloc(sizeof(char *) * (argc + 1));
    new_argv[0] = command;

    for(idx = 1; idx < argc; idx++) {
        new_argv[idx] = argv[idx];
    }

    new_argv[argc] = NULL;
    

    if(execve("./write", new_argv, environ) == -1) {
        return 1;
    }


	return 0;
}
