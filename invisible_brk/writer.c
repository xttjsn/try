#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define FPATHSZ 120
#define FNAME "/output"
#define FATAL(arg) { perror(arg); exit(EXIT_FAILURE); }
#define DATA "helloworld"
#define DATASZ 10

int main()
{
	char *fpath = getcwd(NULL, FPATHSZ);
	strcat(fpath, FNAME);

	int fd;

	if (( fd = open(fpath, O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) == -1) {
		FATAL("open()");
	}

	/* This one will fail */
	/* unsigned long current_brk = syscall(SYS_brk, -1); */
	/* printf("current_brk = %lx\n", current_brk); */

	if (write(fd, DATA, DATASZ) == -1)  {
		FATAL("write()");
	}

    return 0;
}
