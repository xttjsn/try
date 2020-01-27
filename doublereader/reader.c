#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFSZ 10

int main(int argc, char *argv[])
{
    int randomfd = open("/dev/urandom", O_RDONLY);
	char buf[BUFSZ];
	int status;
	for (;;) {
		status = read(randomfd, buf, BUFSZ);
		if (status == 0) {
			perror("eof");
			exit(EXIT_FAILURE);
		} else if (status < 0) {
			perror("read()");
			continue;
		}
		printf("read BUFSZ bytes: %s\n", buf);
	}

    return 0;
}
