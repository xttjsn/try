#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKNAME "socket"

int main(int argc, char *argv[])
{
	int sock, numbytes;
	char buf[1024];
	struct sockaddr_un server;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		exit(1);
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKNAME);
	if (connect(sock, (struct sockaddr *)&server,
				sizeof(struct sockaddr_un)) == -1) {
		perror("connect");
		exit(1);
	}

	for (;;) {
		if (send(sock, "Hello World\n", 14, 0) == -1){
			perror("send");
			exit(1);
		}

		sleep(1);
	}
	return 0;
}
