#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>

#define SOCKNAME "socket"

int main(int argc, char* argv[]) {
	int sock, clientsock, rval;
	struct sockaddr_un server;
	char buf[1024];

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket()");
		exit(1);
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKNAME);
	if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
		perror("bind()");
		exit(1);
	}

	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int))) {
		perror("setsockopt");
		exit(1);
	}

	printf("Socket has name %s\n", server.sun_path);
	listen(sock, 5);
	for (;;) {
		clientsock = accept(sock, 0, 0);
		printf("new client");
		if (clientsock < 0)
			perror("accept()");
		else do {
				bzero(buf, sizeof(buf));
				if ((rval = read(clientsock, buf, 1024)) < 0)
					perror("read()");
				else if (rval == 0)
					printf("Connection end\n");
				else
					printf("-->%s\n", buf);
			} while (rval > 0);
		close(clientsock);
	}
	close(sock);
	unlink(SOCKNAME);
}
