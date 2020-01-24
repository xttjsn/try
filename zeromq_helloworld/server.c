#include <czmq.h>

int main(int argc, char *argv[])
{
    zsock_t *responder = zsock_new(ZMQ_REP);
	int rc = zsock_bind(responder, "ipc://./socket");
	printf("rc = %d\n", rc);

	while (1) {
		char *str = zstr_recv(responder);
		printf("Received Hello\n");
		sleep(1);
		zstr_send(responder, "World");
		zstr_free(&str);
	}
    return 0;
}
