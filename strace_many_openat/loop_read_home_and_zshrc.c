#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	char *home = getenv("HOME");
	char buf[1024];
	ssize_t sz;

	for (;;) {
		int homefd = open(home, O_RDONLY);
		sz = read(homefd, buf, 1024);
		int zshrcfd = openat(homefd, ".zshrc", O_RDONLY);
		sz = read(zshrcfd, buf, 1024);
	}
}
