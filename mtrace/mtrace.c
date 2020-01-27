#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {
	printf(
		"mtrace <program>"
		);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		exit(1);
	}

	struct stat progstat;
	char *progname = argv[1];
	if (stat(progname, &progstat) == -1) {
		perror("stat()");
		exit(1);
	}

	uid_t euid = geteuid();
	gid_t egid = getegid();
	if (((progstat.st_uid == euid) && ((progstat.st_mode & S_IXUSR) == 0)) &&
		((progstat.st_gid == egid) && ((progstat.st_mode & S_IXGRP) == 0)) &&
		((progstat.st_mode & S_IXOTH) == 0)) {
		perror("no execute permission");
		exit(1);
	}

	pid_t cpid = fork();
	if (cpid == -1) {
		perror("fork");
		exit(1);
	}

	if (cpid == 0) {
		// Child
		printf("Child PID is %ld\n", (long) getpid());
		printf("executing %s\n", progname);
		printf("chld argv[1]: %s\n", argv[2]);
		printf("argc = %d\n", argc);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(progname, &argv[1]);
	} else {

		// Sync with PTRACE_TRACEME
		waitpid(cpid, 0, 0);
		ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL);

		for (;;) {
			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
				exit(EXIT_FAILURE);
			}
			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			struct user_regs_struct regs;
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs) == -1) {
				perror("ptrace getregs");
				exit(EXIT_FAILURE);
			}

			long long syscall = regs.orig_rax;
			fprintf(stderr, "0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n",
					syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);

			fprintf(stderr, "rip=0x%llx\n", regs.rip);
			fprintf(stderr, "rbp=0x%llx\n", regs.rbp);

			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall resuming");
				exit(EXIT_FAILURE);
			}
			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			/* Get system call result */
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs) == -1) {
				fputs(" = ?\n", stderr);
				if (errno == ESRCH)
					exit(regs.rdi); // system call was _exit(2) or similar
			}

			/* Print system call result */
			fprintf(stderr, " = %ld\n", (long)regs.rax);
			fprintf(stderr, "rip -> 0x%llx\n", regs.rip);
		}
		exit(EXIT_SUCCESS);
	}

    return 0;
}
