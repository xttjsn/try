#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 100
#define TRACEE "/reader"

int main(int argc, char *argv[])
{
	char tracee_path[BUFSZ];
	char *tracee_argv[] = { tracee_path, NULL };

	if (getcwd(tracee_path, BUFSZ) == NULL) {
		perror("getcwd()");
		exit(EXIT_FAILURE);
	}

	if (strcat(tracee_path, TRACEE) != tracee_path) {
		perror("strcat");
		exit(EXIT_FAILURE);
	}

	pid_t cpid = fork();
	if (cpid == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (cpid == 0) {
		// Child
		printf("Child PID is %ld\n", (long) getpid());
		printf("tracee_path %s\n", tracee_path);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(tracee_path, tracee_argv);

	} else {
		// Sync with PTRACE_TRACEME
		waitpid(cpid, 0, 0);
		ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

		int readcnt = 0;

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
			/* fprintf(stderr, "0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", */
			/* 		syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9); */

			if (syscall == SYS_read) {
				readcnt++;
			}

			// intercepting every 3 read() after the first 5 reads
			if (syscall == SYS_read && (readcnt % 10 == 0) && (readcnt > 5)) {
				printf("intercepting read()");
				regs.rax = -1;
			}

			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
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

			if (syscall == SYS_read && (readcnt % 10 == 0) && (readcnt > 5)) {
				// Block this read
				regs.rax = -EPERM;
				ptrace(PTRACE_SETREGS, cpid, 0, &regs);
			}

			/* Print system call result */
			/* fprintf(stderr, " = %ld\n", (long)regs.rax); */


		}
		exit(EXIT_SUCCESS);
	}

    return 0;
}
