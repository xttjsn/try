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
#define TRACEE "/writer"
#define CHAMBERSZ 1024
#define FATAL(args) { perror(args); exit(EXIT_FAILURE); }

struct tracee {
	int cpid;
};

int resume_syscall(struct tracee *t, struct user_regs_struct *regs_out) {
	if (ptrace(PTRACE_SYSCALL, t->cpid, 0, 0) == -1)
		return -1;

	if (waitpid(t->cpid, 0, 0) == -1)
		return -1;

	if (regs_out != NULL && ptrace(PTRACE_GETREGS, t->cpid, 0, regs_out) == -1)
		return -1;

	return 0;
}

int resume_syscall2(struct tracee *t, struct user_regs_struct *regs_in,
					struct user_regs_struct *regs_out) {
	if (ptrace(PTRACE_SETREGS, t->cpid, 0, regs_in) == -1)
		return -1;
	return resume_syscall(t, regs_out);
}

int detach(struct tracee *t, struct user_regs_struct *regs_in) {
	if (ptrace(PTRACE_SETREGS, t->cpid, 0, regs_in) == -1)
		return -1;

	if (ptrace(PTRACE_DETACH, t->cpid, 0, 0) == -1)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	char tracee_path[BUFSZ];
	char *tracee_argv[] = { tracee_path, NULL };

	if (getcwd(tracee_path, BUFSZ) == NULL) {
		FATAL("getcwd()");
	}

	if (strcat(tracee_path, TRACEE) != tracee_path) {
		FATAL("strcat");
	}

	pid_t cpid = fork();
	if (cpid == -1) {
		FATAL("fork");
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

		struct tracee t = {
			.cpid = cpid,
		};

		struct user_regs_struct regs_enter, regs_exit, regs_brk_enter1, regs_brk_exit1, regs_brk_enter2, regs_brk_exit2;

		// Insert a brk call after the first syscall
		for (;;)
		{
			if (resume_syscall(&t, &regs_enter) == -1) {
				FATAL("resume on regs_enter");
			}

			/* fprintf(stderr, "0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", */
			/* 		syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9); */

			int syscall = regs_enter.orig_rax;

			if (resume_syscall(&t, &regs_exit) == -1) {
				FATAL("resume on regs_exit");
			}

			/* print system call result */
			/* fprintf(stderr, "original result = %ld\n", (long)regs_exit.rax); */

			/* insert brk */
			if (syscall == SYS_write)
			{
				printf("SYS_write encountered\n");

				memcpy(&regs_brk_enter1, &regs_enter, sizeof(regs_enter));
				regs_brk_enter1.rip -= 2;
				regs_brk_enter1.rax = SYS_brk;
				regs_brk_enter1.orig_rax = SYS_brk;
				regs_brk_enter1.rsi = 0;
				regs_brk_enter1.rdx = 0;
				regs_brk_enter1.r10 = 0;
				regs_brk_enter1.r8 = 0;
				regs_brk_enter1.r9 = 0;

				/* intentionally causing it to fail, in order to get the current break. */
				regs_brk_enter1.rdi = -1;

				/* resume tracee */
				if (resume_syscall2(&t, &regs_brk_enter1, NULL) == -1) {
					FATAL("resume on regs_brk_enter1");
				}

				if (resume_syscall(&t, &regs_brk_exit1) == -1) {
					FATAL("resume on regs_brk_enter1");
				}

				unsigned long long current_brk = regs_brk_exit1.rax;
				unsigned long long target_brk = current_brk + CHAMBERSZ;

				printf("current_brk = %llx, target_brk = %llx\n", current_brk, target_brk);

				memcpy(&regs_brk_enter2, &regs_brk_enter1, sizeof(regs_brk_enter2));
				regs_brk_enter2.rdi = target_brk;

				/* resume tracee */
				if (resume_syscall2(&t, &regs_brk_enter2, NULL) == -1) {
					FATAL("resume on regs_brk_enter2");
				}

				if (resume_syscall(&t, &regs_brk_exit2) == -1) {
					FATAL("resume on regs_brk_exit2");
				}

				/* verify brk success */
				if (regs_brk_exit2.rax != target_brk) {
					fprintf(stderr, "target brk not reached."
							"want 0x%llx, get 0x%llx\n", target_brk, regs_brk_exit2.rax);
				} else {
					printf("brk insertion is successful."
						   "you can use memory from 0x%llx to 0x%llx (inclusively)\n",
						   current_brk+1, target_brk);
				}

				if (detach(&t, &regs_exit) == -1) {
					FATAL("detach");
				}

				break;
			}
		}
		exit(EXIT_SUCCESS);
	}

    return 0;
}
