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

		// Insert a brk call after the first syscall
		for (;;)
		{
			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
				exit(EXIT_FAILURE);
			}

			// syscall-enter-stop
			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			/* fprintf(stderr, "0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", */
			/* 		syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9); */

			struct user_regs_struct regs_enter, regs_exit, regs_brk_enter1, regs_brk_exit1, regs_brk_enter2, regs_brk_exit2;

			/* save the enter regs */
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_enter) == -1) {
				perror("ptrace getregs");
				exit(EXIT_FAILURE);
			}

			int syscall = regs_enter.orig_rax;

			// let it perform the first syscall regardless
			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
				exit(EXIT_FAILURE);
			}

			// syscall-exit-stop
			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			/* save original system call result */
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_exit) == -1) {
				fputs(" = ?\n", stderr);
				if (errno == ESRCH)
					exit(regs_exit.rdi); // system call was _exit(2) or similar
			}

			/* print system call result */
			fprintf(stderr, "original result = %ld\n", (long)regs_exit.rax);

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
				regs_brk_enter1.rdi = 1000;

				/* resume tracee */
				if (ptrace(PTRACE_SETREGS, cpid, 0, &regs_brk_enter1) == -1) {
					perror("ptrace setregs brk_enter1");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
					perror("ptrace syscall");
					exit(EXIT_FAILURE);
				}

				/* syscall-enter-stop */
				if (waitpid(cpid, 0, 0) == -1) {
					perror("waitpid");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
					perror("ptrace syscall");
					exit(EXIT_FAILURE);
				}

				/* syscall-exit-stop */
				if (waitpid(cpid, 0, 0) == -1) {
					perror("waitpid");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_brk_exit1) == -1) {
					perror("ptrace getregs");
					exit(EXIT_FAILURE);
				}

				unsigned long long current_brk = regs_brk_exit1.rax;
				unsigned long long target_brk = current_brk + CHAMBERSZ;

				printf("current_brk = %llx, target_brk = %llx\n", current_brk, target_brk);

				memcpy(&regs_brk_enter2, &regs_brk_enter1, sizeof(regs_brk_enter2));
				regs_brk_enter2.rdi = target_brk;

				/* resume tracee */
				if (ptrace(PTRACE_SETREGS, cpid, 0, &regs_brk_enter2) == -1) {
					perror("ptrace setregs brk_enter2");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
					perror("ptrace syscall");
					exit(EXIT_FAILURE);
				}

				/* syscall-enter-stop */
				if (waitpid(cpid, 0, 0) == -1) {
					perror("waitpid");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
					perror("ptrace syscall");
					exit(EXIT_FAILURE);
				}

				/* syscall-exit-stop */
				if (waitpid(cpid, 0, 0) == -1) {
					perror("waitpid");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_brk_exit2) == -1) {
					perror("ptrace getregs");
					exit(EXIT_FAILURE);
				}

				/* verify brk success */
				if (regs_brk_exit2.rax != target_brk) {
					fprintf(stderr, "target brk not reached."
							"want 0x%llx, get 0x%llx\n", target_brk, regs_brk_exit2.rax);
					exit(EXIT_FAILURE);
				} else {
					printf("brk insertion is successful."
						   "you can use memory from 0x%llx to 0x%llx (inclusively)\n",
						   current_brk+1, target_brk);
				}

				/* replace regs with regs_exit */
				if (ptrace(PTRACE_SETREGS, cpid, 0, &regs_exit) == -1) {
					perror("ptrace setregs regs_exit");
					exit(EXIT_FAILURE);
				}

				if (ptrace(PTRACE_DETACH, cpid, 0, 0) == -1) {
					perror("ptrace cont");
					exit(EXIT_FAILURE);
				}
				break;
			}
		}
		exit(EXIT_SUCCESS);
	}

    return 0;
}
