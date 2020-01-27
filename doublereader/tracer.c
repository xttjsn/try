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

		// Make it a double write

		for (;;) {
			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
				exit(EXIT_FAILURE);
			}

			// syscall-enter-stop
			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			struct user_regs_struct regs, regs_result1, regs_result2;
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs) == -1) {
				perror("ptrace getregs");
				exit(EXIT_FAILURE);
			}

			long long syscall = regs.orig_rax;

			// let it perform the first syscall regardless
			if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
				perror("ptrace syscall");
				exit(EXIT_FAILURE);
			}

			if (waitpid(cpid, 0, 0) == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			/* Get system call result */
			if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_result1) == -1) {
				fputs(" = ?\n", stderr);
				if (errno == ESRCH)
					exit(regs_result1.rdi); // system call was _exit(2) or similar
			}

			/* Print system call result */
			fprintf(stderr, "result1 = %ld\n", (long)regs_result1.rax);

			// if it's SYS_write, redo it
			if (syscall == SYS_write) {
				// reduce rip in order to re-execute the syscall
				regs.rip -= 2;
				regs.rax = syscall;
				if (ptrace(PTRACE_SETREGS, cpid, 0, &regs) == -1) {
					perror("ptrace setregs");
					exit(EXIT_FAILURE);
				}
				// perform the second write
				{
					// Let the tracee resume
					if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
						perror("ptrace syscall");
						exit(EXIT_FAILURE);
					}

					// syscall-enter-stop
					if (waitpid(cpid, 0, 0) == -1) {
						perror("waitpid");
						exit(EXIT_FAILURE);
					}

					// verify that it's the same syscall
					struct user_regs_struct new_regs;
					if (ptrace(PTRACE_GETREGS, cpid, 0, &new_regs) == -1) {
						perror("ptrace getregs");
						exit(EXIT_FAILURE);
					}
					if (new_regs.orig_rax != regs.orig_rax) {
						fprintf(stderr, "duplicate syscall failed."
								"expecting %llu, getting %llu\n", regs.rax, new_regs.rax);
						exit(EXIT_FAILURE);
					}

					// Let the tracee resume
					if (ptrace(PTRACE_SYSCALL, cpid, 0, 0) == -1) {
						perror("ptrace syscall");
						exit(EXIT_FAILURE);
					}

					// syscall-exit-stop
					if (waitpid(cpid, 0, 0) == -1) {
						perror("waitpid");
						exit(EXIT_FAILURE);
					}

					/* Get system call result */
					if (ptrace(PTRACE_GETREGS, cpid, 0, &regs_result2) == -1) {
						fputs(" = ?\n", stderr);
						if (errno == ESRCH)
							exit(regs_result2.rdi); // system call was _exit(2) or similar
					}

					/* Print system call result */
					fprintf(stderr, "result2 = %ld\n", (long)regs_result2.rax);
				}
			}
		}
		exit(EXIT_SUCCESS);
	}

    return 0;
}
