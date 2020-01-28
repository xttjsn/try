#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSZ 100
#define TRACEE "/writer"
#define CHAMBERSZ 1024
#define FATAL(args) { perror(args); exit(EXIT_FAILURE); }
#define SOCKNAME "socket"
#define ALIGN(arg, align) ((arg) + ((align) - 1)) & ~((align) - 1)
#define ALIGN_WORD(arg) ALIGN(arg, sizeof(long))

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

		struct user_regs_struct regs_enter, regs_exit,
			regs_brk_enter1, regs_brk_exit1,
			regs_brk_enter2, regs_brk_exit2,
			regs_socket_enter1, regs_socket_exit1,
			regs_connect_enter1, regs_connect_exit1;

		// Insert a brk call after the first syscall
		for (;;)
		{
			if (resume_syscall(&t, &regs_enter) == -1) {
				FATAL("resume on regs_enter");
			}

			/* fprintf(stderr, "0x%llx(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx)\n", */
			/* 		syscall, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9); */

			int syscall = regs_enter.orig_rax;
			unsigned long long current_brk, target_brk;

			if (resume_syscall(&t, &regs_exit) == -1) {
				FATAL("resume on regs_exit");
			}

			/* Replace open() with a brk(), a socket(), and a connect() */
			/* This works by allocating an area we call chamber using brk(), */
			/* and then store a struct sockaddr_un in it.  */
			/* Then we invoke socket() and connect() */
			if (syscall == SYS_openat)
			{
				printf("SYS_write encountered\n");

				/* brk and store struct sockaddr_un */
				{
					memcpy(&regs_brk_enter1, &regs_enter, sizeof(regs_enter));
					regs_brk_enter1.rip -= 2;
					regs_brk_enter1.rax = SYS_brk;
					/* intentionally causing it to fail, in order to get the current break. */
					regs_brk_enter1.rdi = -1;

					if (resume_syscall2(&t, &regs_brk_enter1, NULL) == -1) {
						FATAL("resume on regs_brk_enter1");
					}

					if (resume_syscall(&t, &regs_brk_exit1) == -1) {
						FATAL("resume on regs_brk_enter1");
					}

					current_brk = regs_brk_exit1.rax;
					target_brk = current_brk + ALIGN_WORD(sizeof(struct sockaddr_un));
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
						FATAL("");
					}

					printf("brk insertion is successful."
						   "you can use memory from 0x%llx to 0x%llx (inclusively)\n",
						   current_brk, target_brk-1);

					/* store struct */
					unsigned int addrsz = ALIGN_WORD(sizeof(struct sockaddr_un));
					char *server = malloc(addrsz);
					struct sockaddr_un *serveraddr = (struct sockaddr_un *)server;
					memset(server, 0, addrsz);
				    serveraddr->sun_family = AF_UNIX;
					strcpy(serveraddr->sun_path, SOCKNAME);

					unsigned long offset = 0;
					for (offset = 0; offset < addrsz; offset += sizeof(long)) {
						/* unsigned long from = *(unsigned long*)(base + offset); */
						unsigned long from = *(unsigned long*)(((unsigned long)server) + offset);
						unsigned long to = current_brk + offset;
						printf("copying word 0x%lx to tracee address at 0x%lx\n", from, to);
						if (ptrace(PTRACE_POKEDATA, cpid,
								   to,
								   from) == -1) {
							FATAL("ptrace pokedata");
						}
					}

					/* verify that struct is properly copied */
					for (offset = 0;
						 offset < addrsz; offset += sizeof(long)) {
						unsigned long from = current_brk + offset;
						long word;
						unsigned long expect = *(unsigned long*)(((unsigned long)server) + offset);
						printf("checking word at tracee address 0x%lx verses local word 0x%lx\n",
							   from, expect);

						if ((word = ptrace(PTRACE_PEEKDATA, cpid, from, 0)) == -1)
							FATAL("ptrace peekdata");
						if ((unsigned long)word != expect) {
							fprintf(stderr, "expecting 0x%08lx, getting 0x%08lx\n", (unsigned long)word, word);
							FATAL("sockaddr_un is not properly copied");
						}
					}


					printf("struct sockaddr_un successfully stored at %llx\n", current_brk);
				}

				/* call socket() */
				{
					memcpy(&regs_socket_enter1, &regs_brk_enter1, sizeof(regs_brk_enter1));
					regs_socket_enter1.rax = SYS_socket;
					regs_socket_enter1.rdi = AF_UNIX;
					regs_socket_enter1.rsi = SOCK_STREAM;
					regs_socket_enter1.rdx = 0;

					if (resume_syscall2(&t, &regs_socket_enter1, NULL) == -1)
						FATAL("resume on regs_socket_enter1");

					if (resume_syscall(&t, &regs_socket_exit1) == -1)
						FATAL("resume on regs_socket_exit1");

					if (regs_socket_exit1.rax == (unsigned long)-1)
						FATAL("socket() failed");

					printf("socket() returned 0x%llx\n", regs_socket_exit1.rax);
				}

				/* call connect */
				{
					memcpy(&regs_connect_enter1, &regs_brk_enter1, sizeof(regs_brk_enter1));
					regs_connect_enter1.rax = SYS_connect; printf("rax = 0x%x\n", SYS_connect);
					regs_connect_enter1.rdi = regs_socket_exit1.rax; printf("rdi = 0x%llx\n", regs_socket_exit1.rax);
					regs_connect_enter1.rsi = current_brk; printf("rsi = 0x%llx\n", current_brk);
					regs_connect_enter1.rdx = sizeof(struct sockaddr_un); printf("rdx = 0x%lx\n", sizeof(struct sockaddr_un));

					if (resume_syscall2(&t, &regs_connect_enter1, NULL) == -1)
						FATAL("resume on regs_connect_enter1");

					if (resume_syscall(&t, &regs_connect_exit1) == -1)
						FATAL("resume on regs_connect_enter1");

					if (regs_connect_exit1.rax != 0) {
						fprintf(stderr, "regs_connect_exit1.orig_rax = 0x%llx\n", regs_connect_exit1.orig_rax);
						fprintf(stderr, "regs_connext_exit1.rax = 0x%llx\n", regs_connect_exit1.rax);
						FATAL("connect() failed");
					}

					printf("connect() succeeds");
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
