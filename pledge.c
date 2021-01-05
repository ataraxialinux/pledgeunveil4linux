#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <seccomp.h>

#define	SYS_MAXSYSCALL	313

#define PLEDGE_ALWAYS	0xffffffffffffffffULL
#define PLEDGE_RPATH	0x0000000000000001ULL	/* allow open for read */
#define PLEDGE_WPATH	0x0000000000000002ULL	/* allow open for write */
#define PLEDGE_CPATH	0x0000000000000004ULL	/* allow creat, mkdir, unlink etc */
#define PLEDGE_STDIO	0x0000000000000008ULL	/* operate on own pid */
#define PLEDGE_TMPPATH	0x0000000000000010ULL	/* for mk*temp() */
#define PLEDGE_DNS	0x0000000000000020ULL	/* DNS services */
#define PLEDGE_INET	0x0000000000000040ULL	/* AF_INET/AF_INET6 sockets */
#define PLEDGE_FLOCK	0x0000000000000080ULL	/* file locking */
#define PLEDGE_UNIX	0x0000000000000100ULL	/* AF_UNIX sockets */
#define PLEDGE_ID	0x0000000000000200ULL	/* allow setuid, setgid, etc */
#define PLEDGE_TAPE	0x0000000000000400ULL	/* Tape ioctl */
#define PLEDGE_GETPW	0x0000000000000800ULL	/* YP enables if ypbind.lock */
#define PLEDGE_PROC	0x0000000000001000ULL	/* fork, waitpid, etc */
#define PLEDGE_SETTIME	0x0000000000002000ULL	/* able to set/adj time/freq */
#define PLEDGE_FATTR	0x0000000000004000ULL	/* allow explicit file st_* mods */
#define PLEDGE_PROTEXEC	0x0000000000008000ULL	/* allow use of PROT_EXEC */
#define PLEDGE_TTY	0x0000000000010000ULL	/* tty setting */
#define PLEDGE_SENDFD	0x0000000000020000ULL	/* AF_UNIX CMSG fd sending */
#define PLEDGE_RECVFD	0x0000000000040000ULL	/* AF_UNIX CMSG fd receiving */
#define PLEDGE_EXEC	0x0000000000080000ULL	/* execve, child is free of pledge */
#define PLEDGE_ROUTE	0x0000000000100000ULL	/* routing lookups */
#define PLEDGE_MCAST	0x0000000000200000ULL	/* multicast joins */
#define PLEDGE_VMINFO	0x0000000000400000ULL	/* vminfo listings */
#define PLEDGE_PS	0x0000000000800000ULL	/* ps listings */
#define PLEDGE_DISKLABEL 0x0000000002000000ULL	/* disklabels */
#define PLEDGE_PF	0x0000000004000000ULL	/* pf ioctls */
#define PLEDGE_AUDIO	0x0000000008000000ULL	/* audio ioctls */
#define PLEDGE_DPATH	0x0000000010000000ULL	/* mknod & mkfifo */
#define PLEDGE_DRM	0x0000000020000000ULL	/* drm ioctls */
#define PLEDGE_VMM	0x0000000040000000ULL	/* vmm ioctls */
#define PLEDGE_CHOWN	0x0000000080000000ULL	/* chown(2) family */
#define PLEDGE_CHOWNUID	0x0000000100000000ULL	/* allow owner/group changes */
#define PLEDGE_BPF	0x0000000200000000ULL	/* bpf ioctl */
#define PLEDGE_ERROR	0x0000000400000000ULL	/* ENOSYS instead of kill */
#define PLEDGE_WROUTE	0x0000000800000000ULL	/* interface address ioctls */
#define PLEDGE_UNVEIL	0x0000001000000000ULL	/* allow unveil() */
#define PLEDGE_VIDEO	0x0000002000000000ULL	/* video ioctls */
#define PLEDGE_YPACTIVE 0x8000000000000000ULL /* YP use detected and allowed */

/*
 * Ordered in blocks starting with least risky and most required.
 */
const uint64_t pledge_syscalls[SYS_MAXSYSCALL] = {
	/*
	 * Minimum required
	 */
	[__SNR_exit] = PLEDGE_ALWAYS,
	[__SNR_syslog] = PLEDGE_ALWAYS,	/* stack protector reporting */

	/* "getting" information about self is considered safe */
	[__SNR_getuid] = PLEDGE_STDIO,
	[__SNR_geteuid] = PLEDGE_STDIO,
	[__SNR_getresuid] = PLEDGE_STDIO,
	[__SNR_getgid] = PLEDGE_STDIO,
	[__SNR_getegid] = PLEDGE_STDIO,
	[__SNR_getresgid] = PLEDGE_STDIO,
	[__SNR_getgroups] = PLEDGE_STDIO,
	[__SNR_getpgrp] = PLEDGE_STDIO,
	[__SNR_getpgid] = PLEDGE_STDIO,
	[__SNR_getppid] = PLEDGE_STDIO,
	[__SNR_getsid] = PLEDGE_STDIO,
	[__SNR_getrlimit] = PLEDGE_STDIO,
	[__SNR_gettimeofday] = PLEDGE_STDIO,
	[__SNR_getrusage] = PLEDGE_STDIO,
	[__SNR_clock_getres] = PLEDGE_STDIO,
	[__SNR_clock_gettime] = PLEDGE_STDIO,
	[__SNR_getpid] = PLEDGE_STDIO,

	/* Support for malloc(3) family of operations */
	[__SNR_madvise] = PLEDGE_STDIO,
	[__SNR_mmap] = PLEDGE_STDIO,
	[__SNR_mprotect] = PLEDGE_STDIO,
	[__SNR_munmap] = PLEDGE_STDIO,
	[__SNR_msync] = PLEDGE_STDIO,

	[__SNR_umask] = PLEDGE_STDIO,

	/* read/write operations */
	[__SNR_read] = PLEDGE_STDIO,
	[__SNR_readv] = PLEDGE_STDIO,
	[__SNR_preadv] = PLEDGE_STDIO,
	[__SNR_write] = PLEDGE_STDIO,
	[__SNR_writev] = PLEDGE_STDIO,
	[__SNR_pwritev] = PLEDGE_STDIO,
	[__SNR_recvmsg] = PLEDGE_STDIO,
	[__SNR_recvfrom] = PLEDGE_STDIO | PLEDGE_YPACTIVE,
	[__SNR_ftruncate] = PLEDGE_STDIO,
	[__SNR_lseek] = PLEDGE_STDIO,

	/*
	 * Address selection required a network pledge ("inet",
	 * "unix", "dns".
	 */
	[__SNR_sendto] = PLEDGE_STDIO | PLEDGE_YPACTIVE,

	/*
	 * Address specification required a network pledge ("inet",
	 * "unix", "dns".  SCM_RIGHTS requires "sendfd" or "recvfd".
	 */
	[__SNR_sendmsg] = PLEDGE_STDIO,

	/* Common signal operations */
	[__SNR_nanosleep] = PLEDGE_STDIO,
	[__SNR_sigaltstack] = PLEDGE_STDIO,
	[__SNR_getitimer] = PLEDGE_STDIO,
	[__SNR_setitimer] = PLEDGE_STDIO,

	/*
	 * To support event driven programming.
	 */
	[__SNR_poll] = PLEDGE_STDIO,
	[__SNR_ppoll] = PLEDGE_STDIO,
	[__SNR_epoll_create] = PLEDGE_STDIO,
	[__SNR_epoll_create1] = PLEDGE_STDIO,
	[__SNR_epoll_ctl] = PLEDGE_STDIO,
	[__SNR_epoll_ctl_old] = PLEDGE_STDIO,
	[__SNR_epoll_pwait] = PLEDGE_STDIO,
	[__SNR_epoll_wait] = PLEDGE_STDIO,
	[__SNR_epoll_wait_old] = PLEDGE_STDIO,
	[__SNR_eventfd] = PLEDGE_STDIO,
	[__SNR_select] = PLEDGE_STDIO,

	[__SNR_fstat] = PLEDGE_STDIO,
	[__SNR_fsync] = PLEDGE_STDIO,

	[__SNR_setsockopt] = PLEDGE_STDIO,	/* narrow whitelist */
	[__SNR_getsockopt] = PLEDGE_STDIO,	/* narrow whitelist */

	/* F_SETOWN requires PLEDGE_PROC */
	[__SNR_fcntl] = PLEDGE_STDIO,

	[__SNR_close] = PLEDGE_STDIO,
	[__SNR_dup] = PLEDGE_STDIO,
	[__SNR_dup2] = PLEDGE_STDIO,
	[__SNR_dup3] = PLEDGE_STDIO,
	[__SNR_shutdown] = PLEDGE_STDIO,
	[__SNR_fchdir] = PLEDGE_STDIO,	/* XXX consider tightening */

	[__SNR_pipe] = PLEDGE_STDIO,
	[__SNR_pipe2] = PLEDGE_STDIO,
	[__SNR_socketpair] = PLEDGE_STDIO,

	[__SNR_wait4] = PLEDGE_STDIO,

	/*
	 * Can kill self with "stdio".  Killing another pid
	 * requires "proc"
	 */
	[__SNR_kill] = PLEDGE_STDIO,

	/*
	 * FIONREAD/FIONBIO for "stdio"
	 * Other ioctl are selectively allowed based upon other pledges.
	 */
	[__SNR_ioctl] = PLEDGE_STDIO,

	/*
	 * Path access/creation calls encounter many extensive
	 * checks done during pledge_namei()
	 */
	[__SNR_open] = PLEDGE_STDIO,
	[__SNR_stat] = PLEDGE_STDIO,
	[__SNR_access] = PLEDGE_STDIO,
	[__SNR_readlink] = PLEDGE_STDIO,

	[__SNR_settimeofday] = PLEDGE_SETTIME,

	/*
	 * Needed by threaded programs
	 * XXX should we have a new "threads"?
	 */
	[__SNR_sched_yield] = PLEDGE_STDIO,
	[__SNR_futex] = PLEDGE_STDIO,

	[__SNR_fork] = PLEDGE_PROC,
	[__SNR_vfork] = PLEDGE_PROC,
	[__SNR_setpgid] = PLEDGE_PROC,
	[__SNR_setsid] = PLEDGE_PROC,

	[__SNR_setrlimit] = PLEDGE_PROC | PLEDGE_ID,
	[__SNR_getpriority] = PLEDGE_PROC | PLEDGE_ID,

	[__SNR_setpriority] = PLEDGE_PROC | PLEDGE_ID,

	[__SNR_setuid] = PLEDGE_ID,
	[__SNR_setreuid] = PLEDGE_ID,
	[__SNR_setresuid] = PLEDGE_ID,
	[__SNR_setgid] = PLEDGE_ID,
	[__SNR_setregid] = PLEDGE_ID,
	[__SNR_setresgid] = PLEDGE_ID,
	[__SNR_setgroups] = PLEDGE_ID,

	[__SNR_execve] = PLEDGE_EXEC,

	[__SNR_chdir] = PLEDGE_RPATH,
	[__SNR_openat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[__SNR_faccessat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[__SNR_readlinkat] = PLEDGE_RPATH | PLEDGE_WPATH,
	[__SNR_lstat] = PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_TMPPATH,
	[__SNR_truncate] = PLEDGE_WPATH,
	[__SNR_rename] = PLEDGE_RPATH | PLEDGE_CPATH,
	[__SNR_rmdir] = PLEDGE_CPATH,
	[__SNR_renameat] = PLEDGE_CPATH,
	[__SNR_link] = PLEDGE_CPATH,
	[__SNR_linkat] = PLEDGE_CPATH,
	[__SNR_symlink] = PLEDGE_CPATH,
	[__SNR_symlinkat] = PLEDGE_CPATH,
	[__SNR_unlink] = PLEDGE_CPATH | PLEDGE_TMPPATH,
	[__SNR_unlinkat] = PLEDGE_CPATH,
	[__SNR_mkdir] = PLEDGE_CPATH,
	[__SNR_mkdirat] = PLEDGE_CPATH,

	[__SNR_mknod] = PLEDGE_DPATH,
	[__SNR_mknodat] = PLEDGE_DPATH,

	/* Classify as RPATH, because these leak path information */
	[__SNR_getdents] = PLEDGE_RPATH,
	[__SNR_statfs] = PLEDGE_RPATH,
	[__SNR_fstatfs] = PLEDGE_RPATH,

	[__SNR_utimes] = PLEDGE_FATTR,
	[__SNR_utimensat] = PLEDGE_FATTR,
	[__SNR_chmod] = PLEDGE_FATTR,
	[__SNR_fchmod] = PLEDGE_FATTR,
	[__SNR_fchmodat] = PLEDGE_FATTR,

	[__SNR_chown] = PLEDGE_CHOWN,
	[__SNR_fchownat] = PLEDGE_CHOWN,
	[__SNR_lchown] = PLEDGE_CHOWN,
	[__SNR_fchown] = PLEDGE_CHOWN,

	[__SNR_socket] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[__SNR_connect] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[__SNR_bind] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,
	[__SNR_getsockname] = PLEDGE_INET | PLEDGE_UNIX | PLEDGE_DNS | PLEDGE_YPACTIVE,

	[__SNR_listen] = PLEDGE_INET | PLEDGE_UNIX,
	[__SNR_accept4] = PLEDGE_INET | PLEDGE_UNIX,
	[__SNR_accept] = PLEDGE_INET | PLEDGE_UNIX,
	[__SNR_getpeername] = PLEDGE_INET | PLEDGE_UNIX,

	[__SNR_flock] = PLEDGE_FLOCK | PLEDGE_YPACTIVE,
};

static const struct {
	char *name;
	uint64_t flags;
} pledgereq[] = {
	{ "audio",		PLEDGE_AUDIO },
	{ "bpf",		PLEDGE_BPF },
	{ "chown",		PLEDGE_CHOWN | PLEDGE_CHOWNUID },
	{ "cpath",		PLEDGE_CPATH },
	{ "disklabel",		PLEDGE_DISKLABEL },
	{ "dns",		PLEDGE_DNS },
	{ "dpath",		PLEDGE_DPATH },
	{ "drm",		PLEDGE_DRM },
	{ "error",		PLEDGE_ERROR },
	{ "exec",		PLEDGE_EXEC },
	{ "fattr",		PLEDGE_FATTR | PLEDGE_CHOWN },
	{ "flock",		PLEDGE_FLOCK },
	{ "getpw",		PLEDGE_GETPW },
	{ "id",			PLEDGE_ID },
	{ "inet",		PLEDGE_INET },
	{ "mcast",		PLEDGE_MCAST },
	{ "pf",			PLEDGE_PF },
	{ "proc",		PLEDGE_PROC },
	{ "prot_exec",		PLEDGE_PROTEXEC },
	{ "ps",			PLEDGE_PS },
	{ "recvfd",		PLEDGE_RECVFD },
	{ "route",		PLEDGE_ROUTE },
	{ "rpath",		PLEDGE_RPATH },
	{ "sendfd",		PLEDGE_SENDFD },
	{ "settime",		PLEDGE_SETTIME },
	{ "stdio",		PLEDGE_STDIO },
	{ "tape",		PLEDGE_TAPE },
	{ "tmppath",		PLEDGE_TMPPATH },
	{ "tty",		PLEDGE_TTY },
	{ "unix",		PLEDGE_UNIX },
	{ "unveil",		PLEDGE_UNVEIL },
	{ "video",		PLEDGE_VIDEO },
	{ "vminfo",		PLEDGE_VMINFO },
	{ "vmm",		PLEDGE_VMM },
	{ "wpath",		PLEDGE_WPATH },
	{ "wroute",		PLEDGE_WROUTE },
};

uint64_t
pledgereq_flags(const char *req_name)
{
	int base = 0;
	int i, lim, cmp;

	for (lim = sizeof(pledgereq) / sizeof(*pledgereq); lim != 0; lim >>= 1) {
		i = base + (lim >> 1);
		cmp = strcmp(req_name, pledgereq[i].name);
		if (cmp == 0) {
			return (pledgereq[i].flags);
		}

		if (cmp > 0) {
			base = i + 1;
			lim--;
		}
	}

	return 0;
}

int
real_pledge(const char *promises)
{
	int f;
	char *str, *token;

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

	if (promises == NULL)
		return 1;

	str = strdup(promises);
	token = strtok(str, " ");

	while (token != NULL) {
		f = pledgereq_flags(token);
		switch (f) {
			default:
				fprintf(stderr, "not implemented\n");
		}
		token = strtok(NULL, " ");
	}

	seccomp_load(ctx);

	return 0;
}

#if 0
int
pledge(const char *promises, const char *execpromises)
{
	real_pledge("stdio unix");
	return 0;
}
#endif

int
main()
{
	pid_t pid;

	printf("no restrictions\n");
	real_pledge("stdio unix");
	pid = getpid ();
	printf("restrictions, %d\n", pid);
	return 0;
}
