/*	$OpenBSD: kern_pledge.c,v 1.267 2020/10/29 21:15:27 denis Exp $	*/

/*
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <seccomp.h>

#include "pledge.h"

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

	return EINVAL;
}

int
real_pledge(scmp_filter_ctx ctx, const char *promises, bool isexec)
{
	uint64_t f;
	char *str, *token;

	if (promises == NULL)
		return 1;

	str = strdup(promises);
	token = strtok(str, " ");

	while (token != NULL) {
		if (pledgereq_flags(token) != 0)
			return EINVAL;

		f |= pledgereq_flags(token);
		token = strtok(NULL, " ");
	}

	for (int i = 0; i < SYS_MAXSYSCALL; i++) {
		if (pledge_syscalls[i] == 0)
			continue;

		if (!(pledge_syscalls[i] & f))
			continue;

#if 0
		if (isexec == true) {
			if ((seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0)) != 0)
				return EFAULT;
		} else {
			if ((seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, i, 0)) != 0)
				return EFAULT;
		}
#endif
		if ((seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, i, 0)) != 0)
			return EFAULT;
	}

	return 0;
}

int
pledge(const char *promises, const char *execpromises)
{
	if (promises == NULL)
		return EFAULT;

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		goto fail;

	if(!(real_pledge(ctx, promises, false)) != 0)
		goto fail;

#if 0
	if (execpromises != NULL && strstr(promises, "exec") != NULL)
		if(!(real_pledge(ctx, execpromises, true)) != 0)
			goto fail;
#endif

	if (!seccomp_load(ctx))
		goto fail;

fail:
	seccomp_release(ctx);
	return EFAULT;

	return 0;
}
