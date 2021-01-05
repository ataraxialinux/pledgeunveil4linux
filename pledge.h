#ifndef _PLEDGE_H
#define _PLEDGE_H

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
#define PLEDGE_YPACTIVE 0x8000000000000000ULL   /* YP use detected and allowed */

#endif
