#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <seccomp.h>

static const struct {
	char *name;
	uint64_t flags;
} pledgereq[] = {
	{ "audio",		1 },
	{ "bpf",		2 },
	{ "chown",		3 },
	{ "cpath",		4 },
	{ "disklabel",		5 },
	{ "dns",		6 },
	{ "dpath",		7 },
	{ "drm",		8 },
	{ "error",		9 },
	{ "exec",		10 },
	{ "fattr",		11 },
	{ "flock",		12 },
	{ "getpw",		13 },
	{ "id",			14 },
	{ "inet",		15 },
	{ "mcast",		16 },
	{ "pf",			17 },
	{ "proc",		18 },
	{ "prot_exec",		19 },
	{ "ps",			20 },
	{ "recvfd",		21 },
	{ "route",		22 },
	{ "rpath",		23 },
	{ "sendfd",		24 },
	{ "settime",		25 },
	{ "stdio",		26 },
	{ "tape",		27 },
	{ "tmppath",		28 },
	{ "tty",		29 },
	{ "unix",		30 },
	{ "unveil",		31 },
	{ "video",		32 },
	{ "vminfo",		33 },
	{ "vmm",		34 },
	{ "wpath",		35 },
	{ "wroute",		36 },
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
			case 26:
				printf("unrestricting write\n");
				seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
				seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
				seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
				seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
				break;
			case 30:
				printf("unrestricting unix\n");
				seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
				break;
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
