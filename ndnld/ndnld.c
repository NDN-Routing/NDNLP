#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ndnld.h"

static void daemonize(void)
{
	if (getppid() == 1) return;
	pid_t pid = fork();
	if (pid < 0) exit(-1);
	if (pid > 0) exit(pid);
	umask(0);
	pid_t sid = setsid();
	if (sid < 0) exit(-2);
	if (chdir("/") < 0) exit(-3);
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}

int main(int argc, char* argv[]) {
	daemonize();

	CapsH_drop();

	PollMgr pm = PollMgr_ctor(50);

	CcnCC cc = CcnCC_ctor();
	CcnCC_pollAttach(cc, pm);
	ConnMgr cmgr = ConnMgr_ctor(pm, cc);

	while (true) {
		PollMgr_poll(pm);
		ConnMgr_run(cmgr);
	}
	
	ConnMgr_dtor(cmgr);
	CcnCC_pollDetach(cc, pm);
	CcnCC_dtor(cc);
	PollMgr_dtor(pm);

	return 0;
}

