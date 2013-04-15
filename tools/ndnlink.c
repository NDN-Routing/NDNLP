#include <stdlib.h>
#include <stdio.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include "ndnld.h"

//#define Link_lossy 0
#define Link_lossy 0.02

int main(int argc, char* argv[]) {
	CapsH_drop();
	if (argc < 3) {
		printf("ndnlink ccnx:/ndnld-test ::FFFF:192.168.6.35\nndnlink ccnx:/ndnld-test eth1 08:00:27:a7:ef:fa\n");
		return 9;
	}

	int count;
	PollMgr pm = PollMgr_ctor(50);

	CcnCC cc = CcnCC_ctor();
	CcnCC_pollAttach(cc, pm);

	CcnLAC lac = CcnLAC_ctor();
	CcnLAC_initialize(lac, CcnCC_ccndid(cc), pm);

	count = 20;
	while (--count > 0 && !CcnLAC_ready(lac)) PollMgr_poll(pm);
	if (CcnCC_error(cc) || CcnLAC_error(lac) || !CcnLAC_ready(lac)) return 1;

	struct ccn_charbuf* prefix = ccn_charbuf_create();
	ccn_name_from_uri(prefix, argv[1]);
	CcnH_regPrefix(CcnPrefixOp_register, CcnCC_ccnh(cc), CcnCC_ccndid(cc), CcnLAC_faceid(lac), prefix);
	ccn_charbuf_destroy(&prefix);

	LMD lmd; Link link; SockAddr rAddr;
	if (argc == 3) {
		lmd = LinkC_lUdp(pm);
		if (lmd == NULL) return 2;
		rAddr = LinkC_parseIP(argv[2]);
		if (rAddr == NULL) return 3;
		link = LinkC_rUdp(lmd, rAddr);
		if (link == NULL) return 4;
	} else {
		lmd = LinkC_lEth(pm, argv[2]);
		if (lmd == NULL) return 2;
		rAddr = LinkC_parseEther(argv[3]);
		if (rAddr == NULL) return 3;
		link = LinkC_rEth(lmd, rAddr);
		if (link == NULL) return 4;
	}

	Link_setLossy(link, Link_lossy);
	NdnlpSvc svc = NdnlpSvc_ctor(lac, link, CMPConn_Flags_RLA, CMPConn_SentPktsCapacity_default, CMPConn_RetryCount_default, CMPConn_RetransmitTime_default, CMPConn_AcknowledgeTime_default);

	printf("pollmgr count: %d, first: %d\n", pm->count, pm->fds[0].fd);
	while (true) {
		PollMgr_poll(pm);
		NdnlpSvc_run(svc);
	}
	
	Link_dtor(link);
	SockAddr_dtor(rAddr);
	LMD_dtor(lmd);
	CcnCC_pollDetach(cc, pm);
	CcnCC_dtor(cc);
	PollMgr_dtor(pm);

	return 0;
}

