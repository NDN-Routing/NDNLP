#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <CUnit/CUnit.h>
#include "ndnld.h"

void test_Link_stream(void) {
	int sockets[4]; int res;
	CU_ASSERT(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockets + 0));
	CU_ASSERT(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockets + 2));
	for (int i = 0; i < 4; ++i) {
		res = fcntl(sockets[i], F_GETFL);
		CU_ASSERT_NOT_EQUAL(res, -1);
		CU_ASSERT(0 == fcntl(sockets[i], F_SETFL, res | O_NONBLOCK));
	}

	NBS nbs1 = NBS_ctor(sockets[1], sockets[2], false);
	NBS nbs2 = NBS_ctor(sockets[3], sockets[0], false);
	PollMgr pm = PollMgr_ctor(50);
	NBS_pollAttach(nbs1, pm); NBS_pollAttach(nbs2, pm);
	Link target1 = Link_ctorStream(nbs1);
	Link target2 = Link_ctorStream(nbs2);
	PollMgr_poll(pm);

	Link_write(target1, NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x01\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\xAA\xC5\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCD\x00\x00", 39, true));
	Link_write(target1, NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x02\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\x9A\x95\0\x01\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xC5\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAB\x00\x00", 55, true));

	bool found1 = false; bool found2 = false;
	for (int i = 0; i < 10; ++i) {
		PollMgr_poll(pm);
		NdnlpPkt pkt = Link_read(target2);
		if (pkt != NULL) {
			DataPkt datapkt = NdnlpPkt_asData(pkt);
			if (datapkt != NULL) {
				if (DataPkt_getSequence(datapkt) == 0x0000000000002001) found1 = true;
				if (DataPkt_getSequence(datapkt) == 0x0000000000002002) found2 = true;
			}
			NdnlpPkt_dtor(pkt);
		}
		if (found1 && found2) break;
	}
	CU_ASSERT_TRUE(found1);
	CU_ASSERT_TRUE(found2);

	Link_dtor(target1); Link_dtor(target2);
	PollMgr_dtor(pm);
	close(sockets[0]); close(sockets[1]); close(sockets[2]); close(sockets[3]);
}

#if __linux__
void test_Link_udp(void) {
	struct sockaddr_in6 addrs[4]; int sockets[4];
	memset(addrs, 0, sizeof(addrs));
	NBS nbs[4]; PollMgr pm = PollMgr_ctor(50); LMD lmd[4]; Link link[16];
	for (int i = 0; i < 4; ++i) {
		addrs[i].sin6_family = AF_INET6;
		addrs[i].sin6_port = 32350 + i;
		addrs[i].sin6_addr.s6_addr[15] = 1;//[::1]
		CU_ASSERT(-1 != (sockets[i] = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0)));
		CU_ASSERT(0 == bind(sockets[i], (struct sockaddr*)(addrs + i), sizeof(struct sockaddr_in6)));
		nbs[i] = NBS_ctor(sockets[i], sockets[i], true);
		NBS_pollAttach(nbs[i], pm);
		SockAddr localaddr = SockAddr_create(addrs + i, sizeof(struct sockaddr_in6));
		lmd[i] = LMD_ctor(nbs[i], localaddr, 1000);
		SockAddr_dtor(localaddr);
	}
	//link pairs: 1-4 2-8 3-12 6-9 7-13 11-14
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			if (i == j) continue;
			SockAddr addr = SockAddr_create((struct sockaddr*)(addrs + j), sizeof(struct sockaddr_in6));
			link[i * 4 + j] = Link_ctorDgram(lmd[i], addr);
			SockAddr_dtor(addr);
		}
	}
	PollMgr_poll(pm);

	int inlinks[12] = {1,2,3,6,7,11,4,8,12,9,13,14};
	int outlinks[12] = {4,8,12,9,13,14,1,2,3,6,7,11};
	for (int i = 0; i < 12; ++i) {
		NdnlpPkt pkt1 = NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x01\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\xAA\xC5\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCD\x00\x00", 39, true);
		DataPkt_setSequence(NdnlpPkt_asData(pkt1), 0x100000000 | (inlinks[i] << 16) | (outlinks[i]));
		NdnlpPkt pkt2 = NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x02\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\x9A\x95\0\x01\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xC5\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAB\x00\x00", 55, true);
		DataPkt_setSequence(NdnlpPkt_asData(pkt2), 0x200000000 | (inlinks[i] << 16) | (outlinks[i]));
		Link_write(link[inlinks[i]], pkt1);
		Link_write(link[inlinks[i]], pkt2);
	}
	bool found1[12] = {false,false,false,false,false,false,false,false,false,false,false,false};
	bool found2[12] = {false,false,false,false,false,false,false,false,false,false,false,false};
	int founds = 0;
	for (int k = 0; k < 10; ++k) {
		PollMgr_poll(pm);
		for (int i = 0; i < 12; ++i) {
			NdnlpPkt pkt = Link_read(link[outlinks[i]]);
			if (pkt == NULL) continue;
			DataPkt datapkt = NdnlpPkt_asData(pkt);
			if (datapkt != NULL) {
				if (DataPkt_getSequence(datapkt) == (0x100000000 | (inlinks[i] << 16) | (outlinks[i]))) {
					found1[i] = true;
					++founds;
				}
				if (DataPkt_getSequence(datapkt) == (0x200000000 | (inlinks[i] << 16) | (outlinks[i]))) {
					found2[i] = true;
					++founds;
				}
			}
			NdnlpPkt_dtor(pkt);
		}
		if (founds >= 24) break;
	}
	CU_ASSERT_EQUAL(founds, 24);
	for (int i = 0; i < 12; ++i) {
		CU_ASSERT_TRUE(found1[i]);
		CU_ASSERT_TRUE(found2[i]);
	}

	for (int i = 0; i < 12; ++i) Link_dtor(link[inlinks[i]]);
	for (int i = 0; i < 4; ++i) LMD_dtor(lmd[i]);
	PollMgr_dtor(pm);
	for (int i = 0; i < 4; ++i) close(sockets[i]);
}
#else
#warning "Test test_Link_udp needs to be adapted for other platforms. SOCK_NONBLOCK is not universally defined"
#endif


void suite_Link(void) {
	CU_pSuite suite = CU_add_suite("Link", NULL, NULL);
	CU_add_test(suite, "Link_stream", test_Link_stream);
#if __linux__
	CU_add_test(suite, "Link_udp", test_Link_udp);
#endif
}

