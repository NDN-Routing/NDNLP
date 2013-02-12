#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <CUnit/CUnit.h>
#include "ndnld.h"

void test_DateTime_now(void) {
	DateTime now1 = DateTime_now();
	usleep(2000);
	DateTime now2 = DateTime_now();
	CU_ASSERT_NOT_EQUAL(now1, now2);

	DateTime_mockNow(634676198729668);
	CU_ASSERT_EQUAL(DateTime_now(), 634676198729668);
	DateTime_mockNow(DateTime_noMock);
	CU_ASSERT_NOT_EQUAL(DateTime_now(), 634676198729668);
}

void test_StreamBuf(void) {
	StreamBuf target = StreamBuf_ctor();
	StreamBuf_append(target, "\x99\x06\x07\x08\x09", 1, 4, BufMode_use);
	StreamBuf_prepend(target, "\x00\x01\x02\x03\x04\x05", 0, 6, BufMode_use);
	StreamBuf_append(target, "\x0A\x0B\x0C\x0D\x0E\x0F", 0, 6, BufMode_clone);
	void* data; size_t len;
	//00-0F
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x00", 1);
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x00", 1);
	StreamBuf_consume(target, 3);
	//03-0F
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x03", 1);
	StreamBuf_consume(target, 3);
	//06-0F
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x06", 1);
	StreamBuf_consume(target, 5);
	//0B-0F
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x0B", 1);
	StreamBuf_prepend(target, "\x88\x77", 1, 1, BufMode_use);
	//770B-0F
	CU_ASSERT_TRUE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_PTR_NOT_NULL(data);
	CU_ASSERT(len >= 1);
	CU_ASSERT_NSTRING_EQUAL(data, "\x77", 1);
	StreamBuf_consume(target, 6);
	//empty
	CU_ASSERT_FALSE(StreamBuf_get(target, &data, &len));
	CU_ASSERT_FALSE(StreamBuf_get(target, &data, &len));
	StreamBuf_dtor(target);
}

#ifdef __linux__
void test_NBS_stream(void) {
	int sockets[4]; int res;
	CU_ASSERT(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockets + 0));
	CU_ASSERT(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockets + 2));
	res = fcntl(sockets[1], F_GETFL);
	CU_ASSERT_NOT_EQUAL(res, -1);
	CU_ASSERT(0 == fcntl(sockets[1], F_SETFL, res | O_NONBLOCK));
	res = fcntl(sockets[2], F_GETFL);
	CU_ASSERT_NOT_EQUAL(res, -1);
	CU_ASSERT(0 == fcntl(sockets[2], F_SETFL, res | O_NONBLOCK));

	NBS target = NBS_ctor(sockets[1], sockets[2], false);
	struct pollfd fds[2]; char buf[16];

	fds[0].fd = sockets[1]; fds[0].events = 0;
	fds[1].fd = sockets[2]; fds[1].events = 0;
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 0);
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 1);
	CU_ASSERT_EQUAL(fds[0].fd, sockets[1]);
	CU_ASSERT_TRUE(fds[0].events & POLLIN);
	CU_ASSERT_EQUAL(fds[1].fd, sockets[2]);
	CU_ASSERT_FALSE(fds[1].events & POLLOUT);
	fds[0].revents = POLLIN;
	fds[1].revents = 0;
	CU_ASSERT(4 == write(sockets[0], "\x00\x01\x02\x03", 4));
	NBS_pollCb(target, PollMgrEvt_result, fds + 0);
	NBS_pollCb(target, PollMgrEvt_result, fds + 1);
	CU_ASSERT_EQUAL(NBS_read(target, buf, 3, NULL), 3);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x00\x01\x02", 3);
	NBS_pushback(target, ByteArray_clone("\x01\x02", 2), 1, 1, NULL);
	CU_ASSERT_EQUAL(NBS_read(target, buf, 16, NULL), 2);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x02\x03", 2);

	NBS_write(target, ByteArray_clone("\x10\x11\x12\x13", 4), 0, 3, NULL);
	NBS_write(target, ByteArray_clone("\x13\x14\x15\x16", 4), 0, 4, NULL);
	fds[0].fd = sockets[1]; fds[0].events = 0;
	fds[1].fd = sockets[2]; fds[1].events = 0;
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 0);
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 1);
	CU_ASSERT_EQUAL(fds[0].fd, sockets[1]);
	CU_ASSERT_TRUE(fds[0].events & POLLIN);
	CU_ASSERT_EQUAL(fds[1].fd, sockets[2]);
	CU_ASSERT_TRUE(fds[1].events & POLLOUT);
	fds[0].revents = 0;
	fds[1].revents = POLLOUT;
	NBS_pollCb(target, PollMgrEvt_result, fds + 0);
	NBS_pollCb(target, PollMgrEvt_result, fds + 1);
	CU_ASSERT_EQUAL(read(sockets[3], buf, 16), 7);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x10\x11\x12\x13\x14\x15\x16", 7);

	NBS_dtor(target);
	close(sockets[0]); close(sockets[1]); close(sockets[2]); close(sockets[3]);
}

void test_NBS_dgram(void) {
	struct sockaddr_in6 addrs[4]; int sockets[4];
	memset(addrs, 0, sizeof(addrs));
	for (int i = 0; i < 4; ++i) {
		addrs[i].sin6_family = AF_INET6;
		addrs[i].sin6_port = 32350 + i;
		addrs[i].sin6_addr.s6_addr[15] = 1;//[::1]
	}
	for (int i = 0; i < 4; ++i) {
		CU_ASSERT(-1 != (sockets[i] = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0)));
		CU_ASSERT(0 == bind(sockets[i], (struct sockaddr*)(addrs + i), sizeof(struct sockaddr_in6)));
	}
	CU_ASSERT(0 == connect(sockets[0], (struct sockaddr*)(addrs + 1), sizeof(struct sockaddr_in6)));

	NBS target = NBS_ctor(sockets[1], sockets[2], true);
	struct pollfd fds[2]; char buf[16];
	SockAddr srcaddr = SockAddr_ctor();
	SockAddr dstaddr = SockAddr_create((struct sockaddr*)(addrs + 3), sizeof(struct sockaddr_in6));

	fds[0].fd = sockets[1]; fds[0].events = 0;
	fds[1].fd = sockets[2]; fds[1].events = 0;
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 0);
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 1);
	CU_ASSERT_TRUE(fds[0].events & POLLIN);
	CU_ASSERT_FALSE(fds[1].events & POLLOUT);
	fds[0].revents = POLLIN;
	fds[1].revents = 0;
	CU_ASSERT(4 == write(sockets[0], "\x00\x01\x02\x03", 4));
	NBS_pollCb(target, PollMgrEvt_result, fds + 0);
	NBS_pollCb(target, PollMgrEvt_result, fds + 1);
	CU_ASSERT_EQUAL(NBS_read(target, buf, 3, srcaddr), 3);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x00\x01\x02", 3);
	CU_ASSERT_NSTRING_EQUAL(SockAddr_addr(srcaddr), addrs + 0, SockAddr_addrlen(srcaddr));
	NBS_pushback(target, ByteArray_clone("\x01\x02", 2), 1, 1, srcaddr);
	SockAddr_clear(srcaddr);
	CU_ASSERT_EQUAL(NBS_read(target, buf, 16, srcaddr), 1);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x02", 1);
	CU_ASSERT_NSTRING_EQUAL(SockAddr_addr(srcaddr), addrs + 0, SockAddr_addrlen(srcaddr));
	CU_ASSERT_EQUAL(NBS_read(target, buf, 16, srcaddr), 0);

	NBS_write(target, ByteArray_clone("\x10\x11\x12\x13", 4), 0, 3, dstaddr);
	NBS_write(target, ByteArray_clone("\x13\x14\x15\x16", 4), 0, 4, dstaddr);
	fds[0].fd = sockets[1]; fds[0].events = 0;
	fds[1].fd = sockets[2]; fds[1].events = 0;
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 0);
	NBS_pollCb(target, PollMgrEvt_prepare, fds + 1);
	CU_ASSERT_TRUE(fds[0].events & POLLIN);
	CU_ASSERT_TRUE(fds[1].events & POLLOUT);
	fds[0].revents = 0;
	fds[1].revents = POLLOUT;
	NBS_pollCb(target, PollMgrEvt_result, fds + 0);
	NBS_pollCb(target, PollMgrEvt_result, fds + 1);
	CU_ASSERT_EQUAL(read(sockets[3], buf, 16), 3);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x10\x11\x12", 3);
	CU_ASSERT_EQUAL(read(sockets[3], buf, 16), 4);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x13\x14\x15\x16", 4);

	NBS_dtor(target);
	SockAddr_dtor(srcaddr); SockAddr_dtor(dstaddr);
	close(sockets[0]); close(sockets[1]); close(sockets[2]); close(sockets[3]);
}
#else
#warning "Some tests are disabled due to use of SOCK_NONBLOCK"
#endif

void test_PollMgr_NBS(void) {
	int sockets[64]; NBS nbs[16]; int res;
	for (int i = 0; i < 64; i += 2) {
		CU_ASSERT(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockets + i));
	}
	for (int i = 0; i < 16; ++i) {
		res = fcntl(sockets[i * 4 + 1], F_GETFL);
		CU_ASSERT_NOT_EQUAL(res, -1);
		CU_ASSERT(0 == fcntl(sockets[i * 4 + 1], F_SETFL, res | O_NONBLOCK));
		res = fcntl(sockets[i * 4 + 2], F_GETFL);
		CU_ASSERT_NOT_EQUAL(res, -1);
		CU_ASSERT(0 == fcntl(sockets[i * 4 + 2], F_SETFL, res | O_NONBLOCK));
		nbs[i] = NBS_ctor(sockets[i * 4 + 1], sockets[i * 4 + 2], false);
	}
	DateTime t1; DateTime t2;
	PollMgr target = PollMgr_ctor(50);

	NBS_pollAttach(nbs[0], target);
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 > 30);

	CU_ASSERT(4 == write(sockets[0], "\x80\x81\x82\x83", 4));
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 < 30);//canRead

	for (int i = 1; i < 16; ++i) NBS_pollAttach(nbs[i], target);
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 < 30);//still canRead

	NBS_pollDetach(nbs[0]);
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 > 30);

	NBS_write(nbs[1], ByteArray_clone("\x84\x85\x86\x87", 4), 0, 4, NULL);
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 < 30);//canWrite, writing
	t1 = DateTime_now(); PollMgr_poll(target); t2 = DateTime_now();
	CU_ASSERT(t2 - t1 > 30);//nothing to write

	PollMgr_dtor(target);
	for (int i = 0; i < 16; ++i) NBS_dtor(nbs[i]);
	for (int i = 0; i < 64; ++i) close(sockets[i]);
}

void suite_Utility(void) {
	CU_pSuite suite = CU_add_suite("Utility", NULL, NULL);
	CU_add_test(suite, "DateTime_now", test_DateTime_now);
	CU_add_test(suite, "StreamBuf", test_StreamBuf);
	//CU_add_test(suite, "DgramBuf", test_DgramBuf);
#ifdef __linux__
	CU_add_test(suite, "NBS_stream", test_NBS_stream);
	CU_add_test(suite, "NBS_dgram", test_NBS_dgram);
#endif
	CU_add_test(suite, "PollMgr_NBS", test_PollMgr_NBS);
}

