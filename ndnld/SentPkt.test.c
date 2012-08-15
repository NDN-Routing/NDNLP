#include <CUnit/CUnit.h>
#include "ndnld.h"

void test_SentPkts(void) {
	DataPkt pkt0 = NdnlpPkt_asData(NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x01\x00\x4E\x64\x4C\x92\x95\x80\0\x00\x4E\x64\x4C\x9A\x95\0\0\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xC5\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCD\x00\x00", 55, true));
	DataPkt pkt1 = NdnlpPkt_asData(NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x02\x00\x4E\x64\x4C\x92\x95\x80\0\x00\x4E\x64\x4C\x9A\x95\0\x01\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xC5\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAB\x00\x00", 55, true));
	DataPkt pkt2 = NdnlpPkt_asData(NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x03\x00\x4E\x64\x4C\x92\x95\x80\0\x00\x4E\x64\x4C\x9A\x95\0\x02\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xA5\xEE\xEE\xEE\xEF\x00\x00", 51, true));
	DataPkt pkt3 = NdnlpPkt_asData(NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\x20\x04\x00\x4E\x64\x4C\x92\x95\x80\0\x00\x4E\x64\x4C\x9A\x95\0\x02\x00\x4E\x64\x4C\xA2\x95\0\x03\x00\x4E\x64\x4C\xAA\xA5\xEE\xEE\xEE\xEF\x00\x00", 51, true));

	SentPkts target = SentPkts_ctor(2, 5);
	DateTime_mockNow(634676198729000);
	SentPkts_insert(target, pkt0);//pkt0,sendTime=29,retryCount=5
	DateTime_mockNow(634676198730000);
	SentPkts_insert(target, pkt1);//pkt1,sendTime=30,retryCount=5
	DateTime_mockNow(634676198731000);
	SentPkts_insert(target, pkt2);//pkt0 removed;pkt2,sendTime=31,retryCount=5

	DataPkt r;
	DateTime_mockNow(634676198732000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NULL(r);
	DateTime_mockNow(634676198733000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2002);//pkt1,sendTime=33,retryCount=4
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198734000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2003);//pkt2,sendTime=34,retryCount=4
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198735000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NULL(r);
	DateTime_mockNow(634676198736000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2002);//pkt1,sendTime=36,retryCount=3
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198737000);
	SentPkts_insert(target, pkt3);//pkt1 removed; pkt3,sendTime=37,retryCount=5

	DateTime_mockNow(634676198738000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2003);//pkt2,sendTime=38,retryCount=3
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198739000);
	SentPkts_remove(target, 0x2004);//pkt3 removed

	DateTime_mockNow(634676198740000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NULL(r);
	DateTime_mockNow(634676198741000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2003);//pkt2,sendTime=41,retryCount=2
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198744000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2003);//pkt2,sendTime=44,retryCount=1
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198747000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NOT_NULL(r);
	CU_ASSERT_EQUAL(DataPkt_getSequence(r), 0x2003);//pkt2,sendTime=47,retryCount=0
	NdnlpPkt_dtor(r);
	DateTime_mockNow(634676198750000);
	r = SentPkts_getRetransmit(target, DateTime_now() - 2500);
	CU_ASSERT_PTR_NULL(r);

	DateTime_mockNow(DateTime_noMock);
}

void suite_SentPkt(void) {
	CU_pSuite suite = CU_add_suite("SentPkt", NULL, NULL);
	CU_add_test(suite, "SentPkts", test_SentPkts);
}

