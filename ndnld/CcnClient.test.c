#include <CUnit/CUnit.h>
//#include <stdlib.h>
//#include <ccn/uri.h>
#include "ndnld.h"

void test_CcnbMsg(void) {
	CcnbMsg target = CcnbMsg_ctor(8);
	CU_ASSERT_EQUAL(CcnbMsg_getSize(target), 8);
	CU_ASSERT_EQUAL(CcnbMsg_getEncapSize(target), 13);
	CcnbMsg_setBodyPart(target, "\x01\x02\x03\x04\x11\x12\x13\x14", 0, 8);
	CcnbMsg_resize(target, 16);
	CcnbMsg_setBodyPart(target, "\x21\x22\x23\x24\x31\x32\x33\x34", 8, 8);
	CU_ASSERT_NSTRING_EQUAL(CcnbMsg_getEncap(target), "CCN\202\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34\000", 21);
	CU_ASSERT_NSTRING_EQUAL(CcnbMsg_getBody(target), "\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34", 16);
	CU_ASSERT_PTR_EQUAL(CcnbMsg_getBodyPart(target, 0), CcnbMsg_getBody(target));
	CU_ASSERT_PTR_EQUAL(CcnbMsg_getBodyPart(target, 15), (uint8_t*)CcnbMsg_getBody(target) + 15);
	CU_ASSERT_PTR_NULL(CcnbMsg_getBodyPart(target, -1));
	CU_ASSERT_PTR_NULL(CcnbMsg_getBodyPart(target, 16));
	CcnbMsg_resize(target, 4);
	CU_ASSERT_NSTRING_EQUAL(CcnbMsg_getEncap(target), "CCN\202\x01\x02\x03\x04\000", 9);
	CU_ASSERT_FALSE(CcnbMsg_verifyIntegrity(target));
	CcnbMsg_setBodyPart(target, "\x89OK\0", 0, 4);//<OK/>
	CU_ASSERT_TRUE(CcnbMsg_verifyIntegrity(target));
}

void test_CcnCC(void) {
	CcnCC target = CcnCC_ctor();
	CU_ASSERT_PTR_NOT_NULL_FATAL(target);
	CCNDID ccndid = CcnCC_ccndid(target);
	CU_ASSERT_PTR_NOT_NULL(ccndid);
	CU_ASSERT_NSTRING_NOT_EQUAL(ccndid, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32);
	CcnCC_dtor(target);
}

void test_CcnLAC(void) {
	CcnCC cc = CcnCC_ctor();
	CU_ASSERT_PTR_NOT_NULL_FATAL(cc);
	PollMgr pm = PollMgr_ctor(50);

	CcnLAC target = CcnLAC_ctor();
	CcnLAC_initialize(target, CcnCC_ccndid(cc), pm);
	int count = 20;
	while (!CcnLAC_ready(target) && --count > 0) {
		PollMgr_poll(pm);
	}

	CU_ASSERT_TRUE(CcnLAC_ready(target));
	CU_ASSERT(0 < CcnLAC_faceid(target));

	/*
	struct ccn_charbuf* prefix = ccn_charbuf_create();
	ccn_name_from_uri(prefix, "ccnx:/yoursunny");
	CcnH_regPrefix(CcnPrefixOp_register, CcnCC_ccnh(cc), CcnCC_ccndid(cc), CcnLAC_faceid(target), prefix);
	ccn_charbuf_destroy(&prefix);
	for (int i = 0; i < 20; ++i) PollMgr_poll(pm);
	system("ccndstatus");
	system("sleep 2");
	system("ccndstatus");
	*/

	CcnLAC_dtor(target);
	CcnCC_dtor(cc);
	PollMgr_dtor(pm);
}

void suite_CcnClient(void) {
	CU_pSuite suite = CU_add_suite("CcnClient", NULL, NULL);
	CU_add_test(suite, "CcnbMsg", test_CcnbMsg);
	CU_add_test(suite, "CcnCC", test_CcnCC);
	CU_add_test(suite, "CcnLAC", test_CcnLAC);
}

