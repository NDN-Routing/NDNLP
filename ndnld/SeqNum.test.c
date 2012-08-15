#include <CUnit/CUnit.h>
#include "ndnld.h"

void test_SeqNum_add(void) {
	CU_ASSERT_EQUAL(SeqNum_add(0, 1), 1);
	CU_ASSERT_EQUAL(SeqNum_add(0, -2), 0x0000FFFFFFFFFFFE);
	CU_ASSERT_EQUAL(SeqNum_add(0x0000FFFFFFFFFFFE, 4), 2);
}

void test_SeqNum_rand(void) {
	CU_ASSERT_NOT_EQUAL(SeqNum_rand(), SeqNum_rand());
}

void test_SeqNum_rw(void) {
	SeqNum n = 0x123456789ABC;
	char buf[6];
	SeqNum_writeTo(n, buf);
	CU_ASSERT_NSTRING_EQUAL(buf, "\x12\x34\x56\x78\x9A\xBC", 6);
	CU_ASSERT_EQUAL(SeqNum_readFrom(buf), n);
}

void test_SeqGen(void) {
	SeqGen target = SeqGen_ctor();
	SeqNum v0 = SeqGen_next(target);
	SeqNum v1 = SeqGen_next(target);
	SeqBlock b2 = SeqGen_nextBlock(target, 3);
	SeqNum v2 = SeqBlock_item(b2, 0);
	SeqNum v3 = SeqBlock_item(b2, 1);
	SeqNum v4 = SeqBlock_item(b2, 2);
	SeqNum v5 = SeqGen_next(target);
	SeqBlock_dtor(b2);
	SeqGen_dtor(target);

	CU_ASSERT_EQUAL(v1, SeqNum_add(v0, 1));
	CU_ASSERT_EQUAL(v2, SeqNum_add(v0, 2));
	CU_ASSERT_EQUAL(v3, SeqNum_add(v0, 3));
	CU_ASSERT_EQUAL(v4, SeqNum_add(v0, 4));
	CU_ASSERT_EQUAL(v5, SeqNum_add(v0, 5));
}

void suite_SeqNum(void) {
	CU_pSuite suite = CU_add_suite("SeqNum", NULL, NULL);
	CU_add_test(suite, "SeqNum_add", test_SeqNum_add);
	CU_add_test(suite, "SeqNum_rand", test_SeqNum_rand);
	CU_add_test(suite, "SeqNum_rw", test_SeqNum_rw);
	CU_add_test(suite, "SeqGen", test_SeqGen);
}

