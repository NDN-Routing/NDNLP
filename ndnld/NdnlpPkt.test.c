#include <CUnit/CUnit.h>
#include <ccn/ccn.h>
#include "ndnld.h"

void test_CcnbH_blockHdr(void) {
	CU_ASSERT_STRING_EQUAL(CcnbH_getBlockHdr(20653248, CCN_DTAG), "\x4E\x64\x4C\x82");
	CU_ASSERT_STRING_EQUAL(CcnbH_getBlockHdr(6, CCN_BLOB), "\xB5");

	uint64_t number; enum ccn_tt tt;
	CU_ASSERT_EQUAL(CcnbH_readBlockHdr((uint8_t*)"\x4E\x64\x4C\x82\0\0\0\0", 8, &number, &tt), 4);
	CU_ASSERT_EQUAL(number, 20653248);
	CU_ASSERT_EQUAL(tt, CCN_DTAG);
	CU_ASSERT_EQUAL(CcnbH_readBlockHdr((uint8_t*)"\xB5\x4E\x64\x4C\x8A\0\0\0\0", 8, &number, &tt), 1);
	CU_ASSERT_EQUAL(number, 6);
	CU_ASSERT_EQUAL(tt, CCN_BLOB);
}

void test_DataPkt(void) {
	NdnlpPkt pktN = NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\0\0\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\x9A\x95\0\0\x00\x4E\x64\x4C\xA2\x95\0\0\x00\x4E\x64\x4C\xAA\xDD\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x00\x00", 58, true);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pktN);
	DataPkt target = NdnlpPkt_asData(pktN);
	CU_ASSERT_PTR_NOT_NULL(target);
	if (target != NULL) {
		DataPkt_setSequence(target, 0x123456789ABC);
		DataPkt_setFlags(target, DataPktFlag_RLA);
		CU_ASSERT_TRUE(DataPkt_setFragIndex(target, 4));
		CU_ASSERT_TRUE(DataPkt_setFragCount(target, 11));

		CU_ASSERT_EQUAL(DataPkt_getSequence(target), 0x123456789ABC);
		CU_ASSERT_EQUAL(DataPkt_getFlags(target), DataPktFlag_RLA);
		CU_ASSERT_TRUE(DataPkt_hasRLA(target));
		CU_ASSERT_EQUAL(DataPkt_getFragIndex(target), 4);
		CU_ASSERT_EQUAL(DataPkt_getFragCount(target), 11);
		CU_ASSERT_EQUAL(DataPkt_getMessageIdentifier(target), 0x123456789AB8);
		size_t payloadLength;
		uint8_t* payload = DataPkt_payload(target, &payloadLength);
		CU_ASSERT_PTR_NOT_NULL(payload);
		if (payload != NULL) {
			CU_ASSERT_EQUAL(payloadLength, 11);
			CU_ASSERT_NSTRING_EQUAL(payload, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", 11);
		}
	}
	NdnlpPkt_dtor(pktN);
}

void test_DataPkt_noFragFields(void) {
	NdnlpPkt pktN = NdnlpPkt_ctor("\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\0\0\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\xAA\xDD\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x00\x00", 42, true);
	CU_ASSERT_PTR_NOT_NULL_FATAL(pktN);
	DataPkt target = NdnlpPkt_asData(pktN);
	CU_ASSERT_PTR_NOT_NULL(target);
	if (target != NULL) {
		DataPkt_setSequence(target, 0x123456789ABC);
		DataPkt_setFlags(target, DataPktFlag_RLA);
		CU_ASSERT_TRUE(DataPkt_setFragIndex(target, 0));
		CU_ASSERT_TRUE(DataPkt_setFragCount(target, 1));
		CU_ASSERT_FALSE(DataPkt_setFragIndex(target, 4));
		CU_ASSERT_FALSE(DataPkt_setFragCount(target, 11));

		CU_ASSERT_EQUAL(DataPkt_getSequence(target), 0x123456789ABC);
		CU_ASSERT_EQUAL(DataPkt_getFlags(target), DataPktFlag_RLA);
		CU_ASSERT_TRUE(DataPkt_hasRLA(target));
		CU_ASSERT_EQUAL(DataPkt_getFragIndex(target), 0);
		CU_ASSERT_EQUAL(DataPkt_getFragCount(target), 1);
		size_t payloadLength;
		uint8_t* payload = DataPkt_payload(target, &payloadLength);
		CU_ASSERT_PTR_NOT_NULL(payload);
		if (payload != NULL) {
			CU_ASSERT_EQUAL(payloadLength, 11);
			CU_ASSERT_NSTRING_EQUAL(payload, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", 11);
		}
	}
	NdnlpPkt_dtor(pktN);
}

AckPkt base_AckPkt(void) {
	NdnlpPkt pktN = NdnlpPkt_ctor("\x4E\x64\x4C\xB2\x4E\x64\x4C\xBA\x4E\x64\x4C\xC2\xB5\0\0\0\0\x20\x01\x00\x4E\x64\x4C\xCA\xB5\xD0\0\0\x71\0\0\x00\x00\x4E\x64\x4C\xBA\x4E\x64\x4C\xC2\xB5\0\0\0\0\x21\x01\x00\x4E\x64\x4C\xCA\xC5\x80\0\0\0\0\0\0\x01\x00\x00\x00", 65, true);
	if (pktN == NULL) return NULL;
	return NdnlpPkt_asAck(pktN);
}

void test_AckPkt(void) {
	AckPkt target = base_AckPkt();
	CU_ASSERT_PTR_NOT_NULL_FATAL(target);

	AckBlock ab0 = AckPkt_getAckBlock(target, NULL);
	CU_ASSERT_PTR_NOT_NULL(ab0);
	CU_ASSERT_EQUAL(AckBlock_getSequenceBase(ab0), 0x2001);
	CU_ASSERT_EQUAL(AckBlock_length(ab0), 29);
	CU_ASSERT_EQUAL(AckBlock_bitmapLength(ab0), 6);
	size_t bitmapLength;
	CU_ASSERT_NSTRING_EQUAL(AckBlock_bitmap(ab0, &bitmapLength), "\xD0\0\0\x71\0\0", 6);
	CU_ASSERT_EQUAL(bitmapLength, 6);

	AckBlockEn abe0 = AckBlockEn_ctor(ab0);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2001);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2002);
	AckBlockEn_reset(abe0);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2001);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2002);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2004);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x201a);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x201b);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x201c);
	CU_ASSERT_TRUE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_EQUAL(AckBlockEn_current(abe0),0x2020);
	CU_ASSERT_FALSE(AckBlockEn_moveNext(abe0));
	CU_ASSERT_FALSE(AckBlockEn_moveNext(abe0));
	AckBlockEn_dtor(abe0);

	AckBlock ab1 = AckPkt_getAckBlock(target, ab0);
	AckBlock_dtor(ab0);
	CU_ASSERT_PTR_NOT_NULL(ab1);
	CU_ASSERT_EQUAL(AckBlock_getSequenceBase(ab1), 0x2101);

	AckBlock ab2 = AckPkt_getAckBlock(target, ab1);
	AckBlock_dtor(ab1);
	CU_ASSERT_PTR_NULL(ab2);

	NdnlpPkt_dtor(target);
}

void test_AckPkt_addAckBlock(void) {
	AckPkt target = base_AckPkt();
	CU_ASSERT_PTR_NOT_NULL_FATAL(target);

	AckBlock ab0 = AckPkt_getAckBlock(target, NULL);
	AckBlock ab1 = AckPkt_getAckBlock(target, ab0);
	AckBlock_dtor(ab0);
	AckBlock ab2 = AckPkt_addAckBlock(target, ab1, 300);
	AckBlock_dtor(ab1);
	CU_ASSERT_EQUAL(NdnlpPkt_length(target), 65 + 324);
	AckBlock_dtor(ab2);

	NdnlpPkt_dtor(target);
}

void test_AckQueue(void) {
	int count = 8192;
	AckQueue target = AckQueue_ctor(1500);
	SeqNum seqs[count]; bool found[count]; int foundcount = 0;
	for (int i = 0, div = DateTime_now() % 97; i < count; ++i) {
		seqs[i] = (i % div == 0) ? SeqNum_rand() : SeqNum_add(seqs[i - 1], 1);
		while (true) {
			bool duplicate = false;
			for (int j = 0; j < i; ++j) {
				if (seqs[j] == seqs[i]) {
					duplicate = true;
					break;
				}
			}
			if (duplicate) seqs[i] = SeqNum_rand();
			else break;
		}
		found[i] = false;
		AckQueue_insert(target, seqs[i]);
	}
	NdnlpPktA pkts = AckQueue_getPkts(target);
	for (int i = 0, pktcount = NdnlpPktA_length(pkts); i < pktcount; ++i) {
		AckPkt pkt = NdnlpPkt_asAck(NdnlpPktA_get(pkts, i));
		CU_ASSERT_PTR_NOT_NULL(pkt);
		AckBlock ab; AckBlock ab0 = NULL;
		while (NULL != (ab = AckPkt_getAckBlock(pkt, ab0))) {
			if (ab0 != NULL) AckBlock_dtor(ab0);
			AckBlockEn abe = AckBlockEn_ctor(ab);
			while (AckBlockEn_moveNext(abe)) {
				SeqNum seq = AckBlockEn_current(abe);
				int index = -1;
				for (int j = 0; j < count; ++j) {
					if (seqs[j] == seq) index = j;
				}
				if (index >= 0) {
					found[index] = true;
					++foundcount;
				}
			}
			AckBlockEn_dtor(abe);
			ab0 = ab;
		}
	}
	NdnlpPktA_dtor(pkts, true);
	bool foundall = true;
	for (int i = 0; i < count; ++i) foundall = foundall && found[i];
	CU_ASSERT_EQUAL(foundcount, count);
	CU_ASSERT_TRUE(foundall);
}

void suite_NdnlpPkt(void) {
	CU_pSuite suite = CU_add_suite("NdnlpPkt", NULL, NULL);
	CU_add_test(suite, "CcnbH_blockHdr", test_CcnbH_blockHdr);
	CU_add_test(suite, "DataPkt", test_DataPkt);
	CU_add_test(suite, "DataPkt_noFragFields", test_DataPkt_noFragFields);
	CU_add_test(suite, "AckPkt", test_AckPkt);
	CU_add_test(suite, "AckPkt_addAckBlock", test_AckPkt_addAckBlock);
	CU_add_test(suite, "AckQueue", test_AckQueue);
}

