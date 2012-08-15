#include <CUnit/CUnit.h>
#include "ndnld.h"

void test_MsgSlicer(void) {
	CcnbMsg msg1 = CcnbMsg_ctor(64);
	memset(CcnbMsg_getBodyPart(msg1, 0), '\x11', 29);
	memset(CcnbMsg_getBodyPart(msg1, 29), '\x12', 17);
	memset(CcnbMsg_getBodyPart(msg1, 46), '\x13', 18);
	CcnbMsg msg2 = CcnbMsg_ctor(70);
	memset(CcnbMsg_getBodyPart(msg2, 0), '\x21', 23);
	memset(CcnbMsg_getBodyPart(msg2, 23), '\x22', 19);
	memset(CcnbMsg_getBodyPart(msg2, 42), '\x23', 28);

	SeqGen seqgen = SeqGen_ctor();
	MsgSlicer target = MsgSlicer_ctor(seqgen, 80);
	CU_ASSERT_DOUBLE_EQUAL(target->fragSize, 32, 2);
	target->fragSize = 32;
	NdnlpPktA pkts1 = MsgSlicer_slice(target, msg1);
	NdnlpPktA pkts2 = MsgSlicer_slice(target, msg2);
	CU_ASSERT_EQUAL(NdnlpPktA_length(pkts1), 2);
	CU_ASSERT_EQUAL(NdnlpPktA_length(pkts2), 3);
	DataPkt pkt10 = NdnlpPktA_get(pkts1, 0);
	DataPkt pkt11 = NdnlpPktA_get(pkts1, 1);
	DataPkt pkt20 = NdnlpPktA_get(pkts2, 0);
	DataPkt pkt21 = NdnlpPktA_get(pkts2, 1);
	DataPkt pkt22 = NdnlpPktA_get(pkts2, 2);

	CU_ASSERT_EQUAL(DataPkt_getFragCount(pkt10), 2);
	CU_ASSERT_EQUAL(DataPkt_getFragCount(pkt11), 2);
	CU_ASSERT_EQUAL(DataPkt_getFragCount(pkt20), 3);
	CU_ASSERT_EQUAL(DataPkt_getFragCount(pkt21), 3);
	CU_ASSERT_EQUAL(DataPkt_getFragCount(pkt22), 3);
	CU_ASSERT_EQUAL(DataPkt_getFragIndex(pkt10), 0);
	CU_ASSERT_EQUAL(DataPkt_getFragIndex(pkt11), 1);
	CU_ASSERT_EQUAL(DataPkt_getFragIndex(pkt20), 0);
	CU_ASSERT_EQUAL(DataPkt_getFragIndex(pkt21), 1);
	CU_ASSERT_EQUAL(DataPkt_getFragIndex(pkt22), 2);
	CU_ASSERT_EQUAL(DataPkt_getMessageIdentifier(pkt11), DataPkt_getSequence(pkt10));
	CU_ASSERT_EQUAL(DataPkt_getMessageIdentifier(pkt21), DataPkt_getSequence(pkt20));
	CU_ASSERT_EQUAL(DataPkt_getMessageIdentifier(pkt22), DataPkt_getSequence(pkt20));
	size_t payloadLength;
	payloadLength = 0x800000;
	CU_ASSERT_NSTRING_EQUAL(DataPkt_payload(pkt10, &payloadLength), CcnbMsg_getBodyPart(msg1, 0), 32);
	CU_ASSERT_EQUAL(payloadLength, 32);
	payloadLength = 0x800000;
	CU_ASSERT_NSTRING_EQUAL(DataPkt_payload(pkt11, &payloadLength), CcnbMsg_getBodyPart(msg1, 32), 32);
	CU_ASSERT_EQUAL(payloadLength, 32);
	payloadLength = 0x800000;
	CU_ASSERT_NSTRING_EQUAL(DataPkt_payload(pkt20, &payloadLength), CcnbMsg_getBodyPart(msg2, 0), 32);
	CU_ASSERT_EQUAL(payloadLength, 32);
	payloadLength = 0x800000;
	CU_ASSERT_NSTRING_EQUAL(DataPkt_payload(pkt21, &payloadLength), CcnbMsg_getBodyPart(msg2, 32), 32);
	CU_ASSERT_EQUAL(payloadLength, 32);
	payloadLength = 0x800000;
	CU_ASSERT_NSTRING_EQUAL(DataPkt_payload(pkt22, &payloadLength), CcnbMsg_getBodyPart(msg2, 64), 6);
	CU_ASSERT_EQUAL(payloadLength, 6);

	MsgSlicer_dtor(target);
	SeqGen_dtor(seqgen);
	NdnlpPktA_dtor(pkts1, true);
	NdnlpPktA_dtor(pkts2, true);
}

void suite_MsgSlicer(void) {
	CU_pSuite suite = CU_add_suite("MsgSlicer", NULL, NULL);
	CU_add_test(suite, "MsgSlicer", test_MsgSlicer);
}

