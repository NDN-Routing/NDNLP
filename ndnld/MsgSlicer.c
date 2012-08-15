#include <stdlib.h>
#include <string.h>
#include "ndnld.h"

MsgSlicer MsgSlicer_ctor(SeqGen seqgen, size_t mtu) {
	MsgSlicer self = ALLOCSELF;
	self->seqgen = seqgen;
	if (mtu != 0) {
		self->fragSize = mtu - (DataPkt_hdrlen2 + DataPkt_payloadhdrlen1 + CcnbH_sizeBlockHdr(mtu) + DataPkt_trailerlen);//payload BLOB hdr length may be less but not more
	}
	return self;
}

void MsgSlicer_dtor(MsgSlicer self) {
	free(self);
}

NdnlpPktA MsgSlicer_slice(MsgSlicer self, CcnbMsg msg) {
	size_t msgSize = CcnbMsg_getSize(msg);
	NdnlpPktA pkts;

	if (self->fragSize == 0) {//infinite MTU
		pkts = NdnlpPktA_ctor(1);
		DataPkt pkt = DataPkt_ctor(false, msgSize);
		DataPkt_setSequence(pkt, SeqGen_next(self->seqgen));
		memcpy(DataPkt_payload(pkt, NULL), CcnbMsg_getBodyPart(msg, 0), msgSize);
		NdnlpPktA_set(pkts, 0, pkt);
	} else {
		int fragCount;
		if (msgSize % self->fragSize == 0) fragCount = msgSize / self->fragSize;
		else fragCount = msgSize / self->fragSize + 1;

		pkts = NdnlpPktA_ctor(fragCount);
		SeqBlock seqb = SeqGen_nextBlock(self->seqgen, fragCount);
		for (int i = 0; i < fragCount; ++i) {
			int thisFragSize = self->fragSize;
			if (i == fragCount - 1) thisFragSize = msgSize - self->fragSize * i;
			DataPkt pkt = DataPkt_ctor(fragCount > 1, thisFragSize);
			DataPkt_setSequence(pkt, SeqBlock_item(seqb, i));
			DataPkt_setFragIndex(pkt, i);
			DataPkt_setFragCount(pkt, fragCount);
			memcpy(DataPkt_payload(pkt, NULL), CcnbMsg_getBodyPart(msg, self->fragSize * i), thisFragSize);
			NdnlpPktA_set(pkts, i, pkt);
		}
		SeqBlock_dtor(seqb);
	}
	return pkts;
}

