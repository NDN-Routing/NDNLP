#include <stdlib.h>
#include <stdio.h>
#include "ndnld.h"

NdnlpSvc NdnlpSvc_ctor(CcnLAC lac, Link link, bool rla, int sentPktsCapacity, int retryCount, TimeSpan retransmitTime, TimeSpan acknowledgeTime) {
	NdnlpSvc self = ALLOCSELF;
	self->lac = lac;
	self->link = link;
	self->seqGen = SeqGen_ctor();
	self->msgSlicer = MsgSlicer_ctor(self->seqGen, Link_mtu(link));
	self->partialMsgs = PartialMsgs_ctor();
	self->sentPkts = SentPkts_ctor(sentPktsCapacity, retryCount);
	self->ackQueue = AckQueue_ctor(Link_mtu(link));
	self->rla = rla;
	self->retransmitTime = retransmitTime;
	self->acknowledgeTime = acknowledgeTime;
	return self;
}

void NdnlpSvc_dtor(NdnlpSvc self) {
	MsgSlicer_dtor(self->msgSlicer);
	PartialMsgs_dtor(self->partialMsgs);
	SentPkts_dtor(self->sentPkts);
	AckQueue_dtor(self->ackQueue);
	SeqGen_dtor(self->seqGen);
	free(self);
}

bool NdnlpSvc_error(NdnlpSvc self) {
	return CcnLAC_error(self->lac) || Link_error(self->link);
}

void NdnlpSvc_run(NdnlpSvc self) {
	if (NdnlpSvc_error(self) || !CcnLAC_ready(self->lac)) return;

	NdnlpSvc_ccn2link(self);
	NdnlpSvc_link2ccn(self);
	NdnlpSvc_retransmit(self);
	NdnlpSvc_acknowledge(self);
}

void NdnlpSvc_ccn2link(NdnlpSvc self) {
	CcnbMsg msg;
	while (NULL != (msg = CcnLAC_read(self->lac))) {
		NdnlpSvc_msg(self, msg);
	}
}

void NdnlpSvc_msg(NdnlpSvc self, CcnbMsg msg) {
	NdnlpPktA pkts = MsgSlicer_slice(self->msgSlicer, msg);
	for (int i = 0, len = NdnlpPktA_length(pkts); i < len; ++i) {
		NdnlpPkt pkt = NdnlpPktA_get(pkts, i);
		if (NdnlpSvc_RLAPolicy(self, msg, pkt)) {
			DataPkt_setFlags(pkt, DataPkt_getFlags(pkt) | DataPktFlag_RLA);
			SentPkts_insert(self->sentPkts, pkt);
		}
		Link_write(self->link, pkt);
	}
	NdnlpPktA_dtor(pkts, false);
	CcnbMsg_dtor(msg);
}

bool NdnlpSvc_RLAPolicy(NdnlpSvc self, CcnbMsg msg, DataPkt pkt) {
	return self->rla;
}

void NdnlpSvc_link2ccn(NdnlpSvc self) {
	NdnlpPkt pkt;
	while (NULL != (pkt = Link_read(self->link))) {
		if (NdnlpPkt_isData(pkt)) NdnlpSvc_data(self, NdnlpPkt_asData(pkt));
		else if (NdnlpPkt_isAck(pkt)) NdnlpSvc_ack(self, NdnlpPkt_asAck(pkt));
		else NdnlpPkt_dtor(pkt);
	}
}

void NdnlpSvc_data(NdnlpSvc self, DataPkt pkt) {
	SeqNum sequence = DataPkt_getSequence(pkt);
	if (DataPkt_hasRLA(pkt)) AckQueue_insert(self->ackQueue, sequence);
	PartialMsgRes res = PartialMsgs_arrive(self->partialMsgs, pkt);
	if (!PartialMsgRes_isSuccess(res)) {
		NdnlpPkt_dtor(pkt);
		return;
	}
	if (res == PartialMsgRes_deliver) {
		CcnbMsg msg;
		while (NULL != (msg = PartialMsgs_getDeliver(self->partialMsgs))) {
			CcnLAC_write(self->lac, msg);
		}
	}
}

void NdnlpSvc_ack(NdnlpSvc self, AckPkt pkt) {
	AckBlock ab; AckBlock ab0 = NULL;
	while (NULL != (ab = AckPkt_getAckBlock(pkt, ab0))) {
		if (ab0 != NULL) AckBlock_dtor(ab0);
		AckBlockEn abe = AckBlockEn_ctor(ab);
		while (AckBlockEn_moveNext(abe)) {
			SeqNum seq = AckBlockEn_current(abe);
			SentPkts_remove(self->sentPkts, seq);
		}
		AckBlockEn_dtor(abe);
		ab0 = ab;
	}
	if (ab0 != NULL) AckBlock_dtor(ab0);
	NdnlpPkt_dtor(pkt);
}

void NdnlpSvc_retransmit(NdnlpSvc self) {
	DateTime sendBefore = DateTime_now() - self->retransmitTime;
	DataPkt pkt;
	while (NULL != (pkt = SentPkts_getRetransmit(self->sentPkts, sendBefore))) {
		Link_write(self->link, pkt);
	}
}

void NdnlpSvc_acknowledge(NdnlpSvc self) {
	DateTime now = DateTime_now();
	if (now < self->nextAckTime) return;
	self->nextAckTime = now + self->acknowledgeTime;
	NdnlpPktA pkts = AckQueue_getPkts(self->ackQueue);
	for (int i = 0, pktcount = NdnlpPktA_length(pkts); i < pktcount; ++i) {
		NdnlpPkt pkt = NdnlpPktA_get(pkts, i);
		Link_write(self->link, pkt);
	}
	NdnlpPktA_dtor(pkts, false);
}

