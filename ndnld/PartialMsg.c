#include <stdlib.h>
#include <ccn/hashtb.h>
#include "ndnld.h"

PartialMsgs PartialMsgs_ctor(void) {	
	PartialMsgs self = ALLOCSELF;
	self->index = hashtb_create(sizeof(PartialMsgRec), NULL);
	return self;
}

void PartialMsgs_dtor(PartialMsgs self) {
	PartialMsgRec p, pnext;
	p = self->phead;
	while (p != NULL) { pnext = p->next; PartialMsgRec_dtor(p, false); p = pnext; }
	p = self->dhead;
	while (p != NULL) { pnext = p->next; PartialMsgRec_dtor(p, false); p = pnext; }
	hashtb_destroy(&(self->index));
	free(self);
}

PartialMsgRes PartialMsgs_arrive(PartialMsgs self, DataPkt pkt) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; PartialMsgRec rec; PartialMsgRes res;
	
	SeqNum msgIdentifier = DataPkt_getMessageIdentifier(pkt);
	hashtb_start(self->index, hte);
	htres = hashtb_seek(hte, &msgIdentifier, sizeof(msgIdentifier), 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((PartialMsgRec*)hte->data);
		res = PartialMsgRec_addPkt(rec, pkt);
	} else if (htres == HT_NEW_ENTRY) {
		res = PartialMsgRec_create(pkt, &rec);
		if (PartialMsgRes_isSuccess(res)) {
			*((PartialMsgRec*)hte->data) = rec;
		} else {
			hashtb_delete(hte);
		}
	}
	if (PartialMsgRes_isSuccess(res)) {
		if (htres == HT_OLD_ENTRY) {
			PartialMsgs_pDetach(self, rec);
			--(self->count);
		}
		if (res == PartialMsgRes_deliver) {
			hashtb_delete(hte);
			PartialMsgs_dInsert(self, rec);
		} else {
			PartialMsgs_pInsert(self, rec);
			++(self->count);
		}
	}
	hashtb_end(hte);
	return res;
}

CcnbMsg PartialMsgs_getDeliver(PartialMsgs self) {
	if (self->dhead == NULL) return NULL;
	PartialMsgRec rec = self->dhead;
	PartialMsgs_dDetach(self, rec);
	CcnbMsg msg = rec->message;
	PartialMsgRec_dtor(rec, true);
	return msg;
}

void PartialMsgs_pInsert(PartialMsgs self, PartialMsgRec rec) {
	if (self->ptail == NULL) {
		self->phead = self->ptail = rec;
	} else {
		rec->prev = self->ptail;
		self->ptail = rec->prev->next = rec;
	}
}

void PartialMsgs_pDetach(PartialMsgs self, PartialMsgRec rec) {
	if (rec->prev == NULL) {
		if (self->phead == rec) self->phead = rec->next;
	} else {
		if (rec->prev->next == rec) rec->prev->next = rec->next;
	}
	if (rec->next == NULL) {
		if (self->ptail == rec) self->ptail = rec->prev;
	} else {
		if (rec->next->prev == rec) rec->next->prev = rec->prev;
	}
	rec->prev = rec->next = NULL;
}

void PartialMsgs_dInsert(PartialMsgs self, PartialMsgRec rec) {
	if (self->dtail == NULL) {
		self->dhead = self->dtail = rec;
	} else {
		rec->prev = self->dtail;
		self->dtail = rec->prev->next = rec;
	}
}

void PartialMsgs_dDetach(PartialMsgs self, PartialMsgRec rec) {
	if (rec->prev == NULL) {
		if (self->dhead == rec) self->dhead = rec->next;
	} else {
		if (rec->prev->next == rec) rec->prev->next = rec->next;
	}
	if (rec->next == NULL) {
		if (self->dtail == rec) self->dtail = rec->prev;
	} else {
		if (rec->next->prev == rec) rec->next->prev = rec->prev;
	}
	rec->prev = rec->next = NULL;
}

void PartialMsgRec_dtor(PartialMsgRec self, bool keepMessage) {
	if (self->fragmentArrived != NULL) free(self->fragmentArrived);
	if (self->fragments != NULL) {
		for (int i = 0; i < self->fragmentCount; ++i) {
			if (self->fragments[i] != NULL) NdnlpPkt_dtor(self->fragments[i]);
		}
		free(self->fragments);
	}
	if (!keepMessage && self->message != NULL) CcnbMsg_dtor(self->message);
	if (self->lastFragment != NULL) NdnlpPkt_dtor(self->lastFragment);
	free(self);
}

PartialMsgRes PartialMsgRec_create(DataPkt pkt, PartialMsgRec* pself) {
	uint16_t fragIndex = DataPkt_getFragIndex(pkt);
	uint16_t fragCount = DataPkt_getFragCount(pkt);
	if (fragCount < 1 || fragIndex >= fragCount) return PartialMsgRes_outRange;

	PartialMsgRec self = ALLOCSELF;
	self->identifier = DataPkt_getMessageIdentifier(pkt);
	self->fragmentCount = fragCount;
	self->fragmentArrived = (bool*)calloc(fragCount, sizeof(bool));
	PartialMsgRec_addPktNoCheck(self, pkt);
	*pself = self;
	return PartialMsgRec_checkDeliver(self);
}

PartialMsgRes PartialMsgRec_addPkt(PartialMsgRec self, DataPkt pkt) {
	if (self->fragmentCount != DataPkt_getFragCount(pkt)) return PartialMsgRes_mismatch;
	uint16_t fragIndex = DataPkt_getFragIndex(pkt);
	if (fragIndex >= self->fragmentCount) return PartialMsgRes_outRange;
	if (self->fragmentArrived[fragIndex]) return PartialMsgRes_duplicate;
	if (self->fragmentSize != PartialMsgRec_unknownFragmentSize && fragIndex != self->fragmentCount - 1 && self->fragmentSize != DataPkt_payloadLength(pkt)) return PartialMsgRes_mismatch;
	PartialMsgRec_addPktNoCheck(self, pkt);
	return PartialMsgRec_checkDeliver(self);
}

void PartialMsgRec_addPktNoCheck(PartialMsgRec self, DataPkt pkt) {
	uint16_t fragIndex = DataPkt_getFragIndex(pkt);
	self->arriveTime = DateTime_now();
	++self->arriveCount;
	self->fragmentArrived[fragIndex] = true;

	if (self->fragmentCount > 1 && fragIndex == self->fragmentCount - 1 && self->fragmentSize == PartialMsgRec_unknownFragmentSize) {//got last pkt, don't know msg size
		self->lastFragment = pkt;
	} else {
		if (self->fragmentSize == PartialMsgRec_unknownFragmentSize) {
			self->fragmentSize = DataPkt_payloadLength(pkt);
			size_t msgSize = self->fragmentSize * self->fragmentCount;
			if (msgSize > PartialMsgRec_maxPreallocateBuffer) {
				self->fragments = calloc(self->fragmentCount, sizeof(DataPkt));
			} else {
				self->message = CcnbMsg_ctor(msgSize);
			}
			if (self->lastFragment != NULL) {
				PartialMsgRec_addPktStore(self, self->lastFragment);
				self->lastFragment = NULL;
			}
		}
		PartialMsgRec_addPktStore(self, pkt);
	}
}

void PartialMsgRec_addPktStore(PartialMsgRec self, DataPkt pkt) {
	uint16_t fragIndex = DataPkt_getFragIndex(pkt);
	if (self->message != NULL) {
		PartialMsgRec_addPktMsg(self, pkt);
	} else if (self->fragments != NULL) {
		self->fragments[fragIndex] = pkt;
	}
}

void PartialMsgRec_addPktMsg(PartialMsgRec self, DataPkt pkt) {
	uint16_t fragIndex = DataPkt_getFragIndex(pkt);
	size_t fragSize;
	uint8_t* payload = DataPkt_payload(pkt, &fragSize);
	if (fragIndex == self->fragmentCount - 1) {
		CcnbMsg_resize(self->message, self->fragmentSize * (self->fragmentCount - 1) + fragSize);
	}
	CcnbMsg_setBodyPart(self->message, payload, self->fragmentSize * fragIndex, fragSize);
	NdnlpPkt_dtor(pkt);
}

PartialMsgRes PartialMsgRec_checkDeliver(PartialMsgRec self) {
	if (self->arriveCount == self->fragmentCount) {
		PartialMsgRec_makeMsg(self);
		return PartialMsgRes_deliver;
	}
	return PartialMsgRes_stored;
}

void PartialMsgRec_makeMsg(PartialMsgRec self) {
	if (self->message != NULL) return;
	size_t fragSize = self->fragmentSize;
	uint16_t fragCount = self->fragmentCount;
	size_t lastFragSize = DataPkt_payloadLength(self->fragments[fragCount - 1]);
	size_t msgSize = fragSize * (fragCount - 1) + lastFragSize;
	self->message = CcnbMsg_ctor(msgSize);
	for (int i = 0; i < fragCount - 1; ++i) {
		DataPkt pkt = self->fragments[i];
		size_t payloadLength;
		uint8_t* payload = DataPkt_payload(pkt, &payloadLength);
		CcnbMsg_setBodyPart(self->message, payload, fragSize * i, payloadLength);
		NdnlpPkt_dtor(pkt);
	}
}

