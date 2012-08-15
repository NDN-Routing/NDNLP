#include <stdlib.h>
#include <ccn/hashtb.h>
#include "ndnld.h"

SentPkts SentPkts_ctor(int capacity, int retryCount) {
	SentPkts self = ALLOCSELF;
	self->capacity = capacity;
	self->index = hashtb_create(sizeof(SentPktRec), NULL);
	self->retryCount = retryCount;
	return self;
}

void SentPkts_dtor(SentPkts self) {
	SentPktRec p, pnext; p = self->shead;
	while (p != NULL) { pnext = p->snext; SentPktRec_dtor(p, false); p = pnext; }
	hashtb_destroy(&(self->index));
	free(self);
}

void SentPkts_remove(SentPkts self, SeqNum sequence) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; SentPktRec rec;
	
	hashtb_start(self->index, hte);
	htres = hashtb_seek(hte, &sequence, sizeof(SeqNum), 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((SentPktRec*)hte->data);
		SentPkts_rDetach(self, rec);
		SentPkts_sDetach(self, rec);
		SentPktRec_dtor(rec, false);
	}
	hashtb_delete(hte);
	hashtb_end(hte);
}

void SentPkts_insert(SentPkts self, DataPkt pkt) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; SeqNum sequence; SentPktRec rec;
	
	sequence = DataPkt_getSequence(pkt);
	hashtb_start(self->index, hte);
	htres = hashtb_seek(hte, &sequence, sizeof(SeqNum), 0);
	if (htres == HT_NEW_ENTRY) {
		rec = SentPktRec_ctor(pkt, self->retryCount);
		*((SentPktRec*)hte->data) = rec;
		SentPkts_sInsert(self, rec);
		SentPkts_rInsert(self, rec);
	}
	hashtb_end(hte);
	if (self->count > self->capacity) {
		SentPkts_remove(self, DataPkt_getSequence(self->shead->pkt));
	}
}

DataPkt SentPkts_getRetransmit(SentPkts self, DateTime sendBefore) {
	SentPktRec rec = self->rhead;
	if (rec == NULL || rec->sendTime >= sendBefore) return NULL;

	SentPkts_rDetach(self, rec);
	DataPkt pkt = rec->pkt;
	if (--rec->retryCount <= 0) {
		struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
		SeqNum sequence = DataPkt_getSequence(pkt);
		hashtb_start(self->index, hte);
		hashtb_seek(hte, &sequence, sizeof(SeqNum), 0);
		hashtb_delete(hte);
		hashtb_end(hte);

		SentPkts_sDetach(self, rec);
		SentPktRec_dtor(rec, true);
	} else {
		rec->sendTime = DateTime_now();
		SentPkts_rInsert(self, rec);
		pkt = NdnlpPkt_clone(pkt);
	}
	return pkt;
}

void SentPkts_sInsert(SentPkts self, SentPktRec rec) {
	if (self->stail == NULL) {
		self->shead = self->stail = rec;
	} else {
		rec->sprev = self->stail;
		self->stail = rec->sprev->snext = rec;
	}
	++self->count;
}

void SentPkts_sDetach(SentPkts self, SentPktRec rec) {
	if (rec->sprev == NULL) {
		if (self->shead == rec) self->shead = rec->snext;
	} else {
		if (rec->sprev->snext == rec) rec->sprev->snext = rec->snext;
	}
	if (rec->snext == NULL) {
		if (self->stail == rec) self->stail = rec->sprev;
	} else {
		if (rec->snext->sprev == rec) rec->snext->sprev = rec->sprev;
	}
	rec->sprev = rec->snext = NULL;
	--self->count;
}

void SentPkts_rInsert(SentPkts self, SentPktRec rec) {
	if (self->rtail == NULL) {
		self->rhead = self->rtail = rec;
	} else {
		rec->rprev = self->rtail;
		self->rtail = rec->rprev->rnext = rec;
	}
}

void SentPkts_rDetach(SentPkts self, SentPktRec rec) {
	if (rec->rprev == NULL) {
		if (self->rhead == rec) self->rhead = rec->rnext;
	} else {
		if (rec->rprev->rnext == rec) rec->rprev->rnext = rec->rnext;
	}
	if (rec->rnext == NULL) {
		if (self->rtail == rec) self->rtail = rec->rprev;
	} else {
		if (rec->rnext->rprev == rec) rec->rnext->rprev = rec->rprev;
	}
	rec->rprev = rec->rnext = NULL;
}

SentPktRec SentPktRec_ctor(DataPkt pkt, int retryCount) {
	SentPktRec self = ALLOCSELF;
	self->sendTime = DateTime_now();
	self->retryCount = retryCount;
	self->pkt = NdnlpPkt_clone(pkt);
	return self;
}

void SentPktRec_dtor(SentPktRec self, bool keepPkt) {
	if (!keepPkt) NdnlpPkt_dtor(self->pkt);
	free(self);
}

