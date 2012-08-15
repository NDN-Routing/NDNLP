#include <stdlib.h>
#include <string.h>
#include "ndnld.h"


AckQueue AckQueue_ctor(size_t mtu) {
	AckQueue self = ALLOCSELF;
	self->mtu = mtu;
	self->pkts = NdnlpPktA_ctor(0);
	self->bitmap = (uint8_t*)calloc(mtu, 1);
	return self;
}

void AckQueue_dtor(AckQueue self) {
	free(self->bitmap);
	if (self->lastBlock != NULL) AckBlock_dtor(self->lastBlock);
	if (self->pkt != NULL) NdnlpPkt_dtor(self->pkt);
	NdnlpPktA_dtor(self->pkts, true);
	free(self);
}

void AckQueue_insert(AckQueue self, SeqNum sequence) {
	size_t offset; uint8_t bit;
	if (self->hasBitmap) {
		size_t lastOffset;
		AckQueue_bitmapOffset(self, self->seqmax, &lastOffset, NULL);
		if (!AckQueue_bitmapOffset(self, sequence, &offset, &bit)
			|| offset >= self->mbl
			|| (offset > lastOffset && offset - lastOffset > AckQueue_newBlockGapThreshold)) {
			AckQueue_bitmapIntoPkt(self);
		}
	}
	if (!self->hasBitmap) {
		AckQueue_newBitmap(self, sequence);
		AckQueue_bitmapOffset(self, sequence, &offset, &bit);
	}
	self->bitmap[offset] |= bit;
	if (sequence > self->seqmax) self->seqmax = sequence;
}

NdnlpPktA AckQueue_getPkts(AckQueue self) {
	AckQueue_bitmapIntoPkt(self);
	AckQueue_pktIntoPkts(self);
	NdnlpPktA pkts = self->pkts;
	self->pkts = NdnlpPktA_ctor(0);
	return pkts;
}

void AckQueue_newBitmap(AckQueue self, SeqNum sequence) {
	self->hasBitmap = true;
	if (self->pkt == NULL) {
		self->pkt = AckPkt_ctor();
		self->lastBlock = NULL;
	}
	self->mbl = AckPkt_remainingBitmapSize(self->pkt, self->mtu);
	if (self->mbl == 0) {
		AckQueue_pktIntoPkts(self);
		self->pkt = AckPkt_ctor();
		self->mbl = AckPkt_remainingBitmapSize(self->pkt, self->mtu);
	}
	memset(self->bitmap, 0, self->mtu);
	self->seqbase = self->seqmax = sequence;
}

bool AckQueue_bitmapOffset(AckQueue self, SeqNum sequence, size_t* poffset, uint8_t* pbit) {
	int64_t diff = (int64_t)sequence - (int64_t)(self->seqbase);
	if (diff < 0) return false;
	if (poffset != NULL) *poffset = diff / 8;
	if (pbit != NULL) *pbit = (uint8_t)(0x80 >> (diff % 8));
	return true;
}

void AckQueue_bitmapIntoPkt(AckQueue self) {
	if (!self->hasBitmap) return;
	size_t bitmapLength;
	AckQueue_bitmapOffset(self, self->seqmax, &bitmapLength, NULL);
	++bitmapLength;
	AckBlock ab = AckPkt_addAckBlock(self->pkt, self->lastBlock, bitmapLength);
	AckBlock_setSequenceBase(ab, self->seqbase);
	memcpy(AckBlock_bitmap(ab, NULL), self->bitmap, bitmapLength);
	if (self->lastBlock != NULL) AckBlock_dtor(self->lastBlock);
	self->lastBlock = ab;
 	self->hasBitmap = false;
}

void AckQueue_pktIntoPkts(AckQueue self) {
	if (self->pkt == NULL || self->lastBlock == NULL) return;
	NdnlpPktA_append(self->pkts, self->pkt);
	AckBlock_dtor(self->lastBlock);
	self->lastBlock = NULL;
	self->pkt = NULL;
}

