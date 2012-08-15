#include <stdlib.h>
#include <string.h>
#include "ndnld.h"


AckPkt AckPkt_ctor(void) {
	AckPkt self = ccn_charbuf_create();
	ccn_charbuf_append(self, AckPkt_hdr, AckPkt_hdrlen);
	ccn_charbuf_append(self, AckPkt_trailer, AckPkt_trailerlen);
	return self;
}

AckBlock AckPkt_getAckBlock(AckPkt self, AckBlock previous) {
	size_t offset = AckPkt_nextAckBlockOffset(self, previous);
	if (offset + AckBlock_hdrlen0 >= self->length) return NULL;
	if (0 == memcmp(self->buf + offset, AckBlock_hdr, AckBlock_hdrlen0)) return AckBlock_ctor(self, offset);
	return NULL;
}

AckBlock AckPkt_addAckBlock(AckPkt self, AckBlock last, size_t bitmapLength) {
	size_t offset = AckPkt_nextAckBlockOffset(self, last);
	if (0 != memcmp(self->buf + offset, AckPkt_trailer, AckPkt_trailerlen)) return NULL;//last is invalid

	self->length -= AckPkt_trailerlen;
	size_t ablength = AckBlock_newlength(bitmapLength);
	ccn_charbuf_reserve(self, ablength);	
	AckBlock ab = AckBlock_ctor(self, offset);
	AckBlock_newappend(ab, bitmapLength);
	ccn_charbuf_append(self, AckPkt_trailer, AckPkt_trailerlen);
	return ab;
}

size_t AckPkt_remainingBitmapSize(AckPkt self, size_t mtu) {
	int remaining = mtu - NdnlpPkt_length(self) - AckBlock_hdrlen - AckBlock_trailerlen;
	remaining -= CcnbH_sizeBlockHdr(remaining);
	return remaining > 0 ? remaining : 0;
}

size_t AckPkt_nextAckBlockOffset(AckPkt self, AckBlock previous) {
	size_t offset;
	if (previous == NULL) offset = AckPkt_hdrlen;
	else offset = previous->offset + AckBlock_length(previous);
	return offset;
}

AckBlock AckBlock_ctor(AckPkt pkt, size_t offset) {
	AckBlock self = ALLOCSELF;
	self->pkt = pkt;
	self->offset = offset;
	return self;
}

void AckBlock_dtor(AckBlock self) {
	free(self);
}

#define AckBlock_buf(self) ((self)->pkt->buf + (self)->offset)

SeqNum AckBlock_getSequenceBase(AckBlock self) {
	return SeqNum_readFrom(AckBlock_buf(self) + AckBlock_offset_SequenceBase);
}

void AckBlock_setSequenceBase(AckBlock self, SeqNum value) {
	SeqNum_writeTo(value, AckBlock_buf(self) + AckBlock_offset_SequenceBase);
}

size_t AckBlock_length(AckBlock self) {
	size_t bitmapLength;
	uint8_t* bitmap = AckBlock_bitmap(self, &bitmapLength);
	if (bitmap == NULL) return 0;//failure
	return (bitmap - AckBlock_buf(self)) + bitmapLength + AckBlock_trailerlen;
}

size_t AckBlock_bitmapLength(AckBlock self) {
	size_t len = 0;
	AckBlock_bitmap(self, &len);
	return len;
}

uint8_t* AckBlock_bitmap(AckBlock self, size_t* plen) {
	uint8_t* p = AckBlock_buf(self) + AckBlock_hdrlen;
	uint64_t bitmapLength;
	int bitmaphdrlen2 = CcnbH_readBlockHdr(p, -1, &bitmapLength, NULL);
	if (bitmaphdrlen2 == 0) return NULL;
	if (plen != NULL) *plen = bitmapLength;
	return p + bitmaphdrlen2;
}

size_t AckBlock_newlength(size_t bitmapLength) {
	return AckBlock_hdrlen + CcnbH_sizeBlockHdr(bitmapLength) + bitmapLength + AckBlock_trailerlen;
}

void AckBlock_newappend(AckBlock self, size_t bitmapLength) {
	if (self->pkt->length != self->offset) return;//invalid offset
	ccn_charbuf_append(self->pkt, AckBlock_hdr, AckBlock_hdrlen);
	ccn_charbuf_append_string(self->pkt, CcnbH_getBlockHdr(bitmapLength, CCN_BLOB));
	self->pkt->length += bitmapLength;
	ccn_charbuf_append(self->pkt, AckBlock_trailer, AckBlock_trailerlen);
}

AckBlockEn AckBlockEn_ctor(AckBlock ab) {
	AckBlockEn self = ALLOCSELF;
	self->ab = ab;
	self->seqBase = AckBlock_getSequenceBase(ab);
	AckBlockEn_reset(self);
	return self;
}

void AckBlockEn_dtor(AckBlockEn self) {
	free(self);
}

void AckBlockEn_reset(AckBlockEn self) {
	size_t bitmapLength;
	uint8_t* bitmap = AckBlock_bitmap(self->ab, &bitmapLength);
	self->pos = bitmap - 1;
	self->bitmapEnd = bitmap + bitmapLength;
	self->bitmask = 0x01;
	self->sequence = SeqNum_add(self->seqBase, -1);
}

bool AckBlockEn_moveNext(AckBlockEn self) {
	bool selected;
	do {
		if (self->bitmask == 0x01) {
			self->pos += 1;
			self->bitmask = 0x80;
			if (self->pos >= self->bitmapEnd) return false;
		} else {
			self->bitmask >>= 1;
		}
		self->sequence = SeqNum_add(self->sequence, 1);
		selected = *(self->pos) & self->bitmask;
	} while (!selected);
	return true;
}

SeqNum AckBlockEn_current(AckBlockEn self) {
	return self->sequence;
}


