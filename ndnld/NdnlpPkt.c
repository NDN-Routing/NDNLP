#include <stdlib.h>
#include <string.h>
#include <ccn/ccn.h>
#include "ndnld.h"


int CcnbH_sizeBlockHdr(uint64_t number) {
	if (number <= 0xF) return 1;
	if (number <= 0x7FF) return 2;
	if (number <= 0x3FFFF) return 3;
	if (number <= 0x1FFFFFF) return 4;
	if (number <= 0xFFFFFFFF) return 5;
	if (number <= 0x7FFFFFFFFF) return 6;
	if (number <= 0x3FFFFFFFFFFF) return 7;
	if (number <= 0x1FFFFFFFFFFFFF) return 8;
	if (number <= 0xFFFFFFFFFFFFFFF) return 9;
	return 10;
}

char* CcnbH_getBlockHdr(uint64_t number, enum ccn_tt tt) {
	static char b[CcnbH_maxBlockHdr + 1]; memset(b, 0, CcnbH_maxBlockHdr + 1);
	int len = 1;
	b[CcnbH_maxBlockHdr - len] = (uint8_t)(0x80 | ((number & 0x0F) << 3) | (tt & 0x07));
	number >>= 4;
	if (number != 0) {
		while (++len <= CcnbH_maxBlockHdr) {
			b[CcnbH_maxBlockHdr - len] = (uint8_t)(number & 0x7F);
			if ((number >>= 7) == 0) break;
		}
		if (number != 0) return NULL;//error
	}

	return b + CcnbH_maxBlockHdr - len;
}

int CcnbH_readBlockHdr(uint8_t* buf, size_t len, uint64_t* pnumber, enum ccn_tt* ptt) {
	uint64_t number = 0; enum ccn_tt tt = CCN_NO_TOKEN;
	int i;
	if (len < 0) len = 10;
	for (i = 0; i < len; ++i) {
		uint8_t ch = buf[i];
		if (ch == 0) return 0;
		if (ch & 0x80) {
			number <<= 4;
			number |= (ch & 0x78) >> 3;
			tt = (uint8_t)(ch & 0x07);
			break;
		} else {
			number <<= 7;
			number |= ch;
		}
	}
	if (tt == CCN_NO_TOKEN) return 0;
	if (pnumber != NULL) *pnumber = number;
	if (ptt != NULL) *ptt = tt;
	return i + 1;
}

NdnlpPkt NdnlpPkt_ctor(void* buf, size_t len, bool clone) {
	struct ccn_skeleton_decoder rdecoder = {0};
	struct ccn_skeleton_decoder *rd = &rdecoder;
	size_t dres = ccn_skeleton_decode(rd, buf, len);
	if (!CCN_FINAL_DSTATE(rd->state) || dres <= 0) return NULL;

	NdnlpPkt self = ccn_charbuf_create();
	if (clone) {
		ccn_charbuf_append(self, buf, dres);
	} else {
		self->buf = buf;
		self->length = dres;
		self->limit = len;
	}
	return self;
}

void NdnlpPkt_dtor(NdnlpPkt self) {
	ccn_charbuf_destroy(&self);
}

uint8_t* NdnlpPkt_detachBuf(NdnlpPkt self) {
	uint8_t* buf = self->buf;
	self->buf = NULL;
	ccn_charbuf_destroy(&self);
	return buf;
}

NdnlpPkt NdnlpPkt_clone(NdnlpPkt other) {
	NdnlpPkt self = ccn_charbuf_create();
	ccn_charbuf_append_charbuf(self, other);
	return self;
}

size_t NdnlpPkt_length(NdnlpPkt self) {
	return self->length;
}

bool NdnlpPkt_isData(NdnlpPkt self) {
	if (self->length < NdnlpPkt_typelen) return false;
	return 0 == memcmp(self->buf, DataPkt_hdr, NdnlpPkt_typelen);
}

DataPkt NdnlpPkt_asData(NdnlpPkt self) {
	if (NdnlpPkt_isData(self)) return (DataPkt)self;
	return NULL;
}

bool NdnlpPkt_isAck(NdnlpPkt self) {
	if (self->length < NdnlpPkt_typelen) return false;
	return 0 == memcmp(self->buf, AckPkt_hdr, NdnlpPkt_typelen);
}

AckPkt NdnlpPkt_asAck(NdnlpPkt self) {
	if (NdnlpPkt_isAck(self)) return (AckPkt)self;
	return NULL;
}

NdnlpPktA NdnlpPktA_ctor(int length) {
	if (length < 0) return NULL;
	NdnlpPktA self = ALLOCSELF;
	if (length == 0) {
		self->capacity = NdnlpPktA_initialCapacity;
	} else {
		self->capacity = self->length = length;
	}
	self->items = (NdnlpPkt*)calloc(self->capacity, sizeof(NdnlpPkt));
	return self;
}

void NdnlpPktA_dtor(NdnlpPktA self, bool dtorPkt) {
	if (dtorPkt) {
		for (int i = 0; i < self->length; ++i) {
			NdnlpPkt item = self->items[i];
			if (item != NULL) NdnlpPkt_dtor(item);
		}
	}
	free(self->items);
	free(self);
}

int NdnlpPktA_length(NdnlpPktA self) {
	return self->length;
}

NdnlpPkt NdnlpPktA_get(NdnlpPktA self, int index) {
	if (index < 0 || index >= self->length) return NULL;
	return self->items[index];
}

void NdnlpPktA_set(NdnlpPktA self, int index, NdnlpPkt item) {
	if (index < 0 || index >= self->length) return;
	self->items[index] = item;
}

void NdnlpPktA_append(NdnlpPktA self, NdnlpPkt item) {
	if (self->length == self->capacity) {
		int newcapacity = self->capacity * NdnlpPktA_increaseCapacity;
		NdnlpPkt* newitems = (NdnlpPkt*)calloc(newcapacity, sizeof(NdnlpPkt));
		memcpy(newitems, self->items, self->capacity * sizeof(NdnlpPkt));
		free(self->items);
		self->capacity = newcapacity;
		self->items = newitems;
	}
	NdnlpPktA_set(self, (self->length)++, item);
}

