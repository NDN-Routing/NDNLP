#include <stdlib.h>
#include <string.h>
#include "ndnld.h"


DataPkt DataPkt_ctor(bool hasFragFields, size_t payloadLength) {
	int hdrlen = hasFragFields ? DataPkt_hdrlen2 : DataPkt_hdrlen1;
	int len = hdrlen + DataPkt_payloadhdrlen1
		+ CcnbH_sizeBlockHdr(payloadLength)
		+ payloadLength + DataPkt_trailerlen;

	DataPkt self = ccn_charbuf_create_n(len);
	ccn_charbuf_append(self, DataPkt_hdr, hdrlen);
	ccn_charbuf_append(self, DataPkt_payloadhdr, DataPkt_payloadhdrlen1);
	ccn_charbuf_append_string(self, CcnbH_getBlockHdr(payloadLength, CCN_BLOB));
	self->length += payloadLength;
	ccn_charbuf_append(self, DataPkt_trailer, DataPkt_trailerlen);

	if (self->length != len) {//error
		ccn_charbuf_destroy(&self);
		return NULL;
	}
	return self;
}

SeqNum DataPkt_getSequence(DataPkt self) {
	return SeqNum_readFrom(self->buf + DataPkt_offset_Sequence);
}

void DataPkt_setSequence(DataPkt self, SeqNum value) {
	SeqNum_writeTo(value, self->buf + DataPkt_offset_Sequence);
}

DataPktFlag DataPkt_getFlags(DataPkt self) {
	uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_Flags);
	return be16toh(*p);
}

void DataPkt_setFlags(DataPkt self, DataPktFlag value) {
	uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_Flags);
	*p = htobe16(value);
}

uint16_t DataPkt_getFragIndex(DataPkt self) {
	if (DataPkt_hasFragFields(self)) {
		uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_FragIndex);
		return be16toh(*p);
	} else {
		return DataPkt_default_FragIndex;
	}
}

bool DataPkt_setFragIndex(DataPkt self, uint16_t value) {
	if (DataPkt_hasFragFields(self)) {
		uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_FragIndex);
		*p = htobe16(value);
		return true;
	} else {
		return value == DataPkt_default_FragIndex;
	}
}

uint16_t DataPkt_getFragCount(DataPkt self) {
	if (DataPkt_hasFragFields(self)) {
		uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_FragCount);
		return be16toh(*p);
	} else {
		return DataPkt_default_FragCount;
	}
}

bool DataPkt_setFragCount(DataPkt self, uint16_t value) {
	if (DataPkt_hasFragFields(self)) {
		uint16_t* p = (uint16_t*)(self->buf + DataPkt_offset_FragCount);
		*p = htobe16(value);
		return true;
	} else {
		return value == DataPkt_default_FragCount;
	}
}

/*
size_t DataPkt_length(DataPkt self) {
	size_t payloadLength;
	uint8_t* payload = DataPkt_payload(self, &payloadLength);
	if (payload == NULL) return 0;//failure
	return (payload - self) + payloadLength + DataPkt_trailerlen;
}
*/

SeqNum DataPkt_getMessageIdentifier(DataPkt self) {
	return SeqNum_add(DataPkt_getSequence(self), -((int)DataPkt_getFragIndex(self)));
}

bool DataPkt_isFragmented(DataPkt self) {
	return DataPkt_getFragCount(self) > 1;
}

bool DataPkt_hasRLA(DataPkt self) {
	return DataPkt_getFlags(self) & DataPktFlag_RLA;
}

size_t DataPkt_payloadLength(DataPkt self) {
	size_t len = 0;
	DataPkt_payload(self, &len);
	return len;
}

uint8_t* DataPkt_payload(DataPkt self, size_t* len) {
	uint8_t* p = self->buf + (DataPkt_hasFragFields(self) ? DataPkt_hdrlen2 : DataPkt_hdrlen1) + DataPkt_payloadhdrlen1;
	uint64_t payloadLength;
	int payloadhdrlen2 = CcnbH_readBlockHdr(p, -1, &payloadLength, NULL);
	if (payloadhdrlen2 == 0) return NULL;
	if (len != NULL) *len = payloadLength;
	return p + payloadhdrlen2;
}

bool DataPkt_hasFragFields(DataPkt self) {
	return 0 == memcmp(self->buf + DataPkt_hdrlen1, DataPkt_hdr + DataPkt_hdrlen1, DataPkt_fraglen0);
}

