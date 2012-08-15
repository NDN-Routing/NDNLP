#include <stdlib.h>
#include <stdio.h>
#include "ndnld.h"

SeqNum SeqNum_add(SeqNum self, int diff) {
	return (self + diff) & SeqNum_mask;
}

SeqNum SeqNum_rand(void) {
	SeqNum value = 0;
	FILE* urandom = fopen("/dev/urandom", "r");
	fread(&value, 8, 1, urandom);
	fclose(urandom);
	return value & SeqNum_mask;
}

SeqNum SeqNum_readFrom(void* buf) {
	uint8_t* p = (uint8_t*)buf;
	return ((uint64_t)p[0] << 40) + ((uint64_t)p[1] << 32) + ((uint64_t)p[2] << 24) + ((uint64_t)p[3] << 16) + ((uint64_t)p[4] << 8) + (uint64_t)p[5];
}

void SeqNum_writeTo(SeqNum self, void* buf) {
	uint8_t* p = (uint8_t*)buf;
	p[0] = (uint8_t)((self >> 40) & 0xFF);
	p[1] = (uint8_t)((self >> 32) & 0xFF);
	p[2] = (uint8_t)((self >> 24) & 0xFF);
	p[3] = (uint8_t)((self >> 16) & 0xFF);
	p[4] = (uint8_t)((self >> 8) & 0xFF);
	p[5] = (uint8_t)(self & 0xFF);
}

SeqGen SeqGen_ctor(void) {
	SeqGen self = ALLOCSELF;
	self->next = SeqNum_rand();
	return self;
}

void SeqGen_dtor(SeqGen self) {
	free(self);
}

SeqNum SeqGen_next(SeqGen self) {
	SeqNum sequence = self->next;
	self->next = SeqNum_add(self->next, 1);
	return sequence;
}

SeqBlock SeqGen_nextBlock(SeqGen self, int size) {
	SeqBlock block = SeqBlock_ctor(self->next, size);
	self->next = SeqNum_add(self->next, size);
	return block;
}

SeqBlock SeqBlock_ctor(SeqNum base, int size) {
	SeqBlock self = ALLOCSELF;
	self->base = base;
	self->size = size;
	return self;
}

void SeqBlock_dtor(SeqBlock self) {
	free(self);
}

SeqNum SeqBlock_item(SeqBlock self, int index) {
	if (index < 0 || index >= self->size) return 0;
	return SeqNum_add(self->base, index);
}

