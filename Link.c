#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include "ndnld.h"

Link Link_ctorStream(NBS nbs) {
	if (NBS_isDgram(nbs)) return NULL;
	Link self = ALLOCSELF;
	self->nbs = nbs;
	self->ccnbor = CcnbOR_ctor(nbs);
	return self;
}

Link Link_ctorDgram(LMD lmd, SockAddr addr) {
	Link self = ALLOCSELF;
	self->lmd = lmd;
	self->addr = SockAddr_clone(addr);
	LMD_reg(lmd, self->addr);
	self->nbs = LMD_nbs(lmd);
	return self;
}

void Link_dtor(Link self) {
	if (self->lmd != NULL) {
		LMD_unreg(self->lmd, self->addr);
	} else {
		NBS_dtor(self->nbs);
	}
	free(self);
}

bool Link_error(Link self) {
	return false;
}

void Link_setLossy(Link self, float lossPct) {
	if (lossPct <= 0) {
		self->lossy = 0;
	} else {
		self->lossy = lossPct * RAND_MAX;
	}
}

SockAddr Link_addr(Link self) {
	return self->addr;
}

size_t Link_mtu(Link self) {
	if (self->lmd == NULL) return 0xFFFFFFFF;//infinite
	else return LMD_mtu(self->lmd);
}

NdnlpPkt Link_read(Link self) {
	if (self->lmd != NULL) {
		SockAddr addr = SockAddr_clone(self->addr);
		NdnlpPkt pkt = LMD_read(self->lmd, addr);
		SockAddr_dtor(addr);
		return pkt;
	} else {
		struct ccn_charbuf* cbuf = CcnbOR_read(self->ccnbor);
		if (cbuf == NULL) return NULL;
		return (NdnlpPkt)cbuf;
	}
}

void Link_write(Link self, NdnlpPkt pkt) {
	if (self->lossy > 0 && rand() < self->lossy) {
		NdnlpPkt_dtor(pkt);
		return;
	}
	size_t len = NdnlpPkt_length(pkt);
	uint8_t* buf = NdnlpPkt_detachBuf(pkt);
	NBS_write(self->nbs, buf, 0, len, self->addr);
}

LMD LMD_ctor(NBS nbs, SockAddr localAddr, size_t mtu) {
	if (!NBS_isDgram(nbs)) return NULL;
	LMD self = ALLOCSELF;
	self->nbs = nbs;
	if (localAddr != NULL) self->localAddr = SockAddr_clone(localAddr);
	self->mtu = mtu;
	self->demux = hashtb_create(sizeof(LMDRec), NULL);
	return self;
}

void LMD_dtor(LMD self) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	LMDRec rec;
	for (hashtb_start(self->demux, hte); hte->data != NULL; ) {
		rec = *((LMDRec*)hte->data);
		LMDRec_dtor(rec);
		hashtb_delete(hte);
	}
	hashtb_end(hte);

	NBS_dtor(self->nbs);
	if (self->localAddr != NULL) SockAddr_dtor(self->localAddr);
	hashtb_destroy(&(self->demux));
	free(self);
}

SockAddr LMD_localAddr(LMD self) {
	return self->localAddr;
}

size_t LMD_mtu(LMD self) {
	return self->mtu;
}

NBS LMD_nbs(LMD self) {
	return self->nbs;
}

SockAddr LMD_fallbackAddr() {
	return SockAddr_clone(LMD_fallbackAddr_inst());
}

bool LMD_registered(LMD self, SockAddr srcaddr) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; bool found = false;
	struct ccn_charbuf* hashkey = SockAddr_hashkey(srcaddr);

	hashtb_start(self->demux, hte);
	htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
	if (htres == HT_OLD_ENTRY) {
		found = true;
	} else {
		hashtb_delete(hte);
	}
	hashtb_end(hte);

	return found;
}

void LMD_reg(LMD self, SockAddr srcaddr) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; LMDRec rec = NULL;
	struct ccn_charbuf* hashkey = SockAddr_hashkey(srcaddr);

	hashtb_start(self->demux, hte);
	htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
	if (htres == HT_NEW_ENTRY) {
		rec = LMDRec_ctor(srcaddr);
		*((LMDRec*)hte->data) = rec;
	}
	hashtb_end(hte);

	if (SockAddr_equals(LMD_fallbackAddr_inst(), srcaddr)) {
		self->fallback = rec;
	}
}

void LMD_unreg(LMD self, SockAddr srcaddr) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; LMDRec rec = NULL;
	struct ccn_charbuf* hashkey = SockAddr_hashkey(srcaddr);

	hashtb_start(self->demux, hte);
	htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((LMDRec*)hte->data);
	}
	hashtb_delete(hte);
	hashtb_end(hte);

	if (rec != NULL) {
		if (self->fallback == rec) self->fallback = NULL;
		LMDRec_dtor(rec);
	}
}

NdnlpPkt LMD_read(LMD self, SockAddr srcaddr) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; LMDRec rec = NULL;
	struct ccn_charbuf* hashkey = SockAddr_hashkey(srcaddr);

	hashtb_start(self->demux, hte);
	htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((LMDRec*)hte->data);
	} else if (htres == HT_NEW_ENTRY) {
		hashtb_delete(hte);
	}
	hashtb_end(hte);

	if (rec == NULL) return NULL;
	NdnlpPkt pkt = LMDRec_read(rec, srcaddr);
	if (pkt == NULL) {
		LMD_demux(self);
		pkt = LMDRec_read(rec, srcaddr);
	}
	return pkt;
}

SockAddr LMD_fallbackAddr_inst() {
	static SockAddr fallbackAddr = NULL;
	if (fallbackAddr == NULL) {
		struct sockaddr_in sa = {0};
		sa.sin_family = AF_INET;
		sa.sin_port = 0;
		sa.sin_addr.s_addr = 0xFEFEFEFE;
		fallbackAddr = SockAddr_create(&sa, sizeof(struct sockaddr_in));
	}
	return fallbackAddr;
}

void LMD_demux(LMD self) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; LMDRec rec;
	SockAddr addr = SockAddr_ctor(); struct ccn_charbuf* hashkey;
	void* buf = malloc(self->mtu); size_t len;

	hashtb_start(self->demux, hte);
	while ((len = NBS_read(self->nbs, buf, self->mtu, addr)) > 0) {
	        	
		hashkey = SockAddr_hashkey(addr);
		htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
		rec = NULL;
		if (htres == HT_OLD_ENTRY) {
			rec = *((LMDRec*)hte->data);
		} else {
			rec = self->fallback;
			if (htres == HT_NEW_ENTRY) hashtb_delete(hte);
		}
		if (rec != NULL) {
			LMDRec_deliver(rec, buf, len, addr);
			buf = malloc(self->mtu);
		}
	}
	free(buf);
	hashtb_end(hte);
	SockAddr_dtor(addr);
}

LMDRec LMDRec_ctor(SockAddr addr) {
	LMDRec self = ALLOCSELF;
	self->demuxBuf = DgramBuf_ctor();
	return self;
}

void LMDRec_dtor(LMDRec self) {
	DgramBuf_dtor(self->demuxBuf);
	free(self);
}

void LMDRec_deliver(LMDRec self, void* packet, size_t len, SockAddr srcaddr) {
	DgramBuf_append(self->demuxBuf, packet, 0, len, BufMode_use, srcaddr);
}

NdnlpPkt LMDRec_read(LMDRec self, SockAddr srcaddr) {
	void* packet; size_t len; NdnlpPkt pkt = NULL;
	SockAddr addr = srcaddr == NULL ? SockAddr_ctor() : srcaddr;
	if (DgramBuf_get(self->demuxBuf, &packet, &len, addr)) {
		DgramBuf_consumeOne(self->demuxBuf);
		pkt = NdnlpPkt_ctor(packet, len, false);
		if (pkt == NULL) free(packet);
	}
	if (srcaddr == NULL) SockAddr_dtor(addr);
	return pkt;
}

LMD LinkC_lUdp(PollMgr pm) {
	struct sockaddr_in6 addr = {0};
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htobe16(LinkC_udp_port);

	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock == -1) return NULL;
	int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	int res = bind(sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr_in6));
	if (res != 0) {
		close(sock);
		return NULL;
	}

	NBS nbs = NBS_ctor(sock, sock, SockType_Dgram);
	NBS_pollAttach(nbs, pm);

	LMD lmd = LMD_ctor(nbs, NULL, LinkC_udp_mtu);
	return lmd;
}

Link LinkC_rUdp(LMD lmd, SockAddr rAddr) {
	Link link = NULL;
	if (!LMD_registered(lmd, rAddr)) link = Link_ctorDgram(lmd, rAddr);
	return link;
}

#ifdef ENABLE_ETHER
LMD LinkC_lEth(PollMgr pm, char* ifname) {
	int mtu;

	struct sockaddr_ll addr = {0};
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htobe16(LinkC_eth_proto);
	if (!LinkC_getIfInfo(ifname, &(addr.sll_ifindex), &mtu)) return NULL;

	int sock = CapsH_createPacketSock(SOCK_DGRAM | SOCK_NONBLOCK, LinkC_eth_proto);
	if (sock == -1) return NULL;
	int res = bind(sock, (struct sockaddr*)(&addr), sizeof(struct sockaddr_ll));
	if (res != 0) {
		close(sock);
		return NULL;
	}

	NBS nbs = NBS_ctor(sock, sock, SockType_Dgram);
	NBS_pollAttach(nbs, pm);

	SockAddr lAddr = SockAddr_create(&addr, sizeof(struct sockaddr_ll));
	LMD lmd = LMD_ctor(nbs, lAddr, mtu);
	return lmd;
}

Link LinkC_rEth(LMD lmd, SockAddr rAddr) {
	((struct sockaddr_ll*)SockAddr_addr(rAddr))->sll_ifindex = ((struct sockaddr_ll*)SockAddr_addr(LMD_localAddr(lmd)))->sll_ifindex;

	Link link = NULL;
	if (!LMD_registered(lmd, rAddr)) link = Link_ctorDgram(lmd, rAddr);
	return link;
}
#elif defined(ENABLE_ETHER_BPF)
LMD LinkC_lEth(PollMgr pm, char* ifname) {
	int mtu;
	
	struct sockaddr_ll addr = {0};
	addr.sll_family = AF_INET;
	addr.sll_protocol = htobe16(LinkC_eth_proto);
	if (!LinkC_getIfInfo(ifname, &(addr.sll_ifindex), &mtu)) return NULL;

	int bpf = CapsH_createBPF(ifname);
	if (bpf == -1) return NULL;
	
	NBS nbs = NBS_ctor(bpf, bpf, SockType_BPF);

	NBS_pollAttach(nbs, pm);
	
	/* get size of BPF buffer */
	if( ioctl( bpf, BIOCGBLEN, &nbs->bpf_len ) == -1 ) {
	    perror("error getting size of bpf device\n");
 	    return NULL;	
	}

	SockAddr lAddr = SockAddr_create(&addr, sizeof(struct sockaddr_ll));
	((struct sockaddr_ll*)(SockAddr_addr(lAddr)))->sll_family = AF_PACKET;
	LMD lmd = LMD_ctor(nbs, lAddr, mtu);
	return lmd;
}
Link LinkC_rEth(LMD lmd, SockAddr rAddr) {
	((struct sockaddr_ll*)SockAddr_addr(rAddr))->sll_ifindex = ((struct sockaddr_ll*)SockAddr_addr(LMD_localAddr(lmd)))->sll_ifindex;

	Link link = NULL;
	if (!LMD_registered(lmd, rAddr)) link = Link_ctorDgram(lmd, rAddr);
	return link;
}
#else
LMD LinkC_lEth(PollMgr pm, char* ifname) { return NULL; }
Link LinkC_rEth(LMD lmd, SockAddr rAddr) { return NULL; }
#endif

SockAddr LinkC_parseIP(char* str) {
	struct sockaddr_in6 addr;
	if (1 == inet_pton(AF_INET6, str, &(addr.sin6_addr))) {
	} else if (1 == inet_pton(AF_INET, str, (struct in_addr*)(addr.sin6_addr.s6_addr + 12))) {
		memset(addr.sin6_addr.s6_addr, 0, 10);
		memset(addr.sin6_addr.s6_addr + 10, 0xFF, 2);
	} else {
		return NULL;
	}

	addr.sin6_family = AF_INET6;
	addr.sin6_port = htobe16(LinkC_udp_port);
	return SockAddr_create(&addr, sizeof(struct sockaddr_in6));
}

#ifdef ENABLE_ETHER
SockAddr LinkC_parseEther(char* str) {
	struct ether_addr* phyaddr = ether_aton(str);
	if (phyaddr == NULL) return NULL;

	struct sockaddr_ll addr;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htobe16(LinkC_eth_proto);
	addr.sll_halen = sizeof(struct ether_addr);
	memcpy(addr.sll_addr, phyaddr, sizeof(struct ether_addr));
	return SockAddr_create(&addr, sizeof(struct sockaddr_ll));
}

bool LinkC_getIfInfo(char* ifname, int* pifindex, int* pmtu) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (0 != ioctl(sock, SIOCGIFINDEX, &ifr)) { close(sock); return false; }
	*pifindex = ifr.ifr_ifindex;
	if (0 != ioctl(sock, SIOCGIFMTU, &ifr)) { close(sock); return false; }
	*pmtu = ifr.ifr_mtu;
	close(sock);
	return true;
}
#elif defined(ENABLE_ETHER_BPF)
SockAddr LinkC_parseEther(char* str) {
	struct ether_addr* phyaddr = ether_aton(str);
	if (phyaddr == NULL) return NULL;

	struct sockaddr_ll addr;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htobe16(LinkC_eth_proto);
	addr.sll_halen = sizeof(struct ether_addr);
	memcpy(addr.sll_addr, phyaddr, sizeof(struct ether_addr));
	return SockAddr_create(&addr, sizeof(struct sockaddr_ll));
}

bool LinkC_getIfInfo(char* ifname, int* pifindex, int* pmtu) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	*pifindex = if_nametoindex(ifname);
	if (0 != ioctl(sock, SIOCGIFMTU, &ifr)) { close(sock); return false; }
	*pmtu = ifr.ifr_mtu;
	close(sock);
	return true;
}
#else
SockAddr LinkC_parseEther(char* str) { return NULL; }
bool LinkC_getIfInfo(char* ifname, int* pifindex, int* pmtu) { return false; }
#endif

