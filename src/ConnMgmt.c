#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/hashtb.h>
#include <ccn/uri.h>
#include "ndnld.h"


CMPConn CMPConn_ctor(void) {
	CMPConn self = ALLOCSELF;
	self->SentPktsCapacity = CMPConn_SentPktsCapacity_default;
	self->RetryCount = CMPConn_RetryCount_default;
	self->RetransmitTime = CMPConn_RetransmitTime_default;
	self->AcknowledgeTime = CMPConn_AcknowledgeTime_default;
	self->InterestName = ccn_charbuf_create();
	return self;
}

void CMPConn_dtor(CMPConn self) {
	if (self->Host != NULL) free(self->Host);
	if (self->LocalIf != NULL) free(self->LocalIf);
	ccn_charbuf_destroy(&(self->InterestName));
	free(self);
}

char* CMPConn_toString(CMPConn self) {
	char* lowerProto = ""; char localIf[16];
	if (self->LowerProto == CMPConn_LowerProto_ether) {
		lowerProto = CMPConn_LowerProto_ether_str;
		snprintf(localIf, 16, " on %s", self->LocalIf);
	} else if (self->LowerProto == CMPConn_LowerProto_udp) {
		lowerProto = CMPConn_LowerProto_udp_str;
		localIf[0] = '\0';
	}
	char* flagRLA = "";
	if (self->Flags & CMPConn_Flags_RLA) {
		flagRLA = " RLA";
	}
	char* stateError = "";
	if (self->State == CMPConn_State_error) {
		stateError = " ERROR";
	}

	static char buffer[256];
	snprintf(buffer, 256, "face=%d %s %s%s%s%s", self->FaceID, lowerProto, self->Host, localIf, flagRLA, stateError);
	return buffer;
}

struct ccn_charbuf* CMPConn_toContentObject(CMPConn self) {
	struct ccn_charbuf* c = ccn_charbuf_create();
	if (CMPConn_appendContentObject(self, c)) return c;
	ccn_charbuf_destroy(&c);
	return NULL;
}

bool CMPConn_appendContentObject(CMPConn self, struct ccn_charbuf* c) {
	int res = ccnb_element_begin(c, DTAG_NdnldConnection);
	if (self->Verb == CMPConn_Verb_connect) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_Action, "%s", CMPConn_Verb_connect_str);
	} else if (self->Verb == CMPConn_Verb_disconnect) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_Action, "%s", CMPConn_Verb_disconnect_str);
	} else if (self->Verb == CMPConn_Verb_listconnections) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_Action, "%s", CMPConn_Verb_listconnections_str);
	}
	res |= ccnb_tagged_putf(c, CCN_DTAG_FaceID, "%d", self->FaceID);
	if (self->LowerProto == CMPConn_LowerProto_ether) {
		res |= ccnb_tagged_putf(c, DTAG_NdnldLowerProtocol, "%s", CMPConn_LowerProto_ether_str);
	} else if (self->LowerProto == CMPConn_LowerProto_udp) {
		res |= ccnb_tagged_putf(c, DTAG_NdnldLowerProtocol, "%s", CMPConn_LowerProto_udp_str);
	}
	if (self->Host != NULL) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_Host, "%s", self->Host);
	}
	if (self->LocalIf != NULL) {
		res |= ccnb_tagged_putf(c, DTAG_NdnldLocalInterface, "%s", self->LocalIf);
	}
	uint16_t blobFlags = htobe16(self->Flags);
	res |= ccnb_append_tagged_blob(c, CCN_DTAG_ForwardingFlags, &blobFlags, sizeof(blobFlags));
	res |= ccnb_tagged_putf(c, DTAG_NdnldSentPktsCapacity, "%d", self->SentPktsCapacity);
	res |= ccnb_tagged_putf(c, DTAG_NdnldRetransmitCount, "%d", self->RetryCount);
	res |= ccnb_tagged_putf(c, DTAG_NdnldRetransmitTime, "%d", self->RetransmitTime);
	res |= ccnb_tagged_putf(c, DTAG_NdnldAcknowledgeTime, "%d", self->AcknowledgeTime);
	if (self->State == CMPConn_State_normal) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_StatusCode, "%s", CMPConn_State_normal_str);
	} else if (self->State == CMPConn_State_error) {
		res |= ccnb_tagged_putf(c, CCN_DTAG_StatusCode, "%s", CMPConn_State_error_str);
	}
	res |= ccnb_element_end(c);
	return res == 0;
}

CMPConn CMPConn_fromContentObject(const uint8_t* contentObject, size_t size) {
	struct ccn_buf_decoder decoder;
	struct ccn_buf_decoder* d = ccn_buf_decoder_start(&decoder, contentObject, size);
	CMPConn self = CMPConn_readContentObject(d);
	if (self != NULL && (!CCN_FINAL_DSTATE(d->decoder.state) || d->decoder.index != size)) {
		CMPConn_dtor(self);
		return NULL;
	}
	return self;
}

CMPConn CMPConn_readContentObject(struct ccn_buf_decoder* d) {
	struct ccn_charbuf* store = ccn_charbuf_create();
	CMPConn self = CMPConn_ctor();
	int verb_off = -1;
	int lowerproto_off = -1;
	int host_off = -1;
	int localif_off = -1;
	int state_off = -1;

	if (ccn_buf_match_dtag(d, DTAG_NdnldConnection)) {
		ccn_buf_advance(d);
		verb_off = ccn_parse_tagged_string(d, CCN_DTAG_Action, store);
		self->FaceID = ccn_parse_optional_tagged_nonNegativeInteger(d, CCN_DTAG_FaceID);
		lowerproto_off = ccn_parse_tagged_string(d, DTAG_NdnldLowerProtocol, store);
		host_off = ccn_parse_tagged_string(d, CCN_DTAG_Host, store);
		localif_off = ccn_parse_tagged_string(d, DTAG_NdnldLocalInterface, store);
		self->Flags = (uint16_t)ccn_parse_optional_tagged_binary_number(d, CCN_DTAG_ForwardingFlags, 2, 2, 0);
		self->SentPktsCapacity = ccn_parse_optional_tagged_nonNegativeInteger(d, DTAG_NdnldSentPktsCapacity);
		self->RetryCount = ccn_parse_optional_tagged_nonNegativeInteger(d, DTAG_NdnldRetransmitCount);
		self->RetransmitTime = ccn_parse_optional_tagged_nonNegativeInteger(d, DTAG_NdnldRetransmitTime);
		self->AcknowledgeTime = ccn_parse_optional_tagged_nonNegativeInteger(d, DTAG_NdnldAcknowledgeTime);
		state_off = ccn_parse_tagged_string(d, CCN_DTAG_StatusCode, store);
		ccn_buf_check_close(d);
	} else {
		d->decoder.state = -1;
	}

	bool error = false;
	if (verb_off < 0) {
		error = true;
	} else if (0 == strcmp((char*)(store->buf + verb_off), CMPConn_Verb_connect_str)) {
		self->Verb = CMPConn_Verb_connect;
	} else if (0 == strcmp((char*)(store->buf + verb_off), CMPConn_Verb_disconnect_str)) {
		self->Verb = CMPConn_Verb_disconnect;
	} else if (0 == strcmp((char*)(store->buf + verb_off), CMPConn_Verb_listconnections_str)) {
		self->Verb = CMPConn_Verb_listconnections;
	} else {
		error = true;
	}
	if (lowerproto_off >= 0) {
		if (0 == strcmp((char*)(store->buf + lowerproto_off), CMPConn_LowerProto_ether_str)) {
			self->LowerProto = CMPConn_LowerProto_ether;
		} else if (0 == strcmp((char*)(store->buf + lowerproto_off), CMPConn_LowerProto_udp_str)) {
			self->LowerProto = CMPConn_LowerProto_udp;
		}
	}
	if (host_off >= 0) {
		self->Host = String_clone((char*)(store->buf + host_off));
	}
	if (localif_off >= 0) {
		self->LocalIf = String_clone((char*)(store->buf + localif_off));
	}
	if (self->SentPktsCapacity < 0) self->SentPktsCapacity = CMPConn_SentPktsCapacity_default;
	if (self->RetryCount < 0) self->RetryCount = CMPConn_RetryCount_default;
	if (self->RetransmitTime < 0) self->RetransmitTime = CMPConn_RetransmitTime_default;
	if (self->AcknowledgeTime < 0) self->AcknowledgeTime = CMPConn_AcknowledgeTime_default;
	if (state_off >= 0) {
		if (0 == strcmp((char*)(store->buf + state_off), CMPConn_State_normal_str)) {
			self->State = CMPConn_State_normal;
		} else if (0 == strcmp((char*)(store->buf + state_off), CMPConn_State_error_str)) {
			self->State = CMPConn_State_error;
		}
	}

	ccn_charbuf_destroy(&store);
	if (error) {
		CMPConn_dtor(self);
		return NULL;
	}
	return self;
}

struct ccn_charbuf* CMPConn_toInterestName(CMPConn self, CcnCC cc) {
	struct ccn_charbuf* request = CMPConn_toContentObject(self);
	struct ccn_charbuf* emptyname = ccn_charbuf_create();
	ccn_name_init(emptyname);
	struct ccn_charbuf* signed_request = ccn_charbuf_create();
	ccn_sign_content(CcnCC_ccnh(cc), signed_request, emptyname, NULL, request->buf, request->length);

	bool error = false;
	struct ccn_charbuf* reqname = ccn_charbuf_create();
	ccn_name_from_uri(reqname, "ccnx:/ccnx/ndnld");
	ccn_name_append(reqname, CcnCC_ccndid(cc), CCNDID_length);
	ccn_name_append_str(reqname, "control");
	if (self->Verb == CMPConn_Verb_connect) {
		ccn_name_append_str(reqname, CMPConn_Verb_connect_str);
	} else if (self->Verb == CMPConn_Verb_disconnect) {
		ccn_name_append_str(reqname, CMPConn_Verb_disconnect_str);
	} else if (self->Verb == CMPConn_Verb_listconnections) {
		ccn_name_append_str(reqname, CMPConn_Verb_listconnections_str);
	} else {
		error = true;
	}
	ccn_name_append(reqname, signed_request->buf, signed_request->length);

	ccn_charbuf_destroy(&request);
	ccn_charbuf_destroy(&emptyname);
	ccn_charbuf_destroy(&signed_request);
	if (error) {
		ccn_charbuf_destroy(&reqname);
		return NULL;
	}
	return reqname;
}

CMPConn CMPConn_fromInterest(const uint8_t* interest_ccnb, struct ccn_parsed_interest* pi, struct ccn_indexbuf* interest_comps) {
	if (pi->prefix_comps != 6) return NULL;
	char* compVerb; size_t compVerb_size;
	uint8_t* compNfblob; size_t compNfblob_size;
	int res = ccn_name_comp_get(interest_ccnb, interest_comps, 4, (const uint8_t**)&compVerb, &compVerb_size);
	res |= ccn_name_comp_get(interest_ccnb, interest_comps, 5, (const uint8_t**)&compNfblob, &compNfblob_size);
	if (res != 0) return NULL;

	struct ccn_parsed_ContentObject pco = {0};
	res = ccn_parse_ContentObject(compNfblob, compNfblob_size, &pco, NULL);
	if (res != 0) return NULL;
	uint8_t* request; size_t request_size;
	res = ccn_content_get_value(compNfblob, compNfblob_size, &pco, (const uint8_t**)&request, &request_size);
	if (res != 0) return NULL;

	CMPConn self = CMPConn_fromContentObject(request, request_size);
	if (self == NULL) return NULL;

	bool error = false;
	if (self->Verb == CMPConn_Verb_connect) {
		size_t verblen = strlen(CMPConn_Verb_connect_str);
		if (compVerb_size != verblen || 0 != memcmp(CMPConn_Verb_connect_str, compVerb, verblen)) error = true;
		if (self->LowerProto != CMPConn_LowerProto_ether && self->LowerProto != CMPConn_LowerProto_udp) error = true;
		if (self->Host == NULL) error = true;
		if (self->LowerProto == CMPConn_LowerProto_ether && self->LocalIf == NULL) error = true;
	} else if (self->Verb == CMPConn_Verb_disconnect) {
		size_t verblen = strlen(CMPConn_Verb_disconnect_str);
		if (compVerb_size != verblen || 0 != memcmp(CMPConn_Verb_disconnect_str, compVerb, verblen)) error = true;
		if (self->FaceID < 0) error = true;
	} else if (self->Verb == CMPConn_Verb_listconnections) {
		size_t verblen = strlen(CMPConn_Verb_listconnections_str);
		if (compVerb_size != verblen || 0 != memcmp(CMPConn_Verb_listconnections_str, compVerb, verblen)) error = true;
	} else {
		error = true;
	}
	if (error) {
		CMPConn_dtor(self);
		return NULL;
	}

	ccn_charbuf_append(self->InterestName, interest_ccnb + pi->offset[CCN_PI_B_Name], pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);
	return self;
}

ConnMgr ConnMgr_ctor(PollMgr pm, CcnCC cc) {
	ConnMgr self = ALLOCSELF;
	self->pm = pm;
	self->cc = cc;
	self->htLMD = hashtb_create(sizeof(LMD), NULL);
	self->htAddrRec = hashtb_create(sizeof(ConnMgrRec), NULL);
	self->htFaceRec = hashtb_create(sizeof(ConnMgrRec), NULL);
	CcnCC_setConnMgr(cc, self);
	return self;
}

void ConnMgr_dtor(ConnMgr self) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	hashtb_start(self->htFaceRec, hte);
	for (ConnMgrRec* prec = (ConnMgrRec*)hte->data; prec != NULL; prec = (ConnMgrRec*)hte->data) {
		ConnMgrRec rec = *prec;
		ConnMgrRec_dtor(rec);
		hashtb_next(hte);
	}
	hashtb_end(hte);
	hashtb_start(self->htLMD, hte);
	for (LMD* plmd = (LMD*)hte->data; plmd != NULL; plmd = (LMD*)hte->data) {
		LMD lmd = *plmd;
		LMD_dtor(lmd);
		hashtb_next(hte);
	}
	hashtb_end(hte);

	hashtb_destroy(&(self->htLMD));
	hashtb_destroy(&(self->htAddrRec));
	hashtb_destroy(&(self->htFaceRec));
	free(self);
}

void ConnMgr_cmpRequest(ConnMgr self, CMPConn request) {
	if (request->Verb == CMPConn_Verb_connect) {
		ConnMgr_cmpConnect(self, request);
	} else if (request->Verb == CMPConn_Verb_disconnect) {
		ConnMgr_cmpDisconnect(self, request);
	} else if (request->Verb == CMPConn_Verb_listconnections) {
		ConnMgr_cmpList(self, request);
	} else {
		CMPConn_dtor(request);
	}
}

void ConnMgr_run(ConnMgr self) {
	ConnMgr_checkInitReady(self);
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	hashtb_start(self->htFaceRec, hte);
	for (ConnMgrRec* prec = (ConnMgrRec*)hte->data; prec != NULL; prec = (ConnMgrRec*)hte->data) {
		ConnMgrRec rec = *prec;
		NdnlpSvc_run(rec->svc);
		if (NdnlpSvc_error(rec->svc)) {
			rec->state = ConnMgrRecState_error;
			rec->cmpConn->State = CMPConn_State_error;
		}
		hashtb_next(hte);
	}
	hashtb_end(hte);
}

void ConnMgr_cmpConnect(ConnMgr self, CMPConn request) {
	LMD lmd = ConnMgr_prepareLMD(self, request);//create or get LMD
	if (lmd == NULL) {
		CMPConn_dtor(request);
		return;
	}

	SockAddr rAddr = NULL;//parse address
	if (request->LowerProto == CMPConn_LowerProto_ether) {
		rAddr = LinkC_parseEther(request->Host);
	} else if (request->LowerProto == CMPConn_LowerProto_udp) {
		rAddr = LinkC_parseIP(request->Host);
	}
	if (rAddr == NULL) {
		CMPConn_dtor(request);
		return;
	}
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; ConnMgrRec rec; struct ccn_charbuf* hashkey = SockAddr_hashkey(rAddr);
	hashtb_start(self->htAddrRec, hte);
	htres = hashtb_seek(hte, hashkey->buf, hashkey->length, 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((ConnMgrRec*)hte->data);
		if (rec->state == ConnMgrRecState_normal) {
			rec->cmpConn->Verb = CMPConn_Verb_connect;
			struct ccn_charbuf* response = CMPConn_toContentObject(rec->cmpConn);
			CcnCC_sendContent(self->cc, request->InterestName, 5000, response->buf, response->length);
			ccn_charbuf_destroy(&response);
		}
		CMPConn_dtor(request);
		hashtb_end(hte);
		SockAddr_dtor(rAddr);
		return;
	}

	Link link = NULL;//create link
	if (request->LowerProto == CMPConn_LowerProto_ether) {
		link = LinkC_rEth(lmd, rAddr);
	} else if (request->LowerProto == CMPConn_LowerProto_udp) {
		link = LinkC_rUdp(lmd, rAddr);
	}
	if (link == NULL) {
		CMPConn_dtor(request);
		hashtb_delete(hte);
		hashtb_end(hte);
		SockAddr_dtor(rAddr);
		return;
	}
	rec = ConnMgrRec_ctor();//create record
	rec->cmpConn = request;
	rec->link = link;
	rec->lac = CcnLAC_ctor();
	CcnLAC_initialize(rec->lac, CcnCC_ccndid(self->cc), self->pm);
	rec->state = ConnMgrRecState_init;
	rec->next = self->pendingInit;//prepend to pendingInit list
	self->pendingInit = rec;
	*((ConnMgrRec*)hte->data) = rec;//add to htAddrRec

	hashtb_end(hte);
	SockAddr_dtor(rAddr);
}

void ConnMgr_cmpDisconnect(ConnMgr self, CMPConn request) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; ConnMgrRec rec;
	hashtb_start(self->htFaceRec, hte);
	htres = hashtb_seek(hte, &request->FaceID, sizeof(request->FaceID), 0);
	if (htres == HT_OLD_ENTRY) {
		rec = *((ConnMgrRec*)hte->data);
		rec->cmpConn->Verb = CMPConn_Verb_disconnect;//send response
		struct ccn_charbuf* response = CMPConn_toContentObject(rec->cmpConn);
		CcnCC_sendContent(self->cc, request->InterestName, 5000, response->buf, response->length);
		ccn_charbuf_destroy(&response);
		struct hashtb_enumerator htee2; struct hashtb_enumerator* hte2 = &htee2;
		hashtb_start(self->htAddrRec, hte2);
		for (ConnMgrRec* prec = (ConnMgrRec*)hte->data; prec != NULL; prec = (ConnMgrRec*)hte->data) {
			if (*prec == rec) {
				hashtb_delete(hte2);
				break;
			}
		}
		hashtb_end(hte2);
		ConnMgrRec_dtor(rec);
	}
	hashtb_delete(hte);
	hashtb_end(hte);
}

void ConnMgr_cmpList(ConnMgr self, CMPConn request) {
	struct ccn_charbuf* c = ccn_charbuf_create();
	int res = 0; bool res2 = true;
	res |= ccnb_element_begin(c, CCN_DTAG_Collection);

	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	hashtb_start(self->htFaceRec, hte);
	for (ConnMgrRec* prec = (ConnMgrRec*)hte->data; prec != NULL; prec = (ConnMgrRec*)hte->data) {
		ConnMgrRec rec = *prec;
		rec->cmpConn->Verb = CMPConn_Verb_listconnections;
		res2 = res2 && CMPConn_appendContentObject(rec->cmpConn, c);
		hashtb_next(hte);
	}
	hashtb_end(hte);

	res |= ccnb_element_end(c);
	if (res == 0 && res2) {
		CcnCC_sendContent(self->cc, request->InterestName, 5000, c->buf, c->length);
	}
	ccn_charbuf_destroy(&c);
	CMPConn_dtor(request);
}

LMD ConnMgr_prepareLMD(ConnMgr self, CMPConn request) {
	struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
	int htres; LMD lmd;
	
	char* htkey;
	if (request->LowerProto == CMPConn_LowerProto_ether) {
		htkey = request->LocalIf;
	} else if (request->LowerProto == CMPConn_LowerProto_udp) {
		htkey = CMPConn_LowerProto_udp_str;
	}
	hashtb_start(self->htLMD, hte);
	htres = hashtb_seek(hte, htkey, strlen(htkey), 0);
	if (htres == HT_OLD_ENTRY) {
		lmd = *((LMD*)hte->data);
	} else if (htres == HT_NEW_ENTRY) {
		if (request->LowerProto == CMPConn_LowerProto_ether) {
			lmd = LinkC_lEth(self->pm, request->LocalIf);
		} else if (request->LowerProto == CMPConn_LowerProto_udp) {
			lmd = LinkC_lUdp(self->pm);
		}
		if (lmd != NULL) {
			*((LMD*)hte->data) = lmd;
		} else {
			hashtb_delete(hte);
		}
	}
	hashtb_end(hte);
	return lmd;
}

void ConnMgr_checkInitReady(ConnMgr self) {
	ConnMgrRec rec = self->pendingInit; ConnMgrRec prev = NULL;
	while (rec != NULL) {
		if (CcnLAC_ready(rec->lac)) {
			int faceid = rec->cmpConn->FaceID = CcnLAC_faceid(rec->lac);
			rec->cmpConn->Verb = CMPConn_Verb_connect;
			rec->cmpConn->State = CMPConn_State_normal;
			struct ccn_charbuf* response = CMPConn_toContentObject(rec->cmpConn);//send response
			CcnCC_sendContent(self->cc, rec->cmpConn->InterestName, 5000, response->buf, response->length);
			ccn_charbuf_destroy(&response);
			rec->svc = NdnlpSvc_ctor(rec->lac, rec->link, rec->cmpConn->Flags & CMPConn_Flags_RLA, rec->cmpConn->SentPktsCapacity, rec->cmpConn->RetryCount, rec->cmpConn->RetransmitTime, rec->cmpConn->AcknowledgeTime);//start serving
			struct hashtb_enumerator htee; struct hashtb_enumerator* hte = &htee;
			hashtb_start(self->htFaceRec, hte);//add to htFaceRec
			hashtb_seek(hte, &faceid, sizeof(faceid), 0);
			*((ConnMgrRec*)hte->data) = rec;
			hashtb_end(hte);
			if (prev == NULL) self->pendingInit = rec->next;//detach from pendingInit
			else prev->next = rec->next;
			rec->next = NULL;
			rec->state = ConnMgrRecState_normal;
		} else {
			prev = rec;
		}
		if (prev == NULL) rec = NULL;
		else rec = prev->next;
	}
}

ConnMgrRec ConnMgrRec_ctor(void) {
	ConnMgrRec self = ALLOCSELF;
	return self;
}

void ConnMgrRec_dtor(ConnMgrRec self) {
	if (self->svc != NULL) NdnlpSvc_dtor(self->svc);
	if (self->lac != NULL) CcnLAC_dtor(self->lac);
	if (self->link != NULL) Link_dtor(self->link);
	if (self->cmpConn != NULL) CMPConn_dtor(self->cmpConn);
	free(self);
}

