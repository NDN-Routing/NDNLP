#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/uri.h>
#include <ccn/reg_mgmt.h>
#include "ndnld.h"

CcnbMsg CcnbMsg_ctor(size_t size) {
	CcnbMsg self = (CcnbMsg)ccn_charbuf_create();
	CcnbMsg_setupEncap(self, size + CCN_EMPTY_PDU_LENGTH);
	return self;
}

CcnbMsg CcnbMsg_fromEncap(struct ccn_charbuf* encap) {
	CcnbMsg self = (CcnbMsg)encap;
	CcnbMsg_setupEncap(self, encap->length);
	return self;
}

void CcnbMsg_dtor(CcnbMsg self) {
	ccn_charbuf_destroy(&self);
}

void* CcnbMsg_detachBuf(CcnbMsg self, size_t* size) {
	*size = self->length;
	void* buf = self->buf;
	self->length = self->limit = 0;
	self->buf = NULL;
	CcnbMsg_dtor(self);
	return buf;
}

void CcnbMsg_setupEncap(CcnbMsg self, size_t size) {
	ccn_charbuf_reset(self);
	ccn_charbuf_reserve(self, size);
	self->length = size;
	memcpy(self->buf, CCN_EMPTY_PDU, CCN_EMPTY_PDU_LENGTH - 1);
	self->buf[self->length - 1] = CCN_EMPTY_PDU[CCN_EMPTY_PDU_LENGTH - 1];
}

size_t CcnbMsg_getSize(CcnbMsg self) {
	return self->length - CCN_EMPTY_PDU_LENGTH;
}

void CcnbMsg_resize(CcnbMsg self, size_t size) {
	size_t oldsize = self->length + CCN_EMPTY_PDU_LENGTH;
	if (size == oldsize) return;
	CcnbMsg_setupEncap(self, size + CCN_EMPTY_PDU_LENGTH);
}

void* CcnbMsg_getBody(CcnbMsg self) {
	return CcnbMsg_getBodyPart(self, 0);
}

void* CcnbMsg_getBodyPart(CcnbMsg self, size_t start) {
	if (start < 0 || start >= CcnbMsg_getSize(self)) return NULL;
	return self->buf + (CCN_EMPTY_PDU_LENGTH - 1) + start;
}

size_t CcnbMsg_getEncapSize(CcnbMsg self) {
	return self->length;
}

void* CcnbMsg_getEncap(CcnbMsg self) {
	return self->buf;
}

void CcnbMsg_setBodyPart(CcnbMsg self, void* buf, size_t start, size_t length) {
	if (start < 0 || start + length > CcnbMsg_getSize(self)) return;
	memcpy(CcnbMsg_getBodyPart(self, start), buf, length);
}

bool CcnbMsg_verifyIntegrity(CcnbMsg self) {
	struct ccn_skeleton_decoder rdecoder;
	struct ccn_skeleton_decoder *rd = &rdecoder;
	size_t dres;
	size_t encapSize = CcnbMsg_getEncapSize(self);

	memset(rd, 0, sizeof(rdecoder));
	dres = ccn_skeleton_decode(rd, CcnbMsg_getEncap(self), encapSize);
	return CCN_FINAL_DSTATE(rd->state) && dres == encapSize;
}

struct ccn_charbuf* CcnH_localScopeTempl_inst;
struct ccn_charbuf* CcnH_localScopeTempl(void) {
	if (CcnH_localScopeTempl_inst == NULL) {
		CcnH_localScopeTempl_inst = ccn_charbuf_create();
		ccn_charbuf_append_tt(CcnH_localScopeTempl_inst, CCN_DTAG_Interest, CCN_DTAG);
		ccn_charbuf_append_tt(CcnH_localScopeTempl_inst, CCN_DTAG_Name, CCN_DTAG);
		ccn_charbuf_append_closer(CcnH_localScopeTempl_inst);
		ccnb_tagged_putf(CcnH_localScopeTempl_inst, CCN_DTAG_Scope, "1");
		ccn_charbuf_append_closer(CcnH_localScopeTempl_inst);
	}
	return CcnH_localScopeTempl_inst;
}

struct ccn_forwarding_entry* CcnH_buildForwardingEntry(CcnPrefixOp operation, CCNDID ccndid, int faceid, struct ccn_charbuf* prefix) {
	struct ccn_forwarding_entry* fe = (struct ccn_forwarding_entry*)calloc(1, sizeof(struct ccn_forwarding_entry));
	switch (operation) {
		case CcnPrefixOp_register: fe->action = "prefixreg"; break;
		case CcnPrefixOp_unregister: fe->action = "unreg"; break;
		case CcnPrefixOp_selfreg: fe->action = "selfreg"; break;
		default: free(fe); return NULL;
	}
	fe->ccnd_id = ccndid;
	fe->ccnd_id_size = CCNDID_length;
	if (operation == CcnPrefixOp_selfreg) fe->faceid = ~0;
	else fe->faceid = faceid;
	fe->name_prefix = prefix;
	fe->flags = CCN_FORW_ACTIVE | CCN_FORW_ADVERTISE;
	fe->lifetime = -1;
	return fe;
}

struct ccn_charbuf* CcnH_signForwardingEntry(struct ccn* ccnh, CCNDID ccndid, struct ccn_forwarding_entry* fe) {
	struct ccn_charbuf* request = ccn_charbuf_create();
	ccnb_append_forwarding_entry(request, fe);
	struct ccn_charbuf* emptyname = ccn_charbuf_create();
	ccn_name_init(emptyname);
	struct ccn_charbuf* signed_request = ccn_charbuf_create();
	ccn_sign_content(ccnh, signed_request, emptyname, NULL, request->buf, request->length);

	struct ccn_charbuf* reqname = ccn_charbuf_create();
	ccn_name_from_uri(reqname, "ccnx:/ccnx");
	ccn_name_append(reqname, ccndid, CCNDID_length);
	ccn_name_append_str(reqname, fe->action);
	ccn_name_append(reqname, signed_request->buf, signed_request->length);

	ccn_charbuf_destroy(&request);
	ccn_charbuf_destroy(&emptyname);
	ccn_charbuf_destroy(&signed_request);
	return reqname;
}

void CcnH_regForwardingEntry(struct ccn* ccnh, CCNDID ccndid, struct ccn_forwarding_entry* fe, void* closureData, ccn_handler closureHandler) {
	struct ccn_charbuf* reqname = CcnH_signForwardingEntry(ccnh, ccndid, fe);

	struct ccn_closure* action = NULL;
	if (closureHandler != NULL) {
		action = (struct ccn_closure*)calloc(1, sizeof(*action));
		action->data = closureData;
		action->p = closureHandler;
	}

	ccn_express_interest(ccnh, reqname, action, CcnH_localScopeTempl());
	ccn_charbuf_destroy(&reqname);
}

bool CcnH_regPrefix(CcnPrefixOp operation, struct ccn* ccnh, CCNDID ccndid, int faceid, struct ccn_charbuf* prefix) {
	struct ccn_forwarding_entry* fe = CcnH_buildForwardingEntry(operation, ccndid, faceid, prefix);
	struct ccn_charbuf* reqname = CcnH_signForwardingEntry(ccnh, ccndid, fe);
	int res = ccn_get(ccnh, reqname, CcnH_localScopeTempl(), 5000, NULL, NULL, NULL, 0);
	ccn_charbuf_destroy(&reqname);
	free(fe);
	return res == 0;
}

void CcnH_pollPrepare(struct ccn* ccnh, struct pollfd* fd) {
	fd->events = POLLIN;
	if (ccn_output_is_pending(ccnh)) fd->events |= POLLOUT;
}

void CcnH_pollRun(struct ccn* ccnh, struct pollfd* fd) {
	//if (fd->revents & (POLLIN | POLLOUT)) {
		ccn_run(ccnh, 0);
	//
}

CcnbOR CcnbOR_ctor(NBS nbs) {
	if (NBS_isDgram(nbs)) return NULL;
	CcnbOR self = ALLOCSELF;
	self->nbs = nbs;
	self->rd = (struct ccn_skeleton_decoder*)calloc(1, sizeof(struct ccn_skeleton_decoder));
	self->cbuf = ccn_charbuf_create();
	return self;
}

void CcnbOR_dtor(CcnbOR self) {
	free(self->rd);
	ccn_charbuf_destroy(&(self->cbuf));
}

bool CcnbOR_error(CcnbOR self) {
	return self->error;
}

void CcnbOR_clear(CcnbOR self) {
	memset(self->rd, 0, sizeof(struct ccn_skeleton_decoder));
	ccn_charbuf_reset(self->cbuf);
	self->error = false;
}

struct ccn_charbuf* CcnbOR_read(CcnbOR self) {
	if (NBS_error(self->nbs)) {
		self->error = true;
		return NULL;
	}
	uint8_t* buf = (uint8_t*)malloc(2048);
	size_t readSize = NBS_read(self->nbs, buf, 2048, NULL);
	if (readSize == 0) {
		free(buf);
		return NULL;
	}
	ssize_t consumeSize = ccn_skeleton_decode(self->rd, buf, readSize);
	if (self->rd->state < 0) self->error = true;
	else ccn_charbuf_append(self->cbuf, buf, consumeSize);

	if (consumeSize < readSize) NBS_pushback(self->nbs, buf, consumeSize, readSize - consumeSize, NULL);
	else free(buf);

	if (CCN_FINAL_DSTATE(self->rd->state)) {
		struct ccn_charbuf* cbuf = self->cbuf;
		self->cbuf = ccn_charbuf_create();
		CcnbOR_clear(self);
		return cbuf;
	}
	return NULL;
}

CcnCC CcnCC_ctor(void) {
	CcnCC self = ALLOCSELF;
	self->ccnh = ccn_create();
	int res = ccn_connect(self->ccnh, NULL);
	if (res == -1) {
		self->error = true;
		CcnCC_dtor(self);
		return NULL;
	}

	self->ccndid = self->ccndid_storage;	
	CcnCC_fetchCcndid(self);
	if (self->error) {
		CcnCC_dtor(self);
		return NULL;
	}

	return self;
}

void CcnCC_dtor(CcnCC self) {
	ccn_destroy(&(self->ccnh));
	free(self);
}

bool CcnCC_error(CcnCC self) {
	if (self->error) return true;
	return false;
}

struct ccn* CcnCC_ccnh(CcnCC self) {
	return self->ccnh;
}

CCNDID CcnCC_ccndid(CcnCC self) {
	return self->ccndid;
}

void CcnCC_pollAttach(CcnCC self, PollMgr pm) {
	PollMgr_attach(pm, ccn_get_connection_fd(self->ccnh), &CcnCC_pollCb, self);
}

void CcnCC_pollDetach(CcnCC self, PollMgr pm) {
	PollMgr_detach(pm, ccn_get_connection_fd(self->ccnh), &CcnCC_pollCb, self);
}

void CcnCC_setConnMgr(CcnCC self, ConnMgr cmgr) {
	self->connMgr = cmgr;
	CcnCC_registerControlPrefix(self);
}

void CcnCC_sendContent(CcnCC self, struct ccn_charbuf* name, TimeSpan expires, void* data, size_t size) {
	struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
	if (expires >= 0) {
		sp.template_ccnb = ccn_charbuf_create();
		ccn_charbuf_append_tt(sp.template_ccnb, CCN_DTAG_SignedInfo, CCN_DTAG);
		ccnb_tagged_putf(sp.template_ccnb, CCN_DTAG_FreshnessSeconds, "%ld", expires / 1000);
		sp.sp_flags |= CCN_SP_TEMPL_FRESHNESS;
		ccn_charbuf_append_closer(sp.template_ccnb);
	}
	struct ccn_charbuf* content = ccn_charbuf_create();
	if (0 == ccn_sign_content(self->ccnh, content, name, &sp, data, size)) {
		ccn_put(self->ccnh, content->buf, content->length);
	}
	ccn_charbuf_destroy(&sp.template_ccnb);
	ccn_charbuf_destroy(&content);
}

void CcnCC_fetchCcndid(CcnCC self) {
	int res;
	struct ccn_charbuf* name = ccn_charbuf_create();
	struct ccn_charbuf* resultbuf = ccn_charbuf_create();
	struct ccn_parsed_ContentObject pcobuf = {0};
	const uint8_t* ccndid_result;
	static size_t ccndid_result_size;
	ccn_name_from_uri(name, "ccnx:/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY");
	res = ccn_get(self->ccnh, name, CcnH_localScopeTempl(), 4500, resultbuf, &pcobuf, NULL, 0);
	if (res >= 0) {
		res = ccn_ref_tagged_BLOB(CCN_DTAG_PublisherPublicKeyDigest, resultbuf->buf, pcobuf.offset[CCN_PCO_B_PublisherPublicKeyDigest], pcobuf.offset[CCN_PCO_E_PublisherPublicKeyDigest], &ccndid_result, &ccndid_result_size);
	}
	if (res >= 0 && ccndid_result_size == CCNDID_length) {
		memcpy((void*)self->ccndid, ccndid_result, CCNDID_length);
	} else {
		self->error = true;
	}
	ccn_charbuf_destroy(&name);
	ccn_charbuf_destroy(&resultbuf);
}

void CcnCC_registerControlPrefix(CcnCC self) {
	if (self->regControlPrefix) return;

	struct ccn_charbuf* prefix = ccn_charbuf_create();
	ccn_name_from_uri(prefix, "ccnx:/ccnx/ndnld");
	ccn_name_append(prefix, self->ccndid, CCNDID_length);
	ccn_name_append_str(prefix, "control");

	struct ccn_closure* action = (struct ccn_closure*)calloc(1, sizeof(struct ccn_closure));
	action->data = self;
	action->p = &CcnCC_controlInterest;
	ccn_set_interest_filter(self->ccnh, prefix, action);
	ccn_charbuf_destroy(&prefix);
}

void CcnCC_pollCb(void* pself, PollMgrEvt evt, struct pollfd* fd) {
	CcnCC self = (CcnCC)pself;
	switch (evt) {
		case PollMgrEvt_prepare:
			CcnH_pollPrepare(self->ccnh, fd);
			break;
		case PollMgrEvt_result:
			CcnH_pollRun(self->ccnh, fd);
			break;
		case PollMgrEvt_error:
			printf("ndnld shutting down...\n");
			exit(1);
	}
}

enum ccn_upcall_res CcnCC_controlInterest(struct ccn_closure* selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info* info) {
	CcnCC self = selfp->data;
	switch (kind) {
		case CCN_UPCALL_FINAL:
			free(selfp);
			break;
		case CCN_UPCALL_INTEREST:
			if (CcnCC_controlInterest1(self, info)) return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
			break;
		default: break;
	}
	return CCN_UPCALL_RESULT_OK;
}

bool CcnCC_controlInterest1(CcnCC self, struct ccn_upcall_info* info) {
	if (info->pi->prefix_comps < 5) return false;
	char* compVerb; size_t compVerb_size;
	if (0 == ccn_name_comp_get(info->interest_ccnb, info->interest_comps, 4, (const uint8_t**)&compVerb, &compVerb_size)) {
		if (0 == strncmp(compVerb, CMPConn_Verb_connect_str, compVerb_size) || 0 == strncmp(compVerb, CMPConn_Verb_disconnect_str, compVerb_size) || 0 == strncmp(compVerb, CMPConn_Verb_listconnections_str, compVerb_size)) {
			CMPConn cmpRequest = CMPConn_fromInterest(info->interest_ccnb, info->pi, info->interest_comps);
			if (cmpRequest != NULL && self->connMgr != NULL) {
				ConnMgr_cmpRequest(self->connMgr, cmpRequest);
			}
			return true;
		}
	}
	return false;
}

CcnLAC CcnLAC_ctor() {
	CcnLAC self = ALLOCSELF;
	self->ccnh = ccn_create();
	self->faceid = CcnLAC_faceid_unknown;
	return self;
}

void CcnLAC_dtor(CcnLAC self) {
	if (self->pm != NULL) PollMgr_detach(self->pm, ccn_get_connection_fd(self->ccnh), &CcnLAC_initPollCb, self);
	if (self->nbs != NULL) NBS_pollDetach(self->nbs);
	ccn_destroy(&(self->ccnh));
	if (self->ccnbor != NULL) CcnbOR_dtor(self->ccnbor);
	free(self);
}

bool CcnLAC_error(CcnLAC self) {
	if (self->error) return true;
	if (self->nbs != NULL && NBS_error(self->nbs)) return true;
	return false;
}

bool CcnLAC_ready(CcnLAC self) {
	return self->faceid != CcnLAC_faceid_unknown;
}

void CcnLAC_initialize(CcnLAC self, CCNDID ccndid, PollMgr pm) {
	int res = ccn_connect(self->ccnh, NULL);
	if (res == -1) {
		self->error = true;
		return;
	}
	self->nbs = NBS_ctor(res, res, SockType_Stream);
	self->ccnbor = CcnbOR_ctor(self->nbs);
	self->pm = pm;
	PollMgr_attach(pm, res, &CcnLAC_initPollCb, self);
	CcnLAC_fetchFaceid(self, ccndid);
}

int CcnLAC_faceid(CcnLAC self) {
	return self->faceid;
}

CcnbMsg CcnLAC_read(CcnLAC self) {
	if (!CcnLAC_ready(self)) return NULL;
	struct ccn_charbuf* cbuf = CcnbOR_read(self->ccnbor);
	if (cbuf == NULL) return NULL;
	CcnbMsg msg = CcnbMsg_fromEncap(cbuf);
	if (CcnbMsg_verifyIntegrity(msg)) return msg;
	else {
		self->error = true;
		return NULL;
	}
}

void CcnLAC_write(CcnLAC self, CcnbMsg msg) {
	if (!CcnbMsg_verifyIntegrity(msg)) {
		CcnbMsg_dtor(msg);
		return;
	}
	size_t size;
	void* buf = CcnbMsg_detachBuf(msg, &size);
	NBS_write(self->nbs, buf, 0, size, NULL);
}

void CcnLAC_initPollCb(void* pself, PollMgrEvt evt, struct pollfd* fd) {
	CcnLAC self = (CcnLAC)pself;
	switch (evt) {
		case PollMgrEvt_prepare:
			CcnH_pollPrepare(self->ccnh, fd);
			break;
		case PollMgrEvt_result:
			printf("CcnH_pollRun (2)\n");
			CcnH_pollRun(self->ccnh, fd);
			break;
		case PollMgrEvt_error:
			printf("PollMgrEvt_error (2)\n");
			self->error = true;
			PollMgr_detach(self->pm, ccn_get_connection_fd(self->ccnh), &CcnLAC_initPollCb, self);
			break;
		default:
			printf("UNKNOWN (2)\n");
			exit(1);
	}
}

void CcnLAC_fetchFaceid(CcnLAC self, CCNDID ccndid) {
	struct ccn_charbuf* prefix = ccn_charbuf_create();
	ccn_name_from_uri(prefix, "ccnx:/ccnx/ndnld");
	ccn_name_append(prefix, ccndid, CCNDID_length);
	ccn_name_append_str(prefix, "discover-faceid");

	struct ccn_forwarding_entry* fe = CcnH_buildForwardingEntry(CcnPrefixOp_selfreg, ccndid, 0, prefix);
	fe->flags = CCN_FORW_LAST | CCN_FORW_LOCAL;
	fe->lifetime = 1;

	CcnH_regForwardingEntry(self->ccnh, ccndid, fe, self, &CcnLAC_fetchFaceidCb);
	ccn_charbuf_destroy(&prefix);
	free(fe);
}

enum ccn_upcall_res CcnLAC_fetchFaceidCb(struct ccn_closure* selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info* info) {
	CcnLAC self = (CcnLAC)selfp->data;
	switch (kind) {
		case CCN_UPCALL_FINAL: {
			free(selfp);
			return CCN_UPCALL_RESULT_OK;
		}
		case CCN_UPCALL_INTEREST_TIMED_OUT: {
			return CCN_UPCALL_RESULT_REEXPRESS;
		}
		case CCN_UPCALL_CONTENT_UNVERIFIED:
		case CCN_UPCALL_CONTENT_KEYMISSING:
		case CCN_UPCALL_CONTENT_RAW:
		case CCN_UPCALL_CONTENT: {
			struct ccn_forwarding_entry* fe = NULL;
			const unsigned char* fe_ccnb = NULL;
			size_t fe_ccnb_size = 0;
			int res = ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &fe_ccnb, &fe_ccnb_size);
			if (res == 0) fe = ccn_forwarding_entry_parse(fe_ccnb, fe_ccnb_size);
			if (fe != NULL) {
				self->faceid = fe->faceid;
				ccn_forwarding_entry_destroy(&fe);
			} else {
				self->error = true;
			}
			PollMgr_detach(self->pm, ccn_get_connection_fd(self->ccnh), &CcnLAC_initPollCb, self);
			void* emptyPDU = malloc(CCN_EMPTY_PDU_LENGTH);
			memcpy(emptyPDU, CCN_EMPTY_PDU, CCN_EMPTY_PDU_LENGTH);
			NBS_write(self->nbs, emptyPDU, 0, CCN_EMPTY_PDU_LENGTH, NULL);
			NBS_pollAttach(self->nbs, self->pm);
			return CCN_UPCALL_RESULT_OK;
		}
		default: {
			return CCN_UPCALL_RESULT_ERR;
		}
	}
}


