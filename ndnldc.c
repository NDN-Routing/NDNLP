#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include "ndnld.h"

void usage(void) {
	printf(
	"ndnldc -c -p udp -h 192.0.2.1\nndnldc -c -p udp -h 2001:DB8::1\n\tcreate UDP connection\n"
	"ndnldc -c -p ether -h 08:00:27:01:01:01 -i eth1\n\tcreate Ethernet connection\n"
	"ndnldc -c ... -a -S 100 -C 5 -R 1000 -A 300\n\tRLA SentPktsCapacity RetryCount RetransmitTime AcknowledgeTime\n"
	"ndnldc -d -f 11\n\tdestroy connection\n"
	"ndnldc -l\n\tlist connections\n"
	"ndnldc -r -f 11 -n ccnx:/example\n\tregister prefix\n"
	"ndnldc -u -f 11 -n ccnx:/example\n\tunregister prefix\n"
	);
}

CcnCC cc;
struct ccn* h;

int processCMPlist(const uint8_t* resultval, size_t resultlen) {
	struct ccn_buf_decoder decoder;
	struct ccn_buf_decoder* d = ccn_buf_decoder_start(&decoder, resultval, resultlen);

	if (ccn_buf_match_dtag(d, CCN_DTAG_Collection)) {
		ccn_buf_advance(d);
		while (ccn_buf_match_dtag(d, DTAG_NdnldConnection)) {
			CMPConn item = CMPConn_readContentObject(d);
			if (item == NULL) {
				fprintf(stderr, "CMPConn_readContentObject fails.\n");
				return 1;
			}
			printf("%s\n", CMPConn_toString(item));
		}
		return 0;
	} else {
		fprintf(stderr, "Response root is not Collection element.\n");
		return 1;
	}
}

int requestCMP(CMPConn request) {
	struct ccn_charbuf* name = CMPConn_toInterestName(request, cc);
	if (name == NULL) {
		fprintf(stderr, "CMPConn_toInterestName fails.");
	}

	struct ccn_charbuf* resultbuf = ccn_charbuf_create();
	struct ccn_parsed_ContentObject pcobuf = {0};
	int res;
	if (0 != (res = ccn_get(h, name, CcnH_localScopeTempl(), 5000, resultbuf, &pcobuf, NULL, 0))) {
		fprintf(stderr, "ccn_get fails with code %d.", res);
		return 1;
	}
	const uint8_t* resultval; size_t resultlen;
	if (0 != (res = ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &resultval, &resultlen))) {
		fprintf(stderr, "ccn_content_get_value fails with code %d.", res);
		return 1;
	}

	if (request->Verb == CMPConn_Verb_listconnections) {
		return processCMPlist(resultval, resultlen);
	}
	CMPConn response = CMPConn_fromContentObject(resultval, resultlen);
	if (response == NULL) {
		fprintf(stderr, "CMPConn_fromContentObject fails.");
		return 1;
	}
	if (request->Verb == CMPConn_Verb_connect) {
		printf("%d\n", response->FaceID);
	}
	return 0;
}

int regPrefix(CcnPrefixOp operation, int faceid, char* prefix) {
	struct ccn_charbuf* name = ccn_charbuf_create();
	ccn_name_from_uri(name, prefix);
	bool res = CcnH_regPrefix(operation, h, CcnCC_ccndid(cc), faceid, name);
	ccn_charbuf_destroy(&name);
	if (!res) {
		fprintf(stderr, "CcnH_regPrefix fails.\n");
		return 1;
	}
	return 0;
}

int main(int argc, char* argv[]) {
	cc = CcnCC_ctor();
	h = CcnCC_ccnh(cc);

	CMPConn cmpReq = CMPConn_ctor();
	CcnPrefixOp prefixOp = 0;
	char* prefix;

	int opt;
	while ((opt = getopt(argc, argv, "cp:h:i:aS:C:R:A:df:lrn:u")) >= 0) {
		switch (opt) {
			case 'c': {
				cmpReq->Verb = CMPConn_Verb_connect;
			} break;
			case 'p': {
				if (0 == strcmp(optarg, CMPConn_LowerProto_ether_str)) {
					cmpReq->LowerProto = CMPConn_LowerProto_ether;
				} else if (0 == strcmp(optarg, CMPConn_LowerProto_udp_str)) {
					cmpReq->LowerProto = CMPConn_LowerProto_udp;
				}
			} break;
			case 'h': {
				cmpReq->Host = optarg;
			} break;
			case 'i': {
				cmpReq->LocalIf = optarg;
			} break;
			case 'a': {
				cmpReq->Flags |= CMPConn_Flags_RLA;
			} break;
			case 'S': {
				cmpReq->SentPktsCapacity = atoi(optarg);
			} break;
			case 'C': {
				cmpReq->RetryCount = atoi(optarg);
			} break;
			case 'R': {
				cmpReq->RetransmitTime = atoi(optarg);
			} break;
			case 'A': {
				cmpReq->AcknowledgeTime = atoi(optarg);
			} break;
			case 'd': {
				cmpReq->Verb = CMPConn_Verb_disconnect;
			} break;
			case 'f': {
				cmpReq->FaceID = atoi(optarg);
			} break;
			case 'l': {
				cmpReq->Verb = CMPConn_Verb_listconnections;
			} break;
			case 'r': {
				prefixOp = CcnPrefixOp_register;
			} break;
			case 'n': {
				prefix = optarg;
			} break;
			case 'u': {
				prefixOp = CcnPrefixOp_unregister;
			} break;
			default: break;
		}
	}

	if ((cmpReq->Verb == CMPConn_Verb_connect
		&& ((cmpReq->LowerProto == CMPConn_LowerProto_ether && cmpReq->LocalIf != NULL) || cmpReq->LowerProto == CMPConn_LowerProto_udp)
		&& cmpReq->Host != NULL)
		|| (cmpReq->Verb == CMPConn_Verb_disconnect && cmpReq->FaceID >= 0)
		|| cmpReq->Verb == CMPConn_Verb_listconnections) {
		return requestCMP(cmpReq);
	} else if (prefixOp != 0 && cmpReq->FaceID >= 0 && prefix != NULL) {
		return regPrefix(prefixOp, cmpReq->FaceID, prefix);
	}

	usage();
	return 1;
}

