#ifndef NDNLD_H
#define NDNLD_H

#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef __linux__
	#include <endian.h>
#elif __FreeBSD__
	#include <sys/endian.h>
	#define ENABLE_ETHER_BPF
	#define AF_PACKET  0xab /* workaround for SockAddr_haskey */
               // not defined in BSD, but we need it to retrieve dest MAC addr of outgoing packets
        #include <net/bpf.h>
        #include <net/if_dl.h>

struct __attribute__((__packed__)) sockaddr_ll {
	unsigned char  padding;      /* so this struct will line up with BDS's sockaddr struct */
	unsigned short sll_family;   /* Always AF_PACKET */
	unsigned short sll_protocol; /* Physical layer protocol */
	int            sll_ifindex;  /* Interface number */
	unsigned short sll_hatype;   /* Header type */
	unsigned char  sll_pkttype;  /* Packet type */
	unsigned char  sll_halen;    /* Length of address */
	unsigned char  sll_addr[8];  /* Physical layer address */
};
#elif __APPLE__
	#include <libkern/OSByteOrder.h>
	#define htobe16(x) OSSwapHostToBigInt16(x)
	#define htole16(x) OSSwapHostToLittleInt16(x)
	#define be16toh(x) OSSwapBigToHostInt16(x)
	#define le16toh(x) OSSwapLittleToHostInt16(x)
	#define htobe32(x) OSSwapHostToBigInt32(x)
	#define htole32(x) OSSwapHostToLittleInt32(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define le32toh(x) OSSwapLittleToHostInt32(x)
	#define htobe64(x) OSSwapHostToBigInt64(x)
	#define htole64(x) OSSwapHostToLittleInt64(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
	#define le64toh(x) OSSwapLittleToHostInt64(x)
	#define ENABLE_ETHER_BPF
	#define AF_PACKET  0xab /* workaround for SockAddr_haskey */
               // not defined in BSD, but we need it to retrieve dest MAC addr of outgoing packets
        #include <net/bpf.h>
        #include <net/if_dl.h>

struct __attribute__((__packed__)) sockaddr_ll {
	unsigned char  padding;      /* so this struct will line up with BDS's sockaddr struct */
	unsigned short sll_family;   /* Always AF_PACKET */
	unsigned short sll_protocol; /* Physical layer protocol */
	int            sll_ifindex;  /* Interface number */
	unsigned short sll_hatype;   /* Header type */
	unsigned char  sll_pkttype;  /* Packet type */
	unsigned char  sll_halen;    /* Length of address */
	unsigned char  sll_addr[8];  /* Physical layer address */
};
#endif
#ifdef __linux__
	#define ENABLE_ETHER
	#include <netinet/ether.h>
	#include <netpacket/packet.h>
#endif
#include <ccn/ccn.h>
#include <ccn/hashtb.h>
#include <ccn/reg_mgmt.h>

#define ALLOCSELF (calloc(1, sizeof(*self)))


//valuetype bool
typedef int bool;
#define true -1
#define false 0


//class ByteArray
void* ByteArray_clone(void* src, size_t len);


//class String
char* String_clone(char* src);


//valuetype DateTime TimeSpan
typedef int64_t DateTime;//milliseconds since 1970-01-01
typedef int64_t TimeSpan;//milliseconds
DateTime DateTime_now(void);
void DateTime_mockNow(DateTime mocked);
#define DateTime_noMock -1


//class SocketAddress
struct SockAddr_cls {
	struct sockaddr* addr;
	socklen_t addrlen;
	struct ccn_charbuf* hashkey;
};
typedef struct SockAddr_cls* SockAddr;
SockAddr SockAddr_ctor(void);
SockAddr SockAddr_create(void* addr, socklen_t addrlen);//will clone
void SockAddr_dtor(SockAddr self);
void SockAddr_clear(SockAddr self);
struct sockaddr* SockAddr_addr(SockAddr self);
socklen_t SockAddr_addrlen(SockAddr self);
socklen_t* SockAddr_addrlenp(SockAddr self);
struct ccn_charbuf* SockAddr_hashkey(SockAddr self);//return value owned by SockAddr
bool SockAddr_equals(SockAddr self, SockAddr other);
SockAddr SockAddr_clone(SockAddr self);
void SockAddr_copyto(SockAddr self, SockAddr dst);
char* SockAddr_toString(SockAddr self);


//enum BufferMode
typedef int BufMode;
#define BufMode_own 1//StreamBuf/DgramBuf should free data
#define BufMode_clone 2//StreamBuf/DgramBuf should clone data
#define BufMode_use 3//StreamBuf/DgramBuf can use data, but should not free it

enum SocketType {
	SockType_Dgram,
	SockType_Stream,
	SockType_BPF,
};


//class StreamBuffer
//class DatagramBuffer
struct Buf_rec;
typedef struct Buf_rec* BufRec;
struct Buf_cls {
	BufRec head;
	BufRec tail;
};
typedef struct Buf_cls* StreamBuf;
typedef struct Buf_cls* DgramBuf;
StreamBuf StreamBuf_ctor(void);
void StreamBuf_dtor(StreamBuf self);
void StreamBuf_prepend(StreamBuf self, void* data, size_t start, size_t len, BufMode mode);
void StreamBuf_append(StreamBuf self, void* data, size_t start, size_t len, BufMode mode);
bool StreamBuf_empty(StreamBuf self);
bool StreamBuf_get(StreamBuf self, void** pdata, size_t* plen);//get a block from beginning
void StreamBuf_consume(StreamBuf self, size_t len);
DgramBuf DgramBuf_ctor(void);
void DgramBuf_dtor(DgramBuf self);
void DgramBuf_prepend(DgramBuf self, void* data, size_t start, size_t len, BufMode mode, SockAddr addr);//addr not owned by DgramBuf
void DgramBuf_append(DgramBuf self, void* data, size_t start, size_t len, BufMode mode, SockAddr addr);//addr not owned by DgramBuf
bool DgramBuf_empty(DgramBuf self);
bool DgramBuf_get(DgramBuf self, void** pdata, size_t* plen, SockAddr addr);//get a datagram from beginning; addr allocated by caller
void DgramBuf_consumeOne(DgramBuf self);
//private begin
struct Buf_rec {
	BufRec next;
	uint8_t* buffer;
	bool own;//if true, free buffer on dtor
	size_t pos;
	size_t length;//length of buffer
	SockAddr addr;
};
BufRec BufRec_ctor(void* data, size_t start, size_t len, BufMode mode, SockAddr addr);
void BufRec_dtor(BufRec self);
//private end


//enum PollManagerEventType
typedef int PollMgrEvt;
#define PollMgrEvt_prepare 1
#define PollMgrEvt_result 2
#define PollMgrEvt_error 3


//delegate PollManagerCallback
typedef void (*PollMgrCb)(void* data, PollMgrEvt evt, struct pollfd* fd);//fd->fd is always present when called


//class PollManager
struct PollMgr_rec;
typedef struct PollMgr_rec* PollMgrRec;
struct PollMgr_cls {
	int count;
	int capacity;
	PollMgrRec records;
	struct pollfd* fds;
	int timeout;//milliseconds
};
typedef struct PollMgr_cls* PollMgr;
PollMgr PollMgr_ctor(TimeSpan timeout);
void PollMgr_dtor(PollMgr self);//does not call NBS_dtor
void PollMgr_attach(PollMgr self, int fd, PollMgrCb cb, void* data);
void PollMgr_detach(PollMgr self, int fd, PollMgrCb cb, void* data);
void PollMgr_poll(PollMgr self);
//private begin
struct PollMgr_rec {
	int fd;
	void* data;
	PollMgrCb callback;
	struct pollfd* pfd;
};
void PollMgr_resize(PollMgr self, int capacity);
//private end


//class NonBlockingSocket
struct NBS_cls;
typedef struct NBS_cls* NBS;


//delegate NonBlockingSocketCallback
typedef void (*NBSCb)(void* data, NBS nbs);


//class NonBlockingSocket
struct NBS_cls {
	//bool isDgram;
	enum SocketType sock_type;
	int sockR;
	StreamBuf sbufR;
	DgramBuf dbufR;
	bool canR;
	int sockW;
	StreamBuf sbufW;
	DgramBuf dbufW;
	bool canW;
	bool error;
	bool closeSock;
	NBSCb dataArrivalCb;
	void* dataArrivalCbData;
	PollMgr pm;
	int bpf_len;
};
//typedef struct NBS_cls* NBS;
NBS NBS_ctor(int sockR, int sockW, enum SocketType);
void NBS_dtor(NBS self);
bool NBS_isDgram(NBS self);
int NBS_sockR(NBS self);
int NBS_sockW(NBS self);
bool NBS_error(NBS self);
void NBS_setSockClose(NBS self, bool close);//set whether close sockets on dtor
void NBS_pollAttach(NBS self, PollMgr pm);
void NBS_pollDetach(NBS self);
void NBS_setDataArrivalCb(NBS self, NBSCb cb, void* data);
size_t NBS_read(NBS self, void* buf, size_t count, SockAddr srcaddr);//read up to count octets or one datagram; srcaddr allocated by caller
void NBS_pushback(NBS self, void* data, size_t start, size_t len, SockAddr srcaddr);//push back data/datagram that are read but not consumed; buffer owned by NBS, srcaddr not owned by NBS
void NBS_write(NBS self, void* data, size_t start, size_t len, SockAddr dstaddr);//write data; buffer will be owned by NBS, dstaddr not owned by NBS
//private begin
void NBS_pollCb(void* pself, PollMgrEvt evt, struct pollfd* fd);
void NBS_deferredWrite(NBS self);
//private end


//class CapabilityHelper
void CapsH_drop(void);//drop capabilities; called when the program starts
int CapsH_createPacketSock(int socket_type, int protocol);//create a AF_PACKET socket
int CapsH_createBPF(char* ifname); // create a BPF device (only for BSD)

//class CcnbMessage
typedef struct ccn_charbuf* CcnbMsg;
CcnbMsg CcnbMsg_ctor(size_t size);//size without encap
CcnbMsg CcnbMsg_fromEncap(struct ccn_charbuf* encap);//create from encap; encap will be owned by CcnbMsg
void CcnbMsg_dtor(CcnbMsg self);
void* CcnbMsg_detachBuf(CcnbMsg self, size_t* size);//destroy instance but keep and return buffer, size set to encap size
void CcnbMsg_setupEncap(CcnbMsg self, size_t size);//private, size with encap
size_t CcnbMsg_getSize(CcnbMsg self);//size without encap
void CcnbMsg_resize(CcnbMsg self, size_t size);//size without encap
void* CcnbMsg_getBody(CcnbMsg self);
void* CcnbMsg_getBodyPart(CcnbMsg self, size_t start);
size_t CcnbMsg_getEncapSize(CcnbMsg self);
void* CcnbMsg_getEncap(CcnbMsg self);
void CcnbMsg_setBodyPart(CcnbMsg self, void* buf, size_t start, size_t length);//copy buf into body[start]
bool CcnbMsg_verifyIntegrity(CcnbMsg self);


//valuetype CCNDID
typedef const unsigned char* CCNDID;
#define CCNDID_length 32


//enum CcnPrefixOperation
typedef uint8_t CcnPrefixOp;
#define CcnPrefixOp_register 1
#define CcnPrefixOp_unregister 2
#define CcnPrefixOp_selfreg 3


//class CcnHelper
struct ccn_charbuf* CcnH_localScopeTempl(void);
struct ccn_forwarding_entry* CcnH_buildForwardingEntry(CcnPrefixOp operation, CCNDID ccndid, int faceid, struct ccn_charbuf* prefix);
struct ccn_charbuf* CcnH_signForwardingEntry(struct ccn* ccnh, CCNDID ccndid, struct ccn_forwarding_entry* fe);
void CcnH_regForwardingEntry(struct ccn* ccnh, CCNDID ccndid, struct ccn_forwarding_entry* fe, void* closureData, ccn_handler closureHandler);
bool CcnH_regPrefix(CcnPrefixOp operation, struct ccn* ccnh, CCNDID ccndid, int faceid, struct ccn_charbuf* prefix);//will block
void CcnH_pollPrepare(struct ccn* ccnh, struct pollfd* fd);//set fd->events based on need
void CcnH_pollRun(struct ccn* ccnh, struct pollfd* fd);//call ccn_run if fd->revents suggests


//class CcnbObjectReader
struct CcnbOR_cls {
	NBS nbs;
	struct ccn_skeleton_decoder* rd;
	struct ccn_charbuf* cbuf;
	bool error;
};
typedef struct CcnbOR_cls* CcnbOR;
CcnbOR CcnbOR_ctor(NBS nbs);//NBS must be in Stream mode
void CcnbOR_dtor(CcnbOR self);//does not call NBS_dtor
bool CcnbOR_error(CcnbOR self);
void CcnbOR_clear(CcnbOR self);
struct ccn_charbuf* CcnbOR_read(CcnbOR self);//returns a complete message (owned by caller), or NULL


//class ConnectionManager
struct ConnMgr_cls;
typedef struct ConnMgr_cls* ConnMgr;

//class CcnControlChannel
struct CcnCC_cls {
	struct ccn* ccnh;
	bool error;
	unsigned char ccndid_storage[32];
	CCNDID ccndid;
	bool regControlPrefix;
	ConnMgr connMgr;
};
typedef struct CcnCC_cls* CcnCC;
CcnCC CcnCC_ctor(void);//will block to get ccndid
void CcnCC_dtor(CcnCC self);
bool CcnCC_error(CcnCC self);
struct ccn* CcnCC_ccnh(CcnCC self);
CCNDID CcnCC_ccndid(CcnCC self);
void CcnCC_pollAttach(CcnCC self, PollMgr pm);
void CcnCC_pollDetach(CcnCC self, PollMgr pm);
void CcnCC_setConnMgr(CcnCC self, ConnMgr cmgr);
void CcnCC_sendContent(CcnCC self, struct ccn_charbuf* name, TimeSpan expires, void* data, size_t size);
//private begin
void CcnCC_fetchCcndid(CcnCC self);//will block
void CcnCC_registerControlPrefix(CcnCC self);
void CcnCC_pollCb(void* pself, PollMgrEvt evt, struct pollfd* fd);
enum ccn_upcall_res CcnCC_regPrefixCb(struct ccn_closure* selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info* info);
enum ccn_upcall_res CcnCC_controlInterest(struct ccn_closure* selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info* info);
bool CcnCC_controlInterest1(CcnCC self, struct ccn_upcall_info* info);
//private end


//class CcnLinkAdaptorClient, talk with local ccnd over UNIX socket
struct CcnLAC_cls {
	struct ccn* ccnh;
	bool error;
	NBS nbs;
	PollMgr pm;//(during init only)
	int faceid;
	CcnbOR ccnbor;
};
typedef struct CcnLAC_cls* CcnLAC;
CcnLAC CcnLAC_ctor(void);
void CcnLAC_dtor(CcnLAC self);
bool CcnLAC_error(CcnLAC self);
bool CcnLAC_ready(CcnLAC self);//true if initialization is completed
void CcnLAC_initialize(CcnLAC self, CCNDID ccndid, PollMgr pm);
int CcnLAC_faceid(CcnLAC self);
CcnbMsg CcnLAC_read(CcnLAC self);
void CcnLAC_write(CcnLAC self, CcnbMsg msg);//msg owned by CcnLAC
//private begin
#define CcnLAC_faceid_unknown -1
void CcnLAC_initPollCb(void* pself, PollMgrEvt evt, struct pollfd* fd);
void CcnLAC_fetchFaceid(CcnLAC self, CCNDID ccndid);
enum ccn_upcall_res CcnLAC_fetchFaceidCb(struct ccn_closure* selfp, enum ccn_upcall_kind kind, struct ccn_upcall_info* info);
//private end


//valuetype SequenceNumber (48-bit)
typedef uint64_t SeqNum;
#define SeqNum_mask 0x0000FFFFFFFFFFFF
#define SeqNum_len 6
SeqNum SeqNum_add(SeqNum self, int diff);
SeqNum SeqNum_rand(void);
SeqNum SeqNum_readFrom(void* buf);
void SeqNum_writeTo(SeqNum self, void* buf);


//class SequenceBlock
struct SeqBlock_cls {
	SeqNum base;
	int size;
};
typedef struct SeqBlock_cls* SeqBlock;
SeqBlock SeqBlock_ctor(SeqNum base, int size);
void SeqBlock_dtor(SeqBlock self);
SeqNum SeqBlock_item(SeqBlock self, int index);


//class SequenceGenerator
struct SeqGen_cls {
	SeqNum next;
};
typedef struct SeqGen_cls* SeqGen;
SeqGen SeqGen_ctor(void);
void SeqGen_dtor(SeqGen self);
SeqNum SeqGen_next(SeqGen self);
SeqBlock SeqGen_nextBlock(SeqGen self, int size);


//class CcnbHelper
#define CcnbH_maxBlockHdr 10//max length of block hdr with 64-bit number
int CcnbH_sizeBlockHdr(uint64_t number);//calculate the length of block hdr
char* CcnbH_getBlockHdr(uint64_t number, enum ccn_tt tt);//returns internal buffer, must strcpy immediately
int CcnbH_readBlockHdr(uint8_t* buf, size_t len, uint64_t* pnumber, enum ccn_tt* ptt);//returns consumed octets on success, 0 on failure; len==-1 means unlimited until \0; allow pnumber==NULL or ptt==NULL


//class NdnlpPacket
typedef struct ccn_charbuf* NdnlpPkt;
typedef NdnlpPkt DataPkt;
typedef NdnlpPkt AckPkt;
#define NdnlpPkt_typelen 4//hdr length to identify type
NdnlpPkt NdnlpPkt_ctor(void* buf, size_t len, bool clone);//returns NULL if not valid ccnb
void NdnlpPkt_dtor(NdnlpPkt self);
uint8_t* NdnlpPkt_detachBuf(NdnlpPkt self);//dtor, but keep buffer
NdnlpPkt NdnlpPkt_clone(NdnlpPkt other);
size_t NdnlpPkt_length(NdnlpPkt self);
bool NdnlpPkt_isData(NdnlpPkt self);
DataPkt NdnlpPkt_asData(NdnlpPkt self);
bool NdnlpPkt_isAck(NdnlpPkt self);
AckPkt NdnlpPkt_asAck(NdnlpPkt self);


//class NdnlpPacketArray
struct NdnlpPktA_cls {
	int capacity;
	int length;
	NdnlpPkt* items;
};
#define NdnlpPktA_initialCapacity 1
#define NdnlpPktA_increaseCapacity 2
typedef struct NdnlpPktA_cls* NdnlpPktA;
NdnlpPktA NdnlpPktA_ctor(int length);
void NdnlpPktA_dtor(NdnlpPktA self, bool dtorPkt);//dtorPkt: whether to call NdnlpPkt_dtor
int NdnlpPktA_length(NdnlpPktA self);
NdnlpPkt NdnlpPktA_get(NdnlpPktA self, int index);
void NdnlpPktA_set(NdnlpPktA self, int index, NdnlpPkt item);
void NdnlpPktA_append(NdnlpPktA self, NdnlpPkt item);


//enum DataPktFlag
typedef uint16_t DataPktFlag;
#define DataPktFlag_none 0
#define DataPktFlag_RLA 0x8000


//class DataPacket
//typedef NdnlpPkt DataPkt;
#define DataPkt_hdr "\x4E\x64\x4C\x82\x4E\x64\x4C\x8A\xB5\0\0\0\0\0\0\x00\x4E\x64\x4C\x92\x95\0\0\x00\x4E\x64\x4C\x9A\x95\0\0\x00\x4E\x64\x4C\xA2\x95\0\0\x00"//<NdnlpData><NdnlpSequence>000000</NdnlpSequence><NdnlpFlags>00</NdnlpFlags><NdnlpFragIndex>00</NdnlpFragIndex><NdnlpFragCount>00</NdnlpFragCount>
#define DataPkt_hdrlen1 24//...</NdnlpFlags>
#define DataPkt_hdrlen2 40//...</NdnlpFragCount>
#define DataPkt_fraglen0 4//to identify Frag fields
#define DataPkt_offset_Sequence 9
#define DataPkt_offset_Flags 21
#define DataPkt_offset_FragIndex 29
#define DataPkt_default_FragIndex 0
#define DataPkt_offset_FragCount 37
#define DataPkt_default_FragCount 1
#define DataPkt_payloadhdr "\x4E\x64\x4C\xAA\0\0\0\0\0\0\0\0"//<NdnlpPayload>(and spacer for BLOB hdr)
#define DataPkt_payloadhdrlen1 4//<NdnlpPayload>
#define DataPkt_trailer "\x00\x00"//</NdnlpPayload></NdnlpData>
#define DataPkt_trailerlen 2
DataPkt DataPkt_ctor(bool hasFragFields, size_t payloadLength);
//accessors
SeqNum DataPkt_getSequence(DataPkt self);
void DataPkt_setSequence(DataPkt self, SeqNum value);
DataPktFlag DataPkt_getFlags(DataPkt self);
void DataPkt_setFlags(DataPkt self, DataPktFlag value);
uint16_t DataPkt_getFragIndex(DataPkt self);
bool DataPkt_setFragIndex(DataPkt self, uint16_t value);//returns false if FragIndex element is not present
uint16_t DataPkt_getFragCount(DataPkt self);
bool DataPkt_setFragCount(DataPkt self, uint16_t value);//returns false if FragCount element is not present
//methods
SeqNum DataPkt_getMessageIdentifier(DataPkt self);//Sequence - FragIndex
bool DataPkt_isFragmented(DataPkt self);
bool DataPkt_hasRLA(DataPkt self);
size_t DataPkt_payloadLength(DataPkt self);
uint8_t* DataPkt_payload(DataPkt self, size_t* plen);//allow plen==NULL; if DataPkt is changed, the return value is no longer valid
//private begin
bool DataPkt_hasFragFields(DataPkt self);
//private end


//class MessageSlicer
struct MsgSlicer_cls {
	SeqGen seqgen;
	size_t fragSize;
};
typedef struct MsgSlicer_cls* MsgSlicer;
MsgSlicer MsgSlicer_ctor(SeqGen seqgen, size_t mtu);
void MsgSlicer_dtor(MsgSlicer self);
NdnlpPktA MsgSlicer_slice(MsgSlicer self, CcnbMsg msg);


//enum PartialMessageResult
typedef int PartialMsgRes;
#define PartialMsgRes_deliver 1//message is ready for delivery to ccnd
#define PartialMsgRes_stored 2//packet added to store
#define PartialMsgRes_duplicate 3//packet is a duplicate
#define PartialMsgRes_mismatch 4//fragment size or count mismatches previous packets
#define PartialMsgRes_outRange 5//fragment index is out of range
#define PartialMsgRes_isSuccess(res) (res <= 2)


//class PartialMessagesStore
struct PartialMsg_rec;
typedef struct PartialMsg_rec* PartialMsgRec;
struct PartialMsgs_cls {
	PartialMsgRec phead;//partial messages list
	PartialMsgRec ptail;
	int count;
	struct hashtb* index;//identifier=>PartialMsgRec
	PartialMsgRec dhead;//complete messages (ready for delivery) list
	PartialMsgRec dtail;
};
typedef struct PartialMsgs_cls* PartialMsgs;
PartialMsgs PartialMsgs_ctor(void);
void PartialMsgs_dtor(PartialMsgs self);
PartialMsgRes PartialMsgs_arrive(PartialMsgs self, DataPkt pkt);//pkt owned by PartialMsgs on success
CcnbMsg PartialMsgs_getDeliver(PartialMsgs self);//get a complete message for delivery to ccnd, NULL if no message ready for delivery
//private begin
void PartialMsgs_pInsert(PartialMsgs self, PartialMsgRec rec);//insert to partial messages list
void PartialMsgs_pDetach(PartialMsgs self, PartialMsgRec rec);//detach from partial messages list
void PartialMsgs_dInsert(PartialMsgs self, PartialMsgRec rec);//insert to complete messages list
void PartialMsgs_dDetach(PartialMsgs self, PartialMsgRec rec);//detach from complete messages list
#define PartialMsgRec_maxPreallocateBuffer 0x100000
#define PartialMsgRec_unknownFragmentSize 0
struct PartialMsg_rec {
	PartialMsgRec prev;
	PartialMsgRec next;
	SeqNum identifier;
	DateTime arriveTime;//last arrival time
	unsigned int arriveCount;
	bool* fragmentArrived;
	uint32_t fragmentSize;
	unsigned int fragmentCount;
	//large message: use fragments field, reassembly when all fragments arrived
	//small message: pre-allocate message field, copy each fragment into buffer
	//fragmentSize unknown (only last fragment received): use lastFragment field, wait for next fragment
	DataPkt* fragments;
	CcnbMsg message;
	DataPkt lastFragment;
};
void PartialMsgRec_dtor(PartialMsgRec self, bool keepMessage);
//PartialMsgRec will take care of DataPkt_dtor on successful return
PartialMsgRes PartialMsgRec_create(DataPkt pkt, PartialMsgRec* pself);
PartialMsgRes PartialMsgRec_addPkt(PartialMsgRec self, DataPkt pkt);
void PartialMsgRec_addPktNoCheck(PartialMsgRec self, DataPkt pkt);//add packet without checking
void PartialMsgRec_addPktStore(PartialMsgRec self, DataPkt pkt);//add packet into either .message or .fragments
void PartialMsgRec_addPktMsg(PartialMsgRec self, DataPkt pkt);//add packet into either .message, call DataPkt_dtor
PartialMsgRes PartialMsgRec_checkDeliver(PartialMsgRec self);//check whether all fragments arrived
void PartialMsgRec_makeMsg(PartialMsgRec self);//create .message from .fragments
//private end


//class SentPacketsStore
struct SentPkt_rec;
typedef struct SentPkt_rec* SentPktRec;
struct SentPkts_cls {
	int capacity;
	SentPktRec shead;//send list sorted by first send time, used for drop old packets when store is full
	SentPktRec stail;
	SentPktRec rhead;//resend list sorted by last send time
	SentPktRec rtail;
	int count;
	struct hashtb* index;//sequence=>SentPkt_rec
	int retryCount;
};
typedef struct SentPkts_cls* SentPkts;
SentPkts SentPkts_ctor(int capacity, int retryCount);
void SentPkts_dtor(SentPkts self);
void SentPkts_remove(SentPkts self, SeqNum sequence);//remove when acknowledged
void SentPkts_insert(SentPkts self, DataPkt pkt);//pkt cloned by SentPkts
DataPkt SentPkts_getRetransmit(SentPkts self, DateTime sendBefore);//get a packet to retransmit, last send time < sendBefore; NULL if no retransmission needed; returned pkt owned by caller
//private begin
void SentPkts_sInsert(SentPkts self, SentPktRec rec);//insert to send list
void SentPkts_sDetach(SentPkts self, SentPktRec rec);//detach from send list
void SentPkts_rInsert(SentPkts self, SentPktRec rec);//insert to resend list
void SentPkts_rDetach(SentPkts self, SentPktRec rec);//detach from resend list
#define SentPktRec_retryCount 5
struct SentPkt_rec {
	SentPktRec sprev;
	SentPktRec snext;
	SentPktRec rprev;
	SentPktRec rnext;
	DateTime sendTime;//last send time
	int retryCount;//decrement on each retry until zero
	DataPkt pkt;
};
SentPktRec SentPktRec_ctor(DataPkt pkt, int retryCount);
void SentPktRec_dtor(SentPktRec self, bool keepPkt);
//private end


//class AcknowledgementBlock
struct AckBlock_cls;
typedef struct AckBlock_cls* AckBlock;
//methods defined later


//class AcknowledgementBlockEnumerator
struct AckBlockEn_cls {
	AckBlock ab;
	SeqNum seqBase;
	uint8_t* bitmapEnd;
	uint8_t* pos;
	uint8_t bitmask;
	SeqNum sequence;
};
typedef struct AckBlockEn_cls* AckBlockEn;
AckBlockEn AckBlockEn_ctor(AckBlock ab);//if AckPkt is changed, AckBlockEn is no longer valid without reset
void AckBlockEn_dtor(AckBlockEn self);
void AckBlockEn_reset(AckBlockEn self);
bool AckBlockEn_moveNext(AckBlockEn self);
SeqNum AckBlockEn_current(AckBlockEn self);


//class AcknowledgementBlock
struct AckBlock_cls {
	AckPkt pkt;
	size_t offset;
};
//typedef struct AckBlock_cls* AckBlock;
#define AckBlock_hdr "\x4E\x64\x4C\xBA\x4E\x64\x4C\xC2\xB5\0\0\0\0\0\0\x00\x4E\x64\x4C\xCA"//<NdnlpAckBlock><NdnlpSequenceBase>000000</NdnlpSequenceBase><NdnlpBitmap>
#define AckBlock_hdrlen0 4//to identify AckBlock
#define AckBlock_hdrlen 20
#define AckBlock_offset_SequenceBase 9
#define AckBlock_trailer "\x00\x00"//</NdnlpBitmap></NdnlpAckBlock>
#define AckBlock_trailerlen 2
AckBlock AckBlock_ctor(AckPkt pkt, size_t offset);
void AckBlock_dtor(AckBlock self);
//accessors
SeqNum AckBlock_getSequenceBase(AckBlock self);
void AckBlock_setSequenceBase(AckBlock self, SeqNum value);
//methods
size_t AckBlock_length(AckBlock self);
size_t AckBlock_bitmapLength(AckBlock self);//bitmap length in octets
uint8_t* AckBlock_bitmap(AckBlock self, size_t* plen);//allow plen==NULL; if AckPkt is changed, the return value is no longer valid
size_t AckBlock_newlength(size_t bitmapLength);//calculate the length of a new AckBlock
void AckBlock_newappend(AckBlock self, size_t bitmapLength);//append a new AckBlock into end of AckPkt


//class AcknowledgementPacket
//typedef NdnlpPkt AckPkt;
#define AckPkt_hdr "\x4E\x64\x4C\xB2"//<NdnlpAck>
#define AckPkt_hdrlen 4//...<NdnlpAck>
#define AckPkt_trailer "\x00"//</NdnlpAck>
#define AckPkt_trailerlen 1
AckPkt AckPkt_ctor(void);
AckBlock AckPkt_getAckBlock(AckPkt self, AckBlock previous);//get first (previous==NULL) or next (previous!=NULL) AckBlock, returns NULL if no more AckBlock
AckBlock AckPkt_addAckBlock(AckPkt self, AckBlock last, size_t bitmapLength);//add a new AckBlock at the end; last must be the last AckBlock currently in the AckPkt, or NULL if none
size_t AckPkt_remainingBitmapSize(AckPkt self, size_t mtu);//estimate the maximum size of bitmap if a new AckBlock would be added
//private begin
size_t AckPkt_nextAckBlockOffset(AckPkt self, AckBlock previous);//get the offset of next AckBlock, or where it should be
//private end


//class AcknowledgeQueue
struct AckQueue_cls {
	size_t mtu;
	NdnlpPktA pkts;//completed pkts
	AckPkt pkt;//pkt being built
	AckBlock lastBlock;//last block in pkt
	bool hasBitmap;
	size_t mbl;//max bitmap length to fit in pkt
	uint8_t* bitmap;//bitmap being built (buffer size is mtu)
	SeqNum seqbase;//sequence base of bitmap
	SeqNum seqmax;//max acknowledged sequence number in bitmap
};
#define AckQueue_newBlockGapThreshold 30//if there are more than this number of zeros, a new AckBlock should be created
typedef struct AckQueue_cls* AckQueue;
AckQueue AckQueue_ctor(size_t mtu);
void AckQueue_dtor(AckQueue self);
void AckQueue_insert(AckQueue self, SeqNum sequence);
NdnlpPktA AckQueue_getPkts(AckQueue self);//get AckPkt(s) to send
//private begin
void AckQueue_newBitmap(AckQueue self, SeqNum sequence);//initialize new bitmap that starts with sequence
bool AckQueue_bitmapOffset(AckQueue self, SeqNum sequence, size_t* poffset, uint8_t* pbit);//calculates the offset if putting sequence into current bitmap, allow pbit=NULL
void AckQueue_bitmapIntoPkt(AckQueue self);//move current bitmap into pkt
void AckQueue_pktIntoPkts(AckQueue self);//move current pkt into pkts
//private end


//class LinkMuxDemux
struct LMD_cls;
typedef struct LMD_cls* LMD;


//class Link
struct Link_cls {
	NBS nbs;
	CcnbOR ccnbor;//(Stream only)
	SockAddr addr;//(Dgram only) address of other end
	LMD lmd;//(Dgram only)
	int lossy;//>0: packet loss on write when rand()<lossy
};
typedef struct Link_cls* Link;
Link Link_ctorStream(NBS nbs);
Link Link_ctorDgram(LMD lmd, SockAddr addr);//will clone addr
void Link_dtor(Link self);//will call NBS_dtor in Stream mode, does not call LMD_dtor
void Link_setLossy(Link self, float lossPct);
bool Link_error(Link self);
SockAddr Link_addr(Link self);
size_t Link_mtu(Link self);//only meaningful in Dgram mode
NdnlpPkt Link_read(Link self);//read from lmd or nbs
void Link_write(Link self, NdnlpPkt pkt);//write to lmd or nbs; pkt owned by Link


//class LinkMuxDemux
struct LMD_rec;
typedef struct LMD_rec* LMDRec;
struct LMD_cls {
	SockAddr localAddr;
	size_t mtu;
	NBS nbs;
	LMDRec fallback;
	struct hashtb* demux;//sockaddr=>LMDRec
};
//typedef struct LMD_cls* LMD;
LMD LMD_ctor(NBS nbs, SockAddr localAddr, size_t mtu);//localAddr is optional, will clone
void LMD_dtor(LMD self);//will call NBS_dtor
SockAddr LMD_localAddr(LMD self);
size_t LMD_mtu(LMD self);
NBS LMD_nbs(LMD self);
SockAddr LMD_fallbackAddr(void);//returns a new srcaddr that indicates fallback; caller must call SockAddr_dtor
bool LMD_registered(LMD self, SockAddr srcaddr);//whether an address is already registered
void LMD_reg(LMD self, SockAddr srcaddr);//register receiver
void LMD_unreg(LMD self, SockAddr srcaddr);//unregister receiver
NdnlpPkt LMD_read(LMD self, SockAddr srcaddr);//if srcaddr is fallbackAddr, it will be updated with actual srcaddr
//private begin
SockAddr LMD_fallbackAddr_inst(void);
void LMD_demux(LMD self);//receive all pending pkts and deliver to LMDRec
struct LMD_rec {
	DgramBuf demuxBuf;//received packets not read by Link
};
LMDRec LMDRec_ctor(SockAddr addr);
void LMDRec_dtor(LMDRec self);
void LMDRec_deliver(LMDRec self, void* packet, size_t len, SockAddr srcaddr);//will clone srcaddr
NdnlpPkt LMDRec_read(LMDRec self, SockAddr srcaddr);//srcaddr is output, can be NULL
//private end


//class LinkCreator
#define LinkC_udp_port 29695
#define LinkC_udp_mtu 1420
#define LinkC_eth_proto 0x8624
LMD LinkC_lUdp(PollMgr pm);//local UDP
Link LinkC_rUdp(LMD lmd, SockAddr rAddr);//remote UDP
LMD LinkC_lEth(PollMgr pm, char* ifname);//local Ethernet
Link LinkC_rEth(LMD lmd, SockAddr rAddr);//remote Ethernet
SockAddr LinkC_parseIP(char* str);//parse IPv6 or IPv4 address
SockAddr LinkC_parseEther(char* str);//parse Ethernet MAC address from standard hex-digits-and-colons notation; sll_ifindex is not set
//private begin
bool LinkC_getIfInfo(char* ifname, int* pifindex, int* pmtu);
//private end


//class NdnlpService
struct NdnlpSvc_cls {
	CcnLAC lac;
	Link link;
	SeqGen seqGen;
	MsgSlicer msgSlicer;
	PartialMsgs partialMsgs;
	SentPkts sentPkts;
	AckQueue ackQueue;
	DateTime nextAckTime;
	bool rla;
	TimeSpan retransmitTime;
	TimeSpan acknowledgeTime;
};
#define NdnlpSvc_SentPktsCapacity 100
#define NdnlpSvc_RetransmitTime 1000
#define NdnlpSvc_AcknowledgeTime 300
typedef struct NdnlpSvc_cls* NdnlpSvc;
NdnlpSvc NdnlpSvc_ctor(CcnLAC lac, Link link, bool rla, int sentPktsCapacity, int retryCount, TimeSpan retransmitTime, TimeSpan acknowledgeTime);
void NdnlpSvc_dtor(NdnlpSvc self);
bool NdnlpSvc_error(NdnlpSvc self);
void NdnlpSvc_run(NdnlpSvc self);//should be called after poll
//private begin
void NdnlpSvc_ccn2link(NdnlpSvc self);//process messages from lac
void NdnlpSvc_msg(NdnlpSvc self, CcnbMsg msg);//process one message from lac
bool NdnlpSvc_RLAPolicy(NdnlpSvc self, CcnbMsg msg, DataPkt pkt);//determine whether link-ACK is needed
void NdnlpSvc_link2ccn(NdnlpSvc self);//process packets from link
void NdnlpSvc_data(NdnlpSvc self, DataPkt pkt);//process one data pkt from link
void NdnlpSvc_ack(NdnlpSvc self, AckPkt pkt);//process one ack pkt from link
void NdnlpSvc_retransmit(NdnlpSvc self);//retransmit if necessary
void NdnlpSvc_acknowledge(NdnlpSvc self);//send acknowledgements if necessary
//private end


//class ConnectionManagementProtocol_NdnldConnection
struct CMPConn_cls {
	int Verb;
	int FaceID;
	int LowerProto;
	char* Host;
	char* LocalIf;
	uint16_t Flags;
	int SentPktsCapacity;
	int RetryCount;
	TimeSpan RetransmitTime;
	TimeSpan AcknowledgeTime;
	struct ccn_charbuf* InterestName;//name in interest
	int State;
};//most fields are public
typedef struct CMPConn_cls* CMPConn;
#define CMPConn_Verb_connect 1
#define CMPConn_Verb_connect_str "connect"
#define CMPConn_Verb_disconnect 2
#define CMPConn_Verb_disconnect_str "disconnect"
#define CMPConn_Verb_listconnections 3
#define CMPConn_Verb_listconnections_str "listconnections"
#define CMPConn_LowerProto_ether 1
#define CMPConn_LowerProto_ether_str "ether"
#define CMPConn_LowerProto_udp 2
#define CMPConn_LowerProto_udp_str "udp"
#define CMPConn_Flags_RLA 0x8000
#define CMPConn_SentPktsCapacity_default 100
#define CMPConn_RetryCount_default 5
#define CMPConn_RetransmitTime_default 1000
#define CMPConn_AcknowledgeTime_default 300
#define CMPConn_State_normal 1
#define CMPConn_State_normal_str "normal"
#define CMPConn_State_error 2
#define CMPConn_State_error_str "error"
#define DTAG_NdnldConnection 20653264
#define DTAG_NdnldLowerProtocol 20653265
#define DTAG_NdnldLocalInterface 20653266
#define DTAG_NdnldSentPktsCapacity 20653267
#define DTAG_NdnldRetransmitCount 20653268
#define DTAG_NdnldRetransmitTime 20653269
#define DTAG_NdnldAcknowledgeTime 20653270
CMPConn CMPConn_ctor(void);
void CMPConn_dtor(CMPConn self);
char* CMPConn_toString(CMPConn self);
struct ccn_charbuf* CMPConn_toContentObject(CMPConn self);
bool CMPConn_appendContentObject(CMPConn self, struct ccn_charbuf* c);
CMPConn CMPConn_fromContentObject(const uint8_t* contentObject, size_t size);
CMPConn CMPConn_readContentObject(struct ccn_buf_decoder* d);
struct ccn_charbuf* CMPConn_toInterestName(CMPConn self, CcnCC cc);
CMPConn CMPConn_fromInterest(const uint8_t* interest_ccnb, struct ccn_parsed_interest* pi, struct ccn_indexbuf* interest_comps);


//class ConnectionManager
struct ConnMgr_rec;
typedef struct ConnMgr_rec* ConnMgrRec;
struct ConnMgr_cls {
	PollMgr pm;
	CcnCC cc;
	struct hashtb* htLMD;//udp|localIf=>LMD
	struct hashtb* htAddrRec;//address=>ConnMgrRec
	struct hashtb* htFaceRec;//faceID=>ConnMgrRec
	ConnMgrRec pendingInit;//CcnLAC initializing
};
//typedef struct ConnMgr_cls* ConnMgr;
ConnMgr ConnMgr_ctor(PollMgr pm, CcnCC cc);
void ConnMgr_dtor(ConnMgr self);
void ConnMgr_cmpRequest(ConnMgr self, CMPConn request);
void ConnMgr_run(ConnMgr self);//should be called after poll
//private begin
void ConnMgr_cmpConnect(ConnMgr self, CMPConn request);
void ConnMgr_cmpDisconnect(ConnMgr self, CMPConn request);
void ConnMgr_cmpList(ConnMgr self, CMPConn request);
LMD ConnMgr_prepareLMD(ConnMgr self, CMPConn request);//get or create LMD
void ConnMgr_checkInitReady(ConnMgr self);//check CcnLAC_ready, and start serving
//extensions to CMPConn_State
#define ConnMgrRecState_normal CMPConn_State_normal//inside pendingInit list
#define ConnMgrRecState_init 1001//inside pendingInit list
#define ConnMgrRecState_error CMPConn_State_error
struct ConnMgr_rec {
	ConnMgrRec next;//only used in linked list
	CMPConn cmpConn;
	int state;
	CcnLAC lac;
	Link link;
	NdnlpSvc svc;
};
ConnMgrRec ConnMgrRec_ctor(void);
void ConnMgrRec_dtor(ConnMgrRec self);
//private end


#endif//NDNLD_H
