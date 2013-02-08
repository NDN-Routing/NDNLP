

UNITTEST_SRCS = $(SRCS) unittest.c Utility.test.c CcnClient.test.c SeqNum.test.c NdnlpPkt.test.c MsgSlicer.test.c PartialMsg.test.c SentPkt.test.c Link.test.c
UNITTEST_LIBS = $(LIBS) -lcunit


unittest: $(UNITTEST_SRCS)
	$(CC) $(CFLAGS) -o unittest $(UNITTEST_SRCS) $(UNITTEST_LIBS)

rununittest: unittest
	LD_LIBRARY_PATH=/usr/local/lib ./unittest

