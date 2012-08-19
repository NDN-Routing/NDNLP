CC = cc
CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes -D_BSD_SOURCE -std=gnu99 -I/usr/local/include/
LIBS = -lccn -lcrypto -B/usr/local/lib/
SRCS = Utility.c CcnClient.c SeqNum.c NdnlpPkt.c DataPkt.c AckPkt.c MsgSlicer.c PartialMsg.c SentPkt.c AckQueue.c Link.c NdnlpSvc.c ConnMgmt.c

PROGRAMS = ndnlink ndnld ndnldc unittest
INSTALL_PATH=/usr/local/bin/
INSTALL_PROGRAMS=ndnld ndnldc ndnlink
INSTALL_SETUID=ndnld ndnlink

NDNLINK_SRCS = $(SRCS) ndnlink.c
NDNLINK_LIBS = $(LIBS)
NDNLD_SRCS = $(SRCS) ndnld.c
NDNLD_LIBS = $(LIBS)
NDNLDC_SRCS = $(SRCS) ndnldc.c
NDNLDC_LIBS = $(LIBS)
UNITTEST_SRCS = $(SRCS) unittest.c Utility.test.c CcnClient.test.c SeqNum.test.c NdnlpPkt.test.c MsgSlicer.test.c PartialMsg.test.c SentPkt.test.c Link.test.c
UNITTEST_LIBS = $(LIBS) -lcunit

all: $(INSTALL_PROGRAMS)

ndnlink: $(NDNLINK_SRCS)
	$(CC) $(CFLAGS) -o ndnlink $(NDNLINK_SRCS) $(NDNLINK_LIBS)

ndnld: $(NDNLD_SRCS)
	$(CC) $(CFLAGS) -o ndnld $(NDNLD_SRCS) $(NDNLD_LIBS)

ndnldc: $(NDNLDC_SRCS)
	$(CC) $(CFLAGS) -o ndnldc $(NDNLDC_SRCS) $(NDNLDC_LIBS)

unittest: $(UNITTEST_SRCS)
	$(CC) $(CFLAGS) -o unittest $(UNITTEST_SRCS) $(UNITTEST_LIBS)

rununittest: unittest
	LD_LIBRARY_PATH=/usr/local/lib ./unittest

install: $(INSTALL_PROGRAMS)
	killall $(INSTALL_PROGRAMS) || true
	cp $(INSTALL_PROGRAMS) $(INSTALL_PATH)
	cd $(INSTALL_PATH); chown root:0 $(INSTALL_PROGRAMS); chmod 4755 $(INSTALL_SETUID)

uninstall:
	cd $(INSTALL_PATH); rm -f $(INSTALL_PROGRAMS)

clean:
	rm -f *.o CUnit*.xml
	rm -f $(PROGRAMS)

