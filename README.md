# Named Data Networking Link Protocol

NDNLP is a link protocol for delivering CCNx messages over a local one-hop link.

NDNLP provides the following two features:

* Fragmentation and Reassembly
* Acknowledgement and Retransmission

ndnld/ is an implementation of NDNLP to use with CCNx on linux.

Read [NDN Technical Report NDN-0006](http://www.named-data.org/techreport/TR006-LinkProtocol.pdf) for more details.

## USAGE
### Install
1. `cd ndnld/`
2. `make`
3. `sudo make install`

### Start
1. `ccndstart`
2. `ndnld`  
	The program will daemonize itself.

### Stop
1. `killall ndnld`

### Uninstall
1. `cd ndnld/`
2. `sudo make uninstall`

## CONFIGURATION
`ndnldc` is a command-line utility to configure `ndnld`.

`ndnldc` should be called *after* starting `ndnld`.
Configuration does not persist after `ndnld` is restarted.

### Create UDP Connection
Commands to create a UDP connection between r1 (`192.0.2.1`) and r2 (`192.0.2.2`):

	ndn@r1:~$ ndnldc -c -p udp -h 192.0.2.2
	ndn@r2:~$ ndnldc -c -p udp -h 192.0.2.1

*FaceID* will be echoed back.

### Create Ethernet Connection
Commands to create a Ethernet connection between r1 (`08:00:27:01:01:01`) and r2 (`08:00:27:01:01:02`), where both routers use `eth1` interface to communicate:

	ndn@r1:~$ ndnldc -c -p ether -h 08:00:27:01:01:02 -i eth1
	ndn@r2:~$ ndnldc -c -p ether -h 08:00:27:01:01:01 -i eth1

*FaceID* will be echoed back.

### Register a Prefix
Commands to register a prefix on FaceID 11:

	ndn@r1:~$ ndnldc -r -f 11 -n ccnx:/example

### Other Commands
Please read section 3.4 of [technical report](http://www.named-data.org/techreport/TR006-LinkProtocol.pdf).


