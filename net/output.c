#include "ns.h"

extern union Nsipc nsipcbuf;

void
output(envid_t ns_envid)
{
	binaryname = "ns_output";

	int r;

	envid_t from_env;
	int perm;
	struct jif_pkt *pkt;

	// LAB 6: Your code here:
	// 	- read a packet from the network server
	//	- send the packet to the device driver

	while(1){
		// read a packet from the network server
		r = ipc_recv(&from_env, &nsipcbuf, &perm);

		// ignore non-NSREQ_OUTPUT IPC requests
		if(r != NSREQ_OUTPUT){
			continue;
		}

		// send the packet to the device driver
        	// if tx queue is full, simply wait
		while ((r = sys_transmit_packet(nsipcbuf.pkt.jp_data, nsipcbuf.pkt.jp_len)) == -E_TX_FULL) {
            		sys_yield();
        	}
		
		if (r < 0) {
            	// ignore oversized packets
            		if (r == -E_PKT_TOO_LARGE) {
                		cprintf("%s: packet too large (%d bytes), ingored\n", binaryname, nsipcbuf.pkt.jp_len);
                		continue;
            		} else {
                		panic("%s: sys_transmit_packet(): unexpected return value %d", binaryname, r);
            		}
		}
        
	}
}
