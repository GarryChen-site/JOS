#include "ns.h"
#include "kern/e1000.h"

#define INPUT_BUFSIZE  2048

extern union Nsipc nsipcbuf;

// 不加或sleep时间少的时候，会提示少几个包 
void sleep(int msec){
  unsigned now = sys_time_msec(); 
  unsigned end = now + msec;

  if((int)now < 0 && (int)now > -MAXERROR){
    panic("sys_time_msec: %e", (int)now);  
  }

  if(end < now){
    panic("sleep: wrap");
  }

  while(sys_time_msec() < end){
    sys_yield();
  }
} 

void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// char inputbuf[E1000_RXPKTSIZE];
	// int len;
	uint8_t inputbuf[INPUT_BUFSIZE];
    	int r, i;

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.

	// while(1){

	// 	// read a packet from the device drive
	// 	while((sys_receive_packet(inputbuf, &len)) < 0){
	// 		sys_yield();
	// 	}

	// 	// send it to the network server
	// 	nsipcbuf.pkt.jp_len = len;
	// 	memcpy(nsipcbuf.pkt.jp_data, inputbuf,len);

	// 	ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_U | PTE_P | PTE_W);

	// 	// sys_yield();
	// 	sleep(50); 
	// }

	while (1) {
        	// clear the buffer
        	memset(inputbuf, 0, sizeof(inputbuf));

        	// read a packet from the device driver
        	while ((r = sys_receive_packet(inputbuf, sizeof(inputbuf))) == -E_RX_EMPTY) {
           	 	sys_yield();
        	}

        	// panic if inputbuf is too small
        	if (r < 0) {
            		panic("%s: inputbuf too small", binaryname);
        	}

        	// send it to the network server
        	nsipcbuf.pkt.jp_len = r;
        	memcpy(nsipcbuf.pkt.jp_data, inputbuf, r);
        	ipc_send(ns_envid, NSREQ_INPUT, &nsipcbuf, PTE_P | PTE_U);

		sleep(50);
    	}
}
	
