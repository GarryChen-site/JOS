#include <kern/e1000.h>
#include <kern/pmap.h>
#include <inc/string.h>

// LAB 6: Your driver code here

volatile void *e1000_mmio;
#define E1000REG(offset)  (void *)(e1000_mmio+offset)

// transmit descriptor queue
struct e1000_tdesc e1000_tdesc_queue[E1000_MAXTXQUEUE];

// transmit paackets buffer
char e1000_tx_pkt_buffer[E1000_MAXTXQUEUE][E1000_TXPKTSIZE];

struct e1000_tdh *tdh;
struct e1000_tdt *tdt;

int pci_e1000_attach(struct pci_func *pcif){
  // char *hello = "I'm here!";
  pci_func_enable(pcif);

  e1000_mmio = (void *)mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
  cprintf("PCI E1000 status is 0x%x\n", *(uint32_t *)E1000REG(E1000_STATUS));
  e1000_transmit_init();
  // e1000_transmit_packet(hello, 9);
  return 1;
}   


void e1000_transmit_init() {

  // init tx queue
  int i;

  struct e1000_tdbal *tdbal;
  struct e1000_tdbah *tdbah;
  struct e1000_tdlen *tdlen;
  struct e1000_tctl *tctl;
  struct e1000_tipg *tipg;

  for (i=0; i<E1000_MAXTXQUEUE; i++){
    e1000_tdesc_queue[i].addr = PADDR(e1000_tx_pkt_buffer[i]);
    // chap 3.3.3
    e1000_tdesc_queue[i].cmd  |= E1000_TXD_CMD_RS;
    e1000_tdesc_queue[i].status |= E1000_TXD_STAT_DD;
  }

  tdbal = (struct e1000_tdbal *)E1000REG(E1000_TDBAL);
  tdbal->tdbal = PADDR(e1000_tdesc_queue);

  tdbah = (struct e1000_tdbah *)E1000REG(E1000_TDBAH);
  tdbah->tdbah = 0;

  tdlen = (struct e1000_tdlen *)E1000REG(E1000_TDLEN);
  tdlen->len = E1000_MAXTXQUEUE;

  tdh = (struct e1000_tdh *)E1000REG(E1000_TDH);
  tdh->tdh = 0;

  tdt = (struct e1000_tdt *)E1000REG(E1000_TDT);
  tdt->tdt = 0;

  tctl = (struct e1000_tctl *)E1000REG(E1000_TCTL);
  tctl->en = 1;
  tctl->psp = 1;
  tctl->ct = 0x10;
  tctl->cold = 0x40;

  tipg = (struct e1000_tipg *)E1000REG(E1000_TIPG);
  tipg->ipgt = 10;
  tipg->ipgr1 = 4;
  tipg->ipgr2 = 6;

}

int e1000_transmit_packet(char *data, int len){

  uint16_t tail = tdt->tdt;

  // the transmit queue is full
  if(!(e1000_tdesc_queue[tail].status & E1000_TXD_STAT_DD)){
    return -1;
  }

  e1000_tdesc_queue[tail].length = len;
  e1000_tdesc_queue[tail].status &= ~E1000_TXD_STAT_DD;
  e1000_tdesc_queue[tail].cmd |= (E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS);
  memcpy(e1000_tx_pkt_buffer[tail], data, len);
  tdt->tdt = (tail + 1) % E1000_MAXTXQUEUE;

  return 0;
}