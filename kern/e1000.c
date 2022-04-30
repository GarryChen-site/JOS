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

// receive descriptor queue 
struct e1000_rdesc e1000_rdesc_queue[E1000_MAXRXQUEUE];
// receive packets buffer
char e1000_rx_pkt_buffer[E1000_MAXRXQUEUE][E1000_RXPKTSIZE];

struct e1000_tdh *tdh;
struct e1000_tdt *tdt;

// receive descriptor queue head & tail
struct e1000_rdh *rdh;
struct e1000_rdt *rdt;

// default mac address 52:54:00:12:34:56
#define MACADDR 0x563412005452



int pci_e1000_attach(struct pci_func *pcif){
  // char *hello = "I'm here!";
  pci_func_enable(pcif);

  e1000_mmio = (void *)mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
  cprintf("PCI E1000 status is 0x%x\n", *(uint32_t *)E1000REG(E1000_STATUS));
  e1000_transmit_init();
  e1000_receive_init();
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

void e1000_receive_init() {
  int i;

  uint64_t *ra;
  uint64_t *mta;
  struct e1000_ims *ims;
  struct e1000_rdtr *rdtr;
  struct e1000_rdbal *rdbal;
  struct e1000_rdbah *rdbah;
  struct e1000_rdlen *rdlen;
  struct e1000_rctl *rctl;

    // pointers to buffers should be stored in the receive descriptor 
  for(i = 0; i < E1000_MAXRXQUEUE; i++){
    e1000_rdesc_queue[i].addr = PADDR(e1000_rx_pkt_buffer[i]);
  }

  // set the mac address
  ra = (uint64_t *)E1000REG(E1000_RA);
  *ra = (uint64_t)MACADDR| ((uint64_t)E1000_RAH_AV << 32);

  mta = (uint64_t *)E1000REG(E1000_MTA);
  *mta =  0x0;

  ims = (struct e1000_ims *)E1000REG(E1000_IMS);
  ims->ims = 0x0;

  // set receive descriptor base address low
  rdbal = (struct e1000_rdbal *)E1000REG(E1000_RDBAL);
  rdbal->rdbal = PADDR(e1000_rdesc_queue);
  // set receive descriptor base address high
  rdbah  = (struct e1000_rdbah *)E1000REG(E1000_RDBAH);
  rdbah->rdbah = 0;

  // set receive descriptor queue length
  rdlen = (struct e1000_rdlen *)E1000REG(E1000_RDLEN);
  rdlen->len = E1000_MAXRXQUEUE;

  // set receive descriptor queue head
  rdh = (struct e1000_rdh *)E1000REG(E1000_RDH);
  rdh->rdh = 0;
    
  // set receive desciptor queue tail 
  rdt = (struct e1000_rdt *)E1000REG(E1000_RDT);
  rdt->rdt = E1000_MAXRXQUEUE - 1;

  // set receiver control register
  rctl = (struct e1000_rctl *)E1000REG(E1000_RCTL);
  rctl->rcb |= E1000_RCTL_EN;
  rctl->rcb &= ~E1000_RCTL_LPE;
  rctl->rcb &= ~E1000_RCTL_LBM;

  rctl->rcb |=E1000_RCTL_BAM;
  rctl->rcb |= E1000_RCTL_SECRC;
}

// *len_store used to keep track
int e1000_receive_packet(char *data_store, int *len_store){

  // When the head pointer is equal to the tail pointer, the ring is empty. 
  // Hardware stops storing packets in system memory until software advances the tail pointer, making more receive buffers available.
  uint16_t tail = (rdt->rdt + 1) % E1000_MAXRXQUEUE;

  if(!(e1000_rdesc_queue[tail].status & E1000_RXD_STAT_DD)){
    return -1;
  }

  *len_store = e1000_rdesc_queue[tail].length;
  e1000_rdesc_queue[tail].status &= ~E1000_RXD_STAT_DD;
  memcpy(data_store, e1000_rx_pkt_buffer[tail], *len_store);
  rdt -> rdt = (tail) % E1000_MAXRXQUEUE;

  return 0;
}