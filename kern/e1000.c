#include <kern/e1000.h>
#include <kern/pmap.h>
#include <inc/string.h>

// LAB 6: Your driver code here

volatile void *e1000_mmio;
#define E1000REG(offset)  (void *)(e1000_mmio+offset)


static struct e1000_desc e1000_tx_queue[NTXDESC] __attribute__((aligned(16)));
static uint8_t e1000_tx_buf[NTXDESC][TX_BUF_SIZE];


int pci_e1000_attach(struct pci_func *pcif){
  pci_func_enable(pcif);

  e1000_mmio = (void *)mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
  cprintf("PCI E1000 status is 0x%x\n", *(uint32_t *)E1000REG(E1000_STATUS));
  return 1;
}   


void e1000_transmit_init() {

  // init tx queue
  int i;

  // memset(e1000_tx_queue,0, sizeof(e1000_tx_queue));

  for (i=0; i<NTXDESC; i++){
    // e1000_tx_queue[i].addr = PADDR(e1000_tx_buf[i]);
  }


}