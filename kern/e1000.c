#include <kern/e1000.h>
#include <kern/pmap.h>
#include <inc/string.h>
#include <inc/error.h>

// LAB 6: Your driver code here

volatile void *e1000_mmio;
#define E1000REG(offset)  (*(volatile uint32_t *)(e1000_mmio+offset))


// tx
#define TX_BUF_SIZE 1536  // 16-byte aligned for performance
#define NTXDESC     32

static struct e1000_tx_desc e1000_tx_queue[NTXDESC] __attribute__((aligned(16)));
static uint8_t e1000_tx_buf[NTXDESC][TX_BUF_SIZE];



#define RX_BUF_SIZE 2048
#define NRXDESC     128

static struct e1000_rx_desc e1000_rx_queue[NRXDESC] __attribute__((aligned(16)));
static uint8_t e1000_rx_buf[NRXDESC][RX_BUF_SIZE];



// transmit descriptor queue
// struct e1000_tdesc e1000_tdesc_queue[E1000_MAXTXQUEUE];
// transmit paackets buffer
// char e1000_tx_pkt_buffer[E1000_MAXTXQUEUE][E1000_TXPKTSIZE];

// receive descriptor queue 
// struct e1000_rdesc e1000_rdesc_queue[E1000_MAXRXQUEUE];
// receive packets buffer
// char e1000_rx_pkt_buffer[E1000_MAXRXQUEUE][E1000_RXPKTSIZE];

// struct e1000_tdh *tdh;
// struct e1000_tdt *tdt;

// receive descriptor queue head & tail
// struct e1000_rdh *rdh;
// struct e1000_rdt *rdt;

// default mac address 52:54:00:12:34:56
#define MACADDR 0x563412005452

#define JOS_DEFAULT_MAC_LOW     0x12005452
#define JOS_DEFAULT_MAC_HIGH    0x00005634

uint32_t E1000_MAC[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};



int pci_e1000_attach(struct pci_func *pcif){
  // char *hello = "I'm here!";
  pci_func_enable(pcif);

  e1000_mmio = mmio_map_region(pcif->reg_base[0], pcif->reg_size[0]);
  cprintf("PCI E1000 status is 0x%x\n", E1000REG(E1000_STATUS));
  e1000_transmit_init();
  e1000_receive_init();
  // e1000_transmit_packet(hello, 9);
  // return 1;
  return 0;
}   


void 
e1000_transmit_init() {

int i;
memset(e1000_tx_queue, 0, sizeof(e1000_tx_queue));
for (i = 0; i < NTXDESC; i++) {
        e1000_tx_queue[i].addr = PADDR(e1000_tx_buf[i]);
}

    // initialize transmit descriptor registers
    E1000REG(E1000_TDBAL) = PADDR(e1000_tx_queue);
    E1000REG(E1000_TDBAH) = 0;

    E1000REG(E1000_TDLEN) = sizeof(e1000_tx_queue);

    E1000REG(E1000_TDH) = 0;
    E1000REG(E1000_TDT) = 0;

    // initialize transmit control registers
    E1000REG(E1000_TCTL) &= ~(E1000_TCTL_CT | E1000_TCTL_COLD);
    E1000REG(E1000_TCTL) |= E1000_TCTL_EN | E1000_TCTL_PSP |
                            (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT) |
                            (E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT);

    E1000REG(E1000_TIPG) &= ~(E1000_TIPG_IPGT_MASK | E1000_TIPG_IPGR1_MASK | E1000_TIPG_IPGR2_MASK);
    E1000REG(E1000_TIPG) |= E1000_DEFAULT_TIPG_IPGT |
                            (E1000_DEFAULT_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT) |
                            (E1000_DEFAULT_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT);

}

int e1000_transmit_packet(const void *buf, size_t size){

  int tail = E1000REG(E1000_TDT);

  if (size > E1000_RXPKTSIZE) {
    return -E_PKT_TOO_LARGE;
  }

  if ((e1000_tx_queue[tail].cmd & E1000_TXD_CMD_RS) && !(e1000_tx_queue[tail].status & E1000_TXD_STAT_DD)) {
        return -E_TX_FULL;
  }

  // clears the DD bit
  e1000_tx_queue[tail].status &= ~E1000_TXD_STAT_DD;
  memcpy(e1000_tx_buf[tail], buf, size);
  e1000_tx_queue[tail].length = size;
  // set RS, EOP command bit
  e1000_tx_queue[tail].cmd |= E1000_TXD_CMD_RS | E1000_TXD_CMD_EOP;

  E1000REG(E1000_TDT) = (tail + 1) % NTXDESC;

  return 0;

}


void e1000_receive_init() {

    // initialize rx queue
    int i;
    memset(e1000_rx_queue, 0, sizeof(e1000_rx_queue));
    for (i = 0; i < NRXDESC; i++) {
        e1000_rx_queue[i].addr = PADDR(e1000_rx_buf[i]);
    }


    // initialize receive address registers
    E1000REG(E1000_RAL) = JOS_DEFAULT_MAC_LOW;
    E1000REG(E1000_RAH) = JOS_DEFAULT_MAC_HIGH;
    E1000REG(E1000_RAH) |= E1000_RAH_AV;
    
    E1000REG(E1000_RDBAL) = PADDR(e1000_rx_queue);
    E1000REG(E1000_RDBAH) = 0;

    E1000REG(E1000_RDLEN) = sizeof(e1000_rx_queue);

    E1000REG(E1000_RDH) = 0;
    E1000REG(E1000_RDT) = NRXDESC - 1;

    E1000REG(E1000_RCTL) &= ~(E1000_RCTL_LBM | E1000_RCTL_RDMTS | E1000_RCTL_SZ | E1000_RCTL_BSEX);
    E1000REG(E1000_RCTL) |= E1000_RCTL_EN | E1000_RCTL_SECRC;

}

// *len_store used to keep track
int e1000_receive_packet(void *buf, size_t size){

  // When the head pointer is equal to the tail pointer, the ring is empty. 
  // Hardware stops storing packets in system memory until software advances the tail pointer, making more receive buffers available.
  // uint16_t tail = (rdt->rdt + 1) % E1000_MAXRXQUEUE;

  // if(!(e1000_rx_queue[tail].status & E1000_RXD_STAT_DD)){
  //   return -1;
  // }

  // *len_store = e1000_rx_queue[tail].length;
  // e1000_rx_queue[tail].status &= ~E1000_RXD_STAT_DD;
  // memcpy(data_store, e1000_rx_pkt_buffer[tail], *len_store);
  // rdt -> rdt = (tail) % E1000_MAXRXQUEUE;
    int tail = E1000REG(E1000_RDT);
    int next = (tail + 1) % NRXDESC;
    int length;

    if (!(e1000_rx_queue[next].status & E1000_RXD_STAT_DD)) {
        return -E_RX_EMPTY;
    }

    if ((length = e1000_rx_queue[next].length) > size) {
        return -E_PKT_TOO_LARGE;
    }

    memcpy(buf, e1000_rx_buf[next], length);
    e1000_rx_queue[next].status &= ~E1000_RXD_STAT_DD;

    E1000REG(E1000_RDT) = next;

    return length;
}
