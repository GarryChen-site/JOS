#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H
#endif  // SOL >= 6

#include <kern/pci.h>

#define E1000_STATUS   0x00008  /* Device Status - RO */

int pci_e1000_attach(struct pci_func *pcif);
void e1000_transmit_init();
int e1000_transmit_packet(char *data, int len);

/* transmit queue */
#define E1000_MAXTXQUEUE 56
#define E1000_TXPKTSIZE 1518

/* PCI Vendor ID */
#define E1000_VENDOR_ID_82540EM 0x8086
/* PCI Device IDs */
#define E1000_DEV_ID_82540EM  0x100E

#define E1000_TCTL     0x00400  /* TX Control - RW */
#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */

/* Transmit Control */
#define E1000_TCTL_EN   0x00000002  /* enable tx */
#define E1000_TCTL_PSP  0x00000008  /* pad short packets */
#define E1000_TCTL_CT   0x00000ff0  /* collision threshold */
#define E1000_TCTL_COLD 0x003ff000  /* collision distance */

/* Collision related configuration parameters */
#define E1000_COLLISION_THRESHOLD   0x10

/* Collision distance is a 0-based value that applies to half-duplex-capable hardware only. */
#define E1000_COLLISION_DISTANCE    0x40

/* 13.43 */
/* Default values for the transmit IPG register */
#define E1000_DEFAULT_TIPG_IPGT     10
#define E1000_DEFAULT_TIPG_IPGR1    4
#define E1000_DEFAULT_TIPG_IPGR2    6

// reset value by chap layout
/* Transmit Descriptor bit definitions */
#define E1000_TXD_CMD_EOP    0x01 /* End of Packet */
#define E1000_TXD_CMD_IFCS   0x02 /* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_IC     0x04 /* Insert Checksum */
#define E1000_TXD_CMD_RS     0x08 /* Report Status */
#define E1000_TXD_CMD_RPS    0x10 /* Report Packet Sent */
#define E1000_TXD_CMD_DEXT   0x20 /* Descriptor extension (0 = legacy) */
#define E1000_TXD_CMD_VLE    0x40 /* Add VLAN tag */
#define E1000_TXD_CMD_IDE    0x80 /* Enable Tidv register */
#define E1000_TXD_STAT_DD    0x01 /* Descriptor Done */
#define E1000_TXD_STAT_EC    0x02 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x04 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x08 /* Transmit underrun */


// 下面的参考 chap13
// transmit descriptor
struct e1000_tdesc{
  uint64_t addr;
  uint16_t length;
  uint8_t cso;
  uint8_t cmd;
  uint8_t status;
  uint8_t css;
  uint16_t special;
}__attribute__((packed));


// transmit descriptor base address low
struct e1000_tdbal{
  uint32_t tdbal;
};

// transmit descriptor base address high
struct e1000_tdbah{
  uint32_t tdbah;
};

// transmit descriptor length
struct e1000_tdlen{
  uint32_t zero     : 7;
  uint32_t len      : 13;
  uint32_t reserved : 12;
};

// transmit descriptor head
struct e1000_tdh{
  uint16_t tdh;
  uint16_t reserved;
};

// transmit descriptor tail
struct e1000_tdt{
  uint16_t tdt;
  uint16_t reserved;
};

// transmit control
struct e1000_tctl{
  uint32_t        : 1;
  uint32_t en     : 1;
  uint32_t        : 1;
  uint32_t psp    : 1;
  uint32_t ct     : 8;
  uint32_t cold   : 10;
  uint32_t swxoff : 1;
  uint32_t        : 1;
  uint32_t rtlc   : 1;
  uint32_t nrtu   : 1;
  uint32_t        : 6;
};

// transmit IPG
struct e1000_tipg{
  uint32_t ipgt     : 10;
  uint32_t ipgr1    : 10;
  uint32_t ipgr2    : 10;
  uint32_t reserved : 2;
};






