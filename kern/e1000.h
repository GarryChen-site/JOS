#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H
#endif  // SOL >= 6

#include <kern/pci.h>

#define E1000_STATUS   0x00008  /* Device Status - RO */

int pci_e1000_attach(struct pci_func *pcif);
void e1000_transmit_init();
void e1000_receive_init();
int e1000_transmit_packet(char *data, int len);
int e1000_receive_packet(char *data_store, int *len_store);;

/* transmit queue */
#define E1000_MAXTXQUEUE 32
#define E1000_TXPKTSIZE 1518

/* receive queue */
#define E1000_MAXRXQUEUE 256
#define E1000_RXPKTSIZE 1518

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

#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RDTR     0x02820  /* RX Delay Timer - RW */
#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RA       0x05400  /* Receive Address - RW Array */

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

#define E1000_RXD_STAT_DD         0x01    /* Descriptor Done */
// 这里是0x，Receive Control Bits是binary,需要转换,0x00000002-> 10
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM            0x000000C0    /* no loopback mode */
#define E1000_RCTL_LBM_NO         0x00000000    /* no loopback mode */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */
#define E1000_RAH_AV              0x80000000    /* Receive descriptor valid */ 


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


// receive descriptor
struct e1000_rdesc {
  uint64_t addr;
  uint16_t length;
  uint16_t cksum;
  uint8_t  status;
  uint8_t  errors;
  uint16_t special;
}__attribute__((packed));

// receive descriptor base address low 
struct e1000_rdbal{
  uint32_t rdbal;
};

// receive descriptor base address high
struct e1000_rdbah{
  uint32_t rdbah;
};


// receive descriptor length
struct e1000_rdlen{
  uint32_t zero     : 7;
  uint32_t len      : 13;
  uint32_t reserved : 12;

};

// receive descriptor head
struct e1000_rdh{
    uint16_t rdh;
    uint16_t reserved;
};

// receive descriptor tail
struct e1000_rdt{
  uint16_t rdt;
  uint16_t reserved;
};


// receive control register
struct e1000_rctl{
  uint32_t rcb      : 27;
  uint32_t reserved : 5;
};

// interrupt mask set 
struct e1000_ims{
  uint16_t  ims;
  uint16_t  reserved;
};


// receive delay timer register
struct e1000_rdtr{
  uint16_t dtimer;
  uint16_t      : 15;
  uint16_t  fpd : 1;
};











