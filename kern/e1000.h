#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H
#endif  // SOL >= 6

#include <kern/pci.h>

#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_RXPKTSIZE 1518

int pci_e1000_attach(struct pci_func *pcif);
void e1000_transmit_init();
void e1000_receive_init();
int e1000_transmit_packet(const void *buf, size_t size);
int e1000_receive_packet(void *buf, size_t size);;

/* PCI Vendor ID */
#define E1000_VENDOR_ID_82540EM 0x8086
/* PCI Device IDs */
#define E1000_DEV_ID_82540EM  0x100E

// tx 
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
#define E1000_CT_SHIFT              4

/* Collision distance is a 0-based value that applies to half-duplex-capable hardware only. */
#define E1000_COLLISION_DISTANCE    0x40
#define E1000_COLD_SHIFT            12

/* 13.43 */
/* Default values for the transmit IPG register */
#define E1000_DEFAULT_TIPG_IPGT     10
#define E1000_DEFAULT_TIPG_IPGR1    4
#define E1000_DEFAULT_TIPG_IPGR2    6
#define E1000_TIPG_IPGT_MASK        0x000003FF
#define E1000_TIPG_IPGR1_MASK       0x000FFC00
#define E1000_TIPG_IPGR2_MASK       0x3FF00000
#define E1000_TIPG_IPGR1_SHIFT      10
#define E1000_TIPG_IPGR2_SHIFT      20

#define E1000_TXD_CMD_EOP    0x01 /* End of Packet */
#define E1000_TXD_CMD_RS     0x08 /* Report Status */
#define E1000_TXD_STAT_DD    0x01 /* Descriptor Done */


#define E1000_IMS      0x000D0  /* Interrupt Mask Set - RW */
#define E1000_ICS      0x000C8  /* Interrupt Cause Set - WO */
#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RDTR     0x02820  /* RX Delay Timer - RW */
#define E1000_MTA      0x05200  /* Multicast Table Array - RW Array */
#define E1000_RA       0x05400  /* Receive Address - RW Array */


// rx
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */

#define E1000_RCTL_LBM_NO       0x00000000  /* no loopback mode */
#define E1000_RCTL_LBM_SHIFT    6

#define E1000_RCTL_RDMTS_HALF   0x00000000
#define E1000_RCTL_RDMTS_SHIFT  8

#define E1000_RCTL_SZ_2048      0x00000000  /* rx buffer size 2048 */
#define E1000_RCTL_SZ_SHIFT     16




// reset value by chap layout
/* Transmit Descriptor bit definitions chap 3.3.3.1 */ 

#define E1000_TXD_CMD_IFCS   0x02 /* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_IC     0x04 /* Insert Checksum */

#define E1000_TXD_CMD_RPS    0x10 /* Report Packet Sent */
#define E1000_TXD_CMD_DEXT   0x20 /* Descriptor extension (0 = legacy) */
#define E1000_TXD_CMD_VLE    0x40 /* Add VLAN tag */
#define E1000_TXD_CMD_IDE    0x80 /* Enable Tidv register */

#define E1000_TXD_STAT_EC    0x02 /* Excess Collisions */
#define E1000_TXD_STAT_LC    0x04 /* Late Collisions */
#define E1000_TXD_STAT_TU    0x08 /* Transmit underrun */



#define E1000_RXD_STAT_DD         0x01    /* Descriptor Done */

#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
// 这里是0x，Receive Control Bits是binary,需要转换,0x00000002-> 10(1bit)
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM            0x000000C0    /* no loopback mode */
#define E1000_RCTL_LBM_NO         0x00000000    /* no loopback mode */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */
#define E1000_RAH_AV              0x80000000    /* Receive descriptor valid */ 
#define E1000_RAL                 0x05400
#define E1000_RAH                 0x05404

#define E1000_RCTL_EN       0x00000002  /* enable */
// #define E1000_RCTL_LBM      0x000000c0  /* loopback mode */
#define E1000_RCTL_RDMTS    0x00000300  /* rx desc min threshold size */
#define E1000_RCTL_SZ       0x00030000  /* rx buffer size */
#define E1000_RCTL_SECRC    0x04000000  /* strip ethernet CRC */
#define E1000_RCTL_BSEX     0x02000000  /* Buffer size extension */





// 下面的参考 chap13
// transmit descriptor
struct e1000_tx_desc{
  uint64_t addr;
  uint16_t length;
  uint8_t cso;
  uint8_t cmd;
  uint8_t status;
  uint8_t css;
  uint16_t special;
}__attribute__((packed));




// receive descriptor
struct e1000_rx_desc {
  uint64_t addr;
  uint16_t length;
  uint16_t chksum;
  uint8_t  status;
  uint8_t  errors;
  uint16_t special;
}__attribute__((packed));












