#ifndef WINPCAPDNSHIJACK_H_H_H
#define WINPCAPDNSHIJACK_H_H_H




#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

WORD CalcChecksum(WORD *buffer,int size);
USHORT GetUdpCheckSum(LPUDPHEADER pUdp,DWORD dwSrcIP,DWORD dwDstIP);
int __stdcall DnsSnifferHijack(pcap_t * pcapT);


#endif