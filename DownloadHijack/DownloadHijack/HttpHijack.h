#ifndef SSLHIJACK_H_H_H
#define SSLHIJACK_H_H_H


#include "include\\openssl\\ssl.h"
#include "include\\openssl\\err.h"

#define	PRIVATE_KEY_PWD		"sata19820521"				// 私钥的密码
#define	CERT_FILE			"..\\example.crt"				// 伪造的证书
#define	KEY_FILE			"..\\example.key"				// 伪造证书的私钥
//#define	CERT_FILE			"..\\key\\证书文件.crt"				// 伪造的证书
//#define	KEY_FILE			"..\\key\\www.jinyavip.com.key"				// 伪造证书的私钥

#define	SSL_PORT				443								
#define TV_USEC_VALUE			20000
#define	LISTEN_MAX				16


#define LOG_FILE				"HttpsMidInMan.log"
#define SSL_PROXY_FILE			"SSL_PROXY.dat"
#define HTTP_PROXY_FILE			"HTTP_PROXY.dat"






typedef struct  
{
	sockaddr_in			saToClient;
	SOCKET				sockToClient;
	sockaddr_in			saToServer;
	SOCKET				sockToServer;
	unsigned long		ulThreadID;
	HANDLE				hThread;
}HTTPPROXYPARAM, * LPHTTPPROXYPARAM;


typedef struct  
{
	sockaddr_in			saToClient;
	SOCKET				sockToClient;
	sockaddr_in			saToServer;
	SOCKET				sockToServer;
	unsigned long		ulThreadID;
	HANDLE				hThread;
	unsigned short		usServerPort;
}IMSGPROXYPARAM, * LPIMSGPROXYPARAM;


typedef struct  
{
	sockaddr_in			saToClient;
	SOCKET				sockToClient;
	sockaddr_in			saToServer;
	SOCKET				sockToServer;
	SSL	*				SSLToClient;
	SSL *				SSLToServer;
	SSL_CTX	*			ctxToServer;
	SSL_CTX	*			ctxToClient;
	unsigned long		ulThreadID;
	HANDLE				hThread;
}SSLPROXYPARAM, * LPSSLPROXYPARAM;

int	__stdcall SSLProxy(LPSSLPROXYPARAM pstSSLProxyParam);
int __stdcall SSLListenThread();
int __stdcall HTTPListenThread();
int __stdcall HTTPProxy(LPHTTPPROXYPARAM pstHttpProxyParam);
#endif