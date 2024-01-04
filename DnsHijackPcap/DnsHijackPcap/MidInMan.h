


#include <stdio.h>
#include <windows.h>
#include <winsock.h>
#include <winuser.h>
#include <openssl\\ssl.h>
#include <openssl\\err.h>


#define	PRIVATE_KEY_PWD		"1234"						// 私钥的密码
#define	CERT_FILE			"EXAMPLE.crt"				// 伪造的证书
#define	KEY_FILE			"EXAMPLE.key"				// 伪造证书的私钥
#define ROOT_CERT_FILE		"EXAMPLE.crt"



#define	SSL_PORT				443						
#define	HTTP_PORT				80	
#define XMPP_PORT				5222			
#define TV_USEC_VALUE			20000
#define	LISTEN_MAX				16	
#define HTTP_HOST_LIMIT_LENGTH	256

#define LOG_FILE				"HttpsMidInMan.log"
#define SSL_PROXY_FILE			"SSL_PROXY.dat"
#define HTTP_PROXY_FILE			"HTTP_PROXY.dat"
#define IMSG_PROXY_FILE			"IMSG_PROXY.dat"





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




typedef struct
{
	in_addr			ulFakeIP;
	unsigned short	usFakePort;
	in_addr			ulRealIP;
	unsigned short	usRealPort;
}SPECPROXYPARAM,*LPSPECPROXYPARAM;




int GetRealIPFromHttpHost(unsigned char * ucBuffer,int iCounter,unsigned long * ulHostIp);
int GetRealIPFromXmpp(unsigned char * ucBuffer,int iCounter,in_addr * iaToServer);

SOCKET InitFakeServer(unsigned short usPort);

int HTTPProxy(LPHTTPPROXYPARAM pstHttpProxyParam);

int HTTPListenThread();

int	SSLProxy(LPSSLPROXYPARAM pstSSLProxyParam);

int SSLListenThread();

int SPECProxy(LPIMSGPROXYPARAM pstImsgProxyParam);

int SPECListenThread(LPSPECPROXYPARAM pstSpecProxyParam);

int IMSGProxy(LPIMSGPROXYPARAM pstImsgProxyParam);

int IMSGListenThread(unsigned short ImsgPort);