
#include <windows.h>
#include <stdio.h>
#include "Public.h"


DWORD GetLocalIpAddress()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = {0};
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return FALSE;
	}

	char local[MAX_PATH] = {0};
	int iRet = gethostname(local, sizeof(local));
	if (iRet )
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = {0};
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr)); 
	if (addr.S_un.S_addr == 0)
	{
		return FALSE;
	}
	return addr.S_un.S_addr;
}


DWORD WriteLogFile(char * pData)
{
	HANDLE hFile = CreateFileA(LOGFILENAME,GENERIC_READ | GENERIC_WRITE,0,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile,0,0,FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int iDataSize = lstrlenA(pData);
	int iRet = WriteFile(hFile,pData,iDataSize,&dwCnt,0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != iDataSize)
	{
		return FALSE;
	}

	return TRUE;
}


DWORD WriteLogFile(char * pFileName,char * pData,DWORD dwDataSize)
{
	HANDLE hFile = CreateFileA(pFileName,GENERIC_READ | GENERIC_WRITE,0,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile,0,0,FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int iRet = WriteFile(hFile,pData,dwDataSize,&dwCnt,0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != dwDataSize)
	{
		return FALSE;
	}

	return TRUE;
}



int RecordInFile(char * szFileName,unsigned char * strBuffer,int iCounter)
{
	int iRet = 0;
	FILE * fpFile = 0;
	iRet = fopen_s(&fpFile,szFileName,"a");
	if (fpFile )
	{
		unsigned long ulFileSize = fseek(fpFile,0,SEEK_END);
		iRet = fwrite(strBuffer,1,iCounter,fpFile);
		if (iRet != iCounter)
		{
			fclose(fpFile);
			printf("写文件错误\n");
			return FALSE;
		}
		fclose(fpFile);
		return TRUE;
	}
	else if (fpFile == 0)
	{
		iRet = fopen_s(&fpFile,szFileName,"w");
		if (fpFile)
		{
			unsigned long ulFileSize = fseek(fpFile,0,SEEK_END);
			fwrite(strBuffer,1,iCounter,fpFile);	
			if (iRet != iCounter)
			{
				printf("写文件错误\n");
				fclose(fpFile);
				return FALSE;
			}
			fclose(fpFile);
			return TRUE;
		}
		else
		{
			printf("打开文件错误\n");
			return FALSE;
		}
	}
	return FALSE;
}