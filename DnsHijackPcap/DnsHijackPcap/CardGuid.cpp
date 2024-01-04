
#include "CardGuid.h"
#include <pcap.h>
#include <winreg.h>
#pragma comment(lib,"advapi32.lib")


CardGuid::CardGuid()
{
	m_cardcount = -1;
	m_pCardInfo = NULL;
}

CardGuid::~CardGuid()
{
	delete[] m_pCardInfo;
}

void CardGuid::DumpCardGuid()
{
	for(int i = 0; i<m_cardcount; i++)
	{
		printf("%d. Name:%s\n%s\n%s\n", i+1,
			m_pCardInfo[i].name,
			m_pCardInfo[i].guid,
			m_pCardInfo[i].explain);
	}
}

int CardGuid::FindCard()
{
	char ebuf[PCAP_ERRBUF_SIZE];
	int cardnum;
	m_pCardInfo=NULL;
	pcap_if_t *devpointer;
	
	if (pcap_findalldevs(&devpointer, ebuf) < 0)
		return 0;
	
	for (cardnum=0; devpointer != 0; cardnum++)
	{
		if ((cardnum & 7) == 0)
		{
			CardInfo* tp = new CardInfo[cardnum+8];
			for (int m = 0; m < cardnum; m++)
			{
				tp[m] = m_pCardInfo[m];
			}
			delete[] m_pCardInfo;
			m_pCardInfo = tp;
		}
		m_pCardInfo[cardnum].guid=devpointer->name;

		if (devpointer->description != NULL)
		{
			m_pCardInfo[cardnum].explain=devpointer->description;
		}
		devpointer = devpointer->next;
	}
	m_cardcount=cardnum;
	GetAllCardFromReg();

	return TRUE; 
}

int CardGuid::GetAllCardFromReg()
{
	HKEY hLocKey;
	HKEY hLocKey1;
	char  lpName[500];
	char  lpSubKeyName[500];
	char  lpValue[500];
	unsigned long num=300;
	DWORD ValueType;
	int j=0;
	char  cardstring[500];
	
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\NetWork\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\", 0,KEY_READ, &hLocKey)==ERROR_SUCCESS)
		
	{
		for(int i=0; i<100; i++)
		{
			if(RegEnumKey(hLocKey, i, lpName, 300)==ERROR_SUCCESS)
			{
				sprintf(lpSubKeyName, 
					"System\\CurrentControlSet\\Control\\NetWork\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection\\", 
					lpName);
				sprintf(cardstring, "\\Device\\NPF_%s", lpName);
				for(int m=0;m<m_cardcount;m++)
				{
					if (strcmp(cardstring,m_pCardInfo[m].guid)==0)
					{
						if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKeyName,0,KEY_READ,&hLocKey1)==ERROR_SUCCESS)
						{
							num =300;
							if(RegQueryValueEx(
								hLocKey1,
								"Name",
								NULL,
								&ValueType,
								(unsigned char*)lpValue,
								&num
								)==ERROR_SUCCESS)
								
							{
								m_pCardInfo[m].name.Format("%s",lpValue);
								m_pCardInfo[m].cardno = j++;
							}
							
							RegCloseKey(hLocKey1);
						}
						break;
					}
				}

			}
			else
			{
				RegCloseKey(hLocKey);
				return 0;
			}
		}
		RegCloseKey(hLocKey);
		return 0;
	}
	else
	{
		return 0;
	}
}
