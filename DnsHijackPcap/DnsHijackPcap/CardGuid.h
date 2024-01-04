



typedef struct CardInfo
{
	char		name[MAX_PATH];		// 接口名称(如:本地连接)
	char			guid[MAX_PATH];		// 网卡的GUID
	char			explain[MAX_PATH];	// 网卡的说明
	int			cardno;
}CardInfo;



class CardGuid  
{
public:
	CardGuid();
	~CardGuid();
	
	int			FindCard();
	void		DumpCardGuid();
	
protected:
	int			GetAllCardFromReg();

	int			m_cardcount;
	CardInfo*	m_pCardInfo;
		
};


