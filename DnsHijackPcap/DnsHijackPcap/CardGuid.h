



typedef struct CardInfo
{
	char		name[MAX_PATH];		// �ӿ�����(��:��������)
	char			guid[MAX_PATH];		// ������GUID
	char			explain[MAX_PATH];	// ������˵��
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


