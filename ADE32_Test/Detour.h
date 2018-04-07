#ifndef __DETOUR__
#define __DETOUR__

class Detour_c
{
	public:
		 Detour_c(DWORD cdwOldAddress, DWORD cdwMyAddress);
		~Detour_c();

	private:
		int OpcodeLen;
		BYTE PatchBackup[16];
		DWORD dwTempProtect[2];
		DWORD dwOldAddress;
		DWORD dwNewAddress;
		DWORD dwMyAddress;

	public:
		DWORD   SetupDetour(void);
		BOOLEAN RemoveDetour(void);
		BOOLEAN RemakeDetour(void);
};

#endif