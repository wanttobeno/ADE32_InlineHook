#include "CDetour.h"

void *CDetour::memcpy_s ( void *pvAddress, const void *pvBuffer, size_t stLen )
{
	MEMORY_BASIC_INFORMATION	mbi;
	VirtualQuery( pvAddress, &mbi, sizeof(mbi) );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect );

	void	*pvRetn = memcpy( pvAddress, pvBuffer, stLen );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect );
	FlushInstructionCache( GetCurrentProcess(), pvAddress, stLen );
	return pvRetn;
}

void *CDetour::Create ( BYTE *orig, const BYTE *det, int iPatchType, int len )
{
	BYTE	*jmp = NULL;
	int		iMinLen = 0;

	if ( !(iMinLen = GetDetourLen(iPatchType)) )
		return 0;

	if ( len != 0 && len < iMinLen )
		return 0;

	// Try and find the end of the instruction automatically
	if ( len == 0 )
	{
		len = GetDetourLenAuto( orig, iMinLen );

		if ( len < iMinLen )
			return 0;
	}

	if ( !Detour(jmp, orig, det, iPatchType, len) )
		return 0;

	return jmp - len;
}

void *CDetour::Create ( char *dllName, char *apiName, const BYTE *det, int iPatchType, int len )
{
	BYTE	*jmp = NULL;
	BYTE	*orig = NULL;
	int		iMinLen = 0;

	if ( !(iMinLen = GetDetourLen(iPatchType)) )
		return 0;

	if ( len != 0 && len < iMinLen )
		return 0;

	// Get the API address
	m_hModule = GetModuleHandleA( dllName );
	m_dwAddress = ( DWORD ) GetProcAddress( m_hModule, apiName );

	if ( !m_dwAddress || !det )
		return 0;

	orig = (BYTE *)m_dwAddress;

	// Try and find the end of the instruction automatically
	if ( len == 0 )
	{
		len = GetDetourLenAuto( orig, iMinLen );

		if ( len < iMinLen )
			return 0;
	}

	if ( !Detour(jmp, orig, det, iPatchType, len) )
		return 0;

	return jmp - len;
}

bool CDetour::Detour ( BYTE * &jmp, BYTE * &orig, const BYTE * &det, int iPatchType, int len )
{
	DWORD	dwBack = 0;
	int		i = 0;
	BYTE	*pPatchBuf = NULL;

	// Allocate space for the jump
	jmp = (BYTE *)malloc( len + 5 );

	// Force page protection flags to read|write
	MEMORY_BASIC_INFORMATION	mbi;
	VirtualQuery( (void *)orig, &mbi, sizeof(mbi) );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect );

	// Copy the overwritten opcodes at the original to the malloced space
	memcpy( jmp, orig, len );

	// Increment to the end of the opcodes at the malloced space
	jmp += len;

	// Place a jump back to the original at this point
	jmp[0] = 0xE9;
	*( DWORD * ) ( jmp + 1 ) = ( DWORD ) ( orig + len - jmp ) - 5;

	// Generate a random opcode
	int		iTmpRnd = ( rand() * 0xFF ) + rand();
	BYTE	bTmpRnd = ( BYTE ) iTmpRnd;

	// Place a jump at the original to the detour function
	//pPatchBuf = new BYTE[len];
	pPatchBuf = (BYTE *)malloc(len);

	// Pad out the bytes with NOPs so we don't have ends of intructions
	memset( pPatchBuf, 0x90, len );

	// Write the opcodes to the buffer according to patch type
	switch ( iPatchType )
	{
	case DETOUR_TYPE_JMP:
		pPatchBuf[0] = '\xE9';
		*(DWORD *) &pPatchBuf[1] = ( DWORD ) ( det - orig ) - 5;
		break;

	case DETOUR_TYPE_PUSH_RET:
		pPatchBuf[0] = '\x68';
		*(DWORD *) &pPatchBuf[1] = ( DWORD ) det;
		pPatchBuf[5] = '\xC3';
		break;

	case DETOUR_TYPE_PUSH_FUNC:
		pPatchBuf[0] = '\x68';
		*(DWORD *) &pPatchBuf[1] = ( DWORD ) det;
		break;

	case DETOUR_TYPE_CALL_FUNC:
		pPatchBuf[0] = '\xE8';
		*(DWORD *) &pPatchBuf[1] = ( DWORD ) ( det - orig ) - 5;
		break;

	default:
		free(pPatchBuf);
		return false;
	}

	// Write the detour
	for ( i = 0; i < len; i++ )
		orig[i] = pPatchBuf[i];
	free(pPatchBuf);
	// Put the old page protection flags back
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect );

	FlushInstructionCache( GetCurrentProcess(), orig, len );

	return true;
}

bool CDetour::Remove ( BYTE *orig, BYTE *jmp, int iPatchType, int len )
{
	int		iMinLen = 0;
	DWORD	dwBack = 0;

	if ( !(iMinLen = GetDetourLen(iPatchType)) )
		return false;

	if ( len != 0 && len < iMinLen )
		return false;

	// Try and find the end of the instruction automatically
	if ( len == 0 )
	{
		len = GetDetourLenAuto( jmp, iMinLen );
		if ( len == 0 )
			len = GetDetourLen( iPatchType );
		if ( len == 0 || iMinLen == 0 )
			return false;
		if ( len < iMinLen )
			return false;
	}

	// Write the bytes @ the jmp back to the orig
	MEMORY_BASIC_INFORMATION	mbi;
	VirtualQuery( (void *)orig, &mbi, sizeof(mbi) );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect );
	memcpy( orig, jmp, len );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect );
	FlushInstructionCache( GetCurrentProcess(), (void *)orig, len );

	return true;
}

bool CDetour::RestoreFunction ( BYTE *func, int len )
{
	MEMORY_BASIC_INFORMATION	mbi;
	bool						bRet = false;
	VirtualQuery( (void *)func, &mbi, sizeof(mbi) );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect );
	memcpy( (void *)func, (void *)bBackup, len );
	if ( *(BYTE *)func == (BYTE) bBackup[0] )
	{
		bRet = true;
	}
	else
	{
		bRet = false;
	}

	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect );
	FlushInstructionCache( GetCurrentProcess(), (void *)func, len );
	return bRet;
}

bool CDetour::BackupFunction ( BYTE *func, int len )
{
	MEMORY_BASIC_INFORMATION	mbi;
	bool						bRet = false;
	VirtualQuery( (void *)func, &mbi, sizeof(mbi) );
	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect );
	memcpy( (void *)bBackup, (void *)func, len );
	if ( (BYTE) bBackup[0] == * (BYTE *)func )
	{
		bRet = true;
	}
	else
	{
		bRet = false;
	}

	VirtualProtect( mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect );
	FlushInstructionCache( GetCurrentProcess(), (void *)func, len );
	return bRet;
}

bool CDetour::Remove ( char *dllName, char *apiName, BYTE *jmp, int iPatchType, int len )
{
	DWORD	dwBack = 0;
	BYTE	*orig = NULL;
	int		iMinLen = 0;

	// Get the API address
	m_hModule = GetModuleHandleA( dllName );
	m_dwAddress = ( DWORD ) GetProcAddress( m_hModule, apiName );

	if ( !m_dwAddress || !jmp )
		return false;

	orig = (BYTE *)m_dwAddress;

	if ( !(iMinLen = GetDetourLen(iPatchType)) )
		return false;

	if ( len != 0 && len < iMinLen )
		return false;

	// Try and find the end of the instruction automatically
	if ( len == 0 )
	{
		len = GetDetourLenAuto( jmp, iMinLen );

		if ( len < iMinLen )
			return 0;
	}

	// Write the bytes @ the jmp back to the orig
	VirtualProtect( orig, len, PAGE_READWRITE, &dwBack );
	memcpy( orig, jmp, len );
	VirtualProtect( orig, len, dwBack, &dwBack );

	return true;
}

int CDetour::GetDetourLen ( int iPatchType )
{
	switch ( iPatchType )
	{
	case DETOUR_TYPE_JMP:
	case DETOUR_TYPE_PUSH_FUNC:
	case DETOUR_TYPE_CALL_FUNC:
		return 5;

	case DETOUR_TYPE_PUSH_RET:
		return 6;

	default:
		return 0;
	}
}

int CDetour::GetDetourLenAuto ( BYTE * &orig, int iMinLen )
{
	int		tmpLen = 0;
	BYTE	*pCurOp = orig;

	while ( tmpLen < iMinLen )
	{
		int i = oplen( pCurOp );

		if ( i == 0 || i == -1 )
			return false;

		tmpLen += i;
		pCurOp += i;
	}

	return tmpLen;
}