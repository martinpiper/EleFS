#ifndef _BLOBFILELIB_FILECRYPTO_H_
#define _BLOBFILELIB_FILECRYPTO_H_

#include <windows.h>

namespace BlobFileLib
{
	/// Manages transparent file crypto operations
	class FileCrypto
	{
	public:
		BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

		BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
	}; //< class BlobFile

}; //< namespace BlobFileLib

#endif
