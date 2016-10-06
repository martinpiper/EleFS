#include <windows.h>
#include <assert.h>
#include "BlobFileLib/Inc/FileCrypto.h"
#include "RNPlatform/Inc/Encryption.h"

namespace BlobFileLib
{

static LONGLONG GetFilePointerEx(HANDLE hFile)
{
	LARGE_INTEGER liOfs={0};
	LARGE_INTEGER liNew={0};
	SetFilePointerEx(hFile, liOfs, &liNew, FILE_CURRENT);
	return liNew.QuadPart;
}

LARGE_INTEGER MakeLarge(LONGLONG value)
{
	LARGE_INTEGER ret;
	ret.QuadPart = value;
	return ret;
}

FileCrypto::FileCrypto() : mTempBuffer(0) , mEncryptedBlockSize(0) , mKeyData(0) , mKeyDataLength(0)
{
	SetEncryptedBlockSize();
}

FileCrypto::~FileCrypto()
{
	free (mTempBuffer);
}

void FileCrypto::SetEncryptedBlockSize(const DWORD byteSize)
{
	free (mTempBuffer);
	mTempBuffer = 0;

	mEncryptedBlockSize = byteSize;
}

void FileCrypto::SetKeyData(const void *keyData , const size_t keyDataLength)
{
	mKeyData = keyData;
	mKeyDataLength = keyDataLength;
}

static const int extraTwist = 0xf7139b7;

BOOL FileCrypto::ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	if (!mEncryptedBlockSize || !mKeyData || !mKeyDataLength)
	{
		return ::ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, 0);
	}

	if (!mTempBuffer)
	{
		mTempBuffer = (char *) calloc(1 , mEncryptedBlockSize);
	}

	LONGLONG fpos = GetFilePointerEx(hFile);

	LONGLONG roundedPos = fpos & (~(LONGLONG)(mEncryptedBlockSize-1));
	DWORD insideBlockOffset = (DWORD)(fpos & (mEncryptedBlockSize-1));

	DWORD totalToTransfer = nNumberOfBytesToRead;
	DWORD totalRead = 0;
	while (totalToTransfer > 0)
	{
		LONGLONG roundedPos2 = (roundedPos * extraTwist) ^ extraTwist ^ (roundedPos>>3);
		// First fill the buffer with aligned data
		DWORD bytesRead;
		SetFilePointerEx(hFile , MakeLarge(roundedPos) , 0 , FILE_BEGIN);
		if (!::ReadFile(hFile, mTempBuffer, mEncryptedBlockSize, &bytesRead, 0))
		{
			return FALSE;
		}
		if ( (bytesRead == 0) || (bytesRead < insideBlockOffset))
		{
			break;
		}
		totalRead += bytesRead - insideBlockOffset;

		RNReplicaNet::Encryption::Key key;
		key.Create(mKeyData,mKeyDataLength);
		key.AddCrypto(&roundedPos2 , sizeof(roundedPos2));

		// Decrypt the data found in the block
		RNReplicaNet::Encryption::CommutativeDecrypt(mTempBuffer , bytesRead , &key);
		RNReplicaNet::Encryption::Decrypt(mTempBuffer , bytesRead , &key);

		// Copy the information into the buffers at the correct offset
		DWORD toCopy = min(totalToTransfer , mEncryptedBlockSize - insideBlockOffset);
		CopyMemory(lpBuffer , mTempBuffer + insideBlockOffset , toCopy);

		totalToTransfer -= toCopy;
		lpBuffer = ((char*)lpBuffer) + toCopy;

		roundedPos += mEncryptedBlockSize;
		insideBlockOffset = 0;
	}

	SetFilePointerEx(hFile , MakeLarge(fpos  + totalRead) , 0 , FILE_BEGIN);

	if (lpNumberOfBytesRead)
	{
		*lpNumberOfBytesRead = totalRead;
	}

	return TRUE;
}

BOOL FileCrypto::WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	if (!mEncryptedBlockSize || !mKeyData || !mKeyDataLength)
	{
		return ::WriteFile(hFile , lpBuffer , nNumberOfBytesToWrite , lpNumberOfBytesWritten , 0);
	}

	if (!mTempBuffer)
	{
		mTempBuffer = (char *) calloc(1 , mEncryptedBlockSize);
	}

	LONGLONG fpos = GetFilePointerEx(hFile);

	LONGLONG roundedPos = fpos & (~(LONGLONG)(mEncryptedBlockSize-1));
	DWORD insideBlockOffset = (DWORD)(fpos & (mEncryptedBlockSize-1));

	DWORD totalToTransfer = nNumberOfBytesToWrite;
	while (totalToTransfer > 0)
	{
		LONGLONG roundedPos2 = (roundedPos * extraTwist) ^ extraTwist ^ (roundedPos>>3);
		// First fill the buffer with aligned data
		DWORD bytesRead;
		SetFilePointerEx(hFile , MakeLarge(roundedPos) , 0 , FILE_BEGIN);
		// Try to read up to a full aligned buffer
		if (!::ReadFile(hFile, mTempBuffer, mEncryptedBlockSize, &bytesRead, 0))
		{
			return FALSE;
		}

		RNReplicaNet::Encryption::Key key;
		key.Create(mKeyData,mKeyDataLength);
		key.AddCrypto(&roundedPos2 , sizeof(roundedPos2));

		// Decrypt the data read in the block
		if (bytesRead > 0)
		{
			RNReplicaNet::Encryption::CommutativeDecrypt(mTempBuffer , bytesRead , &key);
			RNReplicaNet::Encryption::Decrypt(mTempBuffer , bytesRead , &key);
		}

		// Copy the information into the buffers at the correct offset
		DWORD toCopy = min(totalToTransfer , mEncryptedBlockSize - insideBlockOffset);
		CopyMemory(mTempBuffer + insideBlockOffset , lpBuffer ,  toCopy);

		// Now encrypt the output block
		DWORD toChunk = max( min(totalToTransfer + insideBlockOffset , mEncryptedBlockSize) , bytesRead);
		RNReplicaNet::Encryption::Encrypt(mTempBuffer , toChunk , &key);
		RNReplicaNet::Encryption::CommutativeEncrypt(mTempBuffer , toChunk , &key);

		// Write out the first block again
		SetFilePointerEx(hFile , MakeLarge(roundedPos) , 0 , FILE_BEGIN);
		if (!::WriteFile(hFile, mTempBuffer, toChunk, 0 , 0))
		{
			return FALSE;
		}
	
		totalToTransfer -= toCopy;
		lpBuffer = ((char*)lpBuffer) + toCopy;

		roundedPos += mEncryptedBlockSize;
		insideBlockOffset = 0;
	}

	SetFilePointerEx(hFile , MakeLarge(fpos  + nNumberOfBytesToWrite) , 0 , FILE_BEGIN);

	if (lpNumberOfBytesWritten)
	{
		*lpNumberOfBytesWritten = nNumberOfBytesToWrite;
	}

	return TRUE;
}

}; //< namespace BlobFileLib
