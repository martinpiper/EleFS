#ifndef _BLOBFILELIB_BLOBFILE_H_
#define _BLOBFILELIB_BLOBFILE_H_

#include <windows.h>
#include <string>

#include "BlobFileLib/Inc/FileCrypto.h"

namespace BlobFileLib
{

	struct Header
	{
		Header()
		{
			Init();
		}

		void Init(void)
		{
			mFreeBlock = 0;
			mApplicationData = 0;
		}

		// The free block link list
		LONGLONG mFreeBlock;
		LONGLONG mApplicationData;
	};

	class ScopedHeader
	{
	public:
		ScopedHeader(Header &header,HANDLE fp) : mHeader(header) , mFP(fp)
		{
			DWORD numBytes;
			SetFilePointer(mFP,0,0,FILE_BEGIN);
			ReadFile(mFP,&mHeader,sizeof(mHeader),&numBytes,0);
			if (numBytes < sizeof(mHeader))
			{
				// Must be a new empty file so just create and empty header
				mHeader.Init();
				SetFilePointer(mFP,0,0,FILE_BEGIN);
				WriteFile(mFP,&mHeader,sizeof(mHeader),&numBytes,0);
			}
		}

		virtual ~ScopedHeader()
		{
			DWORD numBytes;
			SetFilePointer(mFP,0,0,FILE_BEGIN);
			WriteFile(mFP,&mHeader,sizeof(mHeader),&numBytes,0);
		}

		Header &mHeader;
		HANDLE mFP;
	};

	// Use this special handle value to always point to the first allocated block
	const LONGLONG kFirstBlockHandle = 0;

	/// Manages blobs of data in a container file. Each blob can be allocated, freed, resized, written or read.
	/// Blobs may not be contiguous in the container file so that free space is reused by new allocations.
	class BlobFile
	{
	public:
		explicit BlobFile(HANDLE fileHandle);
		virtual ~BlobFile();

		/// Sets an application defined value, usually a handle to a block, that is stored in the blob file header.
		bool SetApplicationData(const LONGLONG handle);
		LONGLONG GetApplicationData(void);

		LONGLONG AllocateBlock(const LONGLONG size);
		bool FreeBlock(LONGLONG handle);
		bool ResizeBlock(LONGLONG handle, const LONGLONG size);
		bool ReadBlock(LONGLONG handle, void *dest, const DWORD size, const LONGLONG offset = 0, DWORD *sizeRead = 0);
		bool WriteBlock(LONGLONG handle, const void *src, const DWORD size, const LONGLONG offset = 0, DWORD *sizeWritten = 0);
		bool GetBlockSize(LONGLONG handle,LONGLONG &theSize);
		bool IsValidHandle(LONGLONG &handle);

		void SetKeyData(const void *keyData = 0 , const size_t keyDataLength = 0)
		{
			mCrypto.SetKeyData(keyData , keyDataLength);
		}
	private:
		LONGLONG InternalAllocateBlock(const LONGLONG size);
		bool InternalFreeBlock(LONGLONG handle);
		bool BlockReadWrite(LONGLONG handle, void *data, const DWORD size, const bool read = true, const LONGLONG offset = 0, DWORD *sizeProcessed = 0);

		HANDLE mLockedHandle;

		Header mHeader;

		FileCrypto mCrypto;
	}; //< class BlobFile

}; //< namespace BlobFileLib

#endif
