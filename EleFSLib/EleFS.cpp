#include <windows.h>
#include <assert.h>
#include <map>
#include <list>
#include <string>
#include "EleFSLib/Inc/EleFS.h"
#include "BlobFileLib/Inc/BlobFile.h"

using namespace BlobFileLib;
#pragma comment( lib, "BlobFileLib.lib" )

namespace EleFSLib
{

#pragma pack(push,1)
	struct FileDirectoryEntry
	{
		FileDirectoryEntry()
		{
		}

		void Init(const WCHAR *filename = 0)
		{
			// Remember if the packing is anything but 1 then *this must be explicitly zeroed to include any unused space between members.
			// Otherwise we can see unused memory being written to the file, which could be a security risk.
			mNext = 0;
			mHandle = 0;
			mFileSize = 0;
			mIsDirectory = false;
			mFileAttributes = 0;
			ZeroMemory(&mCreationTime,sizeof(mCreationTime));
			ZeroMemory(&mLastAccessTime,sizeof(mLastAccessTime));
			ZeroMemory(&mLastWriteTime,sizeof(mLastWriteTime));
			ZeroMemory(mName,sizeof(mName));
			if (filename)
			{
				wcsncpy(mName,filename,MAX_PATH);
			}
		}

		LONGLONG mNext;		// The next entry at this level
		LONGLONG mHandle;	// Either the handle to the block or a handle to the next directory for a FileDirectoryEntry
		LONGLONG mFileSize;
		bool mIsDirectory;
		// Standard Windows file information
		DWORD mFileAttributes;
		FILETIME mCreationTime;
		FILETIME mLastAccessTime;
		FILETIME mLastWriteTime;

		// Allow for null termination
		WCHAR mName[MAX_PATH+1];
	};

#pragma pack(pop)

	class AutoLocker
	{
	public:
		AutoLocker(CRITICAL_SECTION *section) : mSection(section)
		{
			EnterCriticalSection(section);
		}

		virtual ~AutoLocker()
		{
			LeaveCriticalSection(mSection);
		}

		CRITICAL_SECTION *mSection;
	};
#define LOCK() AutoLocker _locker(&mSection);

	class FSLock
	{
	public:
		FSLock(EleFS *fs,const bool forWrite = false) : mFS(fs)
		{
			mFS->Lock(forWrite);
		}

		virtual ~FSLock()
		{
			mFS->Unlock();
		}

		EleFS *mFS;
	};
#define FSLOCK(forWrite) \
	FSLock _locker2(this,forWrite);	\
	BlobFile blobFile(mLockedHandle);	\
	blobFile.SetKeyData(mKeyData , mKeyDataLength);	\
	ScopedEleFSHeader header(mHeader,blobFile,forWrite);


	class ScopedEleFSHeader
	{
	public:
		ScopedEleFSHeader(EleFS::EleFSHeader &header,BlobFile &fp,const bool isWriteLocked) : mHeader(header) , mFP(fp) , mIsWriteLocked(isWriteLocked)
		{
			if (!mFP.GetApplicationData() && mIsWriteLocked)
			{
				LONGLONG handle = mFP.AllocateBlock(sizeof(mHeader));
				FileDirectoryEntry entry;
				entry.Init(L"<root>");
				entry.mIsDirectory = true;
				entry.mFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
				mHeader.mRootDirectoryHandle = mFP.AllocateBlock(sizeof(entry));
				mFP.WriteBlock(mHeader.mRootDirectoryHandle,&entry,sizeof(entry));
				mFP.WriteBlock(handle,&mHeader,sizeof(mHeader));
				mFP.SetApplicationData(handle);
			}
			else
			{
				mFP.ReadBlock(mFP.GetApplicationData(),&mHeader,sizeof(mHeader));
			}
		}

		virtual ~ScopedEleFSHeader()
		{
			if (mIsWriteLocked)
			{
				mFP.WriteBlock(mFP.GetApplicationData(),&mHeader,sizeof(mHeader));
			}
		}

		EleFS::EleFSHeader &mHeader;
		BlobFile &mFP;
		bool mIsWriteLocked;
	};


	EleFS::EleFS() : mLockedHandle(INVALID_HANDLE_VALUE) , mLockCounter(0) , mLockedForWrite(false) , mLastContainerFileSize(0) , mKeyData(0) , mKeyDataLength(0)
	{
		InitializeCriticalSection(&mSection);
	}

	EleFS::~EleFS()
	{
		assert((mLockCounter == 0) && "mLockCounter shouldn't indicate any outstanding locks during dtor");
		// If we are in release mode then just close any outstanding handles
		if (mLockedHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(mLockedHandle);
		}
	}

	bool EleFS::Initialise(const WCHAR *filename , const void *keyData , const size_t keyDataLength )
	{
		LOCK();
		mKeyData = keyData;
		mKeyDataLength = keyDataLength;

		HANDLE handle = CreateFileW(filename,GENERIC_READ,FILE_SHARE_READ,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
		if (handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}

		DWORD attr = ::GetFileAttributes(filename);
		if (attr == INVALID_FILE_ATTRIBUTES)
		{
			return false;
		}

		mFilename = filename;

		// Check the FS header is available and create it if it isn't there.
		FSLOCK(true);

		return true;
	}

	bool EleFS::Lock(const bool forWrite)
	{
		LOCK();
		int retry = 0;

		if (mLockedHandle == INVALID_HANDLE_VALUE)
		{
			// This should not retry that often.
			do
			{
				mLockedHandle = CreateFileW(mFilename.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, 0);

				if (mLockedHandle == INVALID_HANDLE_VALUE)
				{
					Sleep(100);
					printf("****Locked retry %d\n", retry++);
				}
			} while (mLockedHandle == INVALID_HANDLE_VALUE);

			// This will block until the lock is gained or there is an error
			ZeroMemory(&mOverlapped, sizeof(mOverlapped));
			mOverlapped.Offset = 0;
			LockFileEx(mLockedHandle, forWrite ? LOCKFILE_EXCLUSIVE_LOCK : 0, 0, 10, 0, &mOverlapped);
		}

		LARGE_INTEGER totalSize;
		if (GetFileSizeEx(mLockedHandle, &totalSize))
		{
			mLastContainerFileSize = totalSize.QuadPart;
		}

		// Accumulate the write lock indicator
		if (forWrite)
		{
			mLockedForWrite = true;
		}
		mLockCounter++;
		return true;
	}

	void EleFS::Unlock(void)
	{
		LOCK();

		if (mLockCounter)
		{
			mLockCounter--;
			// Last lock?
			if (!mLockCounter)
			{
				if (mLockedForWrite)
				{
					FlushFileBuffers(mLockedHandle);
				}

				UnlockFileEx(mLockedHandle,0,10,0,&mOverlapped);

				// If writing then make sure we release the file handle to ensure we don't block access for anyone else
				if (mLockedForWrite)
				{
					CloseHandle(mLockedHandle);
					mLockedHandle = INVALID_HANDLE_VALUE;
				}

				mLockedForWrite = false;
			}
		}
	}

	// File handling starts here
	EleFS::File::File(EleFS &fs) : mFS(fs) , mEntryHandle(0) , mSize(0) , mDataHandle(0) , mFilePointer(0) , mFileSize(0) , mBeingDeleted(false)
	{
	}

	EleFS::File::~File()
	{
		if (!mBeingDeleted)
		{
			mBeingDeleted = true;
			mFS.CloseFile(this);
		}
	}

	static void TidyPath(std::wstring &filename)
	{
		// Tidy the path
		while(!filename.empty() && *filename.begin() == '\\')
		{
			filename.erase(filename.begin());
		}
		size_t pos;
		while (!filename.empty() && ((pos = filename.find(L"\\\\")) != std::wstring::npos) )
		{
			filename.erase(pos,1);
		}
	}

	/// Parses the path to a directory if it exists. Returns the parent directory handle.
	/// \param createMissing When true this function assumes the full path just contains the directory path to create and does not have a terminating filename.
	static LONGLONG ParsePathToDirectory(EleFS::EleFSHeader &mHeader, BlobFile &blobFile, const WCHAR *filename, FileDirectoryEntry &entry, bool createMissing = false)
	{
		entry.Init();
		LONGLONG searchHandle = mHeader.mRootDirectoryHandle;
		LONGLONG oldParent = searchHandle;
		if (!blobFile.ReadBlock(searchHandle,&entry,sizeof(entry)))
		{
			return 0;
		}
		LONGLONG resultant = searchHandle;
		searchHandle = entry.mHandle;

		std::wstring pathToSplit(filename);
		TidyPath(pathToSplit);
		size_t pos;
		if (createMissing && (pathToSplit.empty() || (*(--pathToSplit.end()) != L'\\')))
		{
			pathToSplit.append(L"\\");
		}

		std::wstring split;
		while( (pos = pathToSplit.find_first_of('\\')) != std::wstring::npos )
		{
			split = pathToSplit.substr(0,pos);
			pathToSplit = pathToSplit.substr(pos+1);
			bool nextDir = false;
			while (searchHandle)
			{
				if (!blobFile.ReadBlock(searchHandle,&entry,sizeof(entry)))
				{
					return 0;
				}
				if (!_wcsicmp(entry.mName,split.c_str()))
				{
					if (!entry.mIsDirectory)
					{
						return 0;
					}
					resultant = searchHandle;
					oldParent = searchHandle;
					searchHandle = entry.mHandle;
					nextDir = true;
					break;
				}
				searchHandle = entry.mNext;
			}
			if (nextDir)
			{
				continue;
			}
			resultant = 0;
			if (!searchHandle && createMissing && !split.empty())
			{
				FileDirectoryEntry oldParentEntry;
				if (!blobFile.ReadBlock(oldParent,&oldParentEntry,sizeof(oldParentEntry)))
				{
					return 0;
				}
				searchHandle = blobFile.AllocateBlock(sizeof(entry));
				entry.Init(split.c_str());
				entry.mIsDirectory = true;
				entry.mFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
				entry.mNext = oldParentEntry.mHandle;
				oldParentEntry.mHandle = searchHandle;

				if (!blobFile.WriteBlock(oldParent,&oldParentEntry,sizeof(oldParentEntry)))
				{
					return 0;
				}
				GetSystemTimeAsFileTime(&entry.mCreationTime);
				entry.mLastAccessTime = entry.mCreationTime;
				entry.mLastWriteTime = entry.mCreationTime;

				blobFile.WriteBlock(searchHandle,&entry,sizeof(entry));
				resultant = searchHandle;
				oldParent = searchHandle;
				searchHandle = 0;
				continue;
			}

			if (!searchHandle)
			{
				return 0;
			}
		}

		return resultant;
	}

	static bool LinkEntryToDirectory(EleFS::EleFSHeader &mHeader, BlobFile &blobFile, LONGLONG entryHandle, FileDirectoryEntry &entry, LONGLONG directoryHandle)
	{
		FileDirectoryEntry oldParentEntry;
		if (!blobFile.ReadBlock(directoryHandle,&oldParentEntry,sizeof(oldParentEntry)))
		{
			return false;
		}
		entry.mNext = oldParentEntry.mHandle;
		oldParentEntry.mHandle = entryHandle;
		blobFile.WriteBlock(directoryHandle,&oldParentEntry,sizeof(oldParentEntry));

		blobFile.WriteBlock(entryHandle,&entry,sizeof(entry));
		return true;
	}

	static LONGLONG FindEntryInDirectory(EleFS::EleFSHeader &mHeader, BlobFile &blobFile, const WCHAR *filename, LONGLONG searchHandle, FileDirectoryEntry &entry, LONGLONG directoryHandle, bool createMissing = false)
	{
		entry.Init();

		std::wstring pathToSplit(filename);
		std::wstring split = pathToSplit;
		size_t pos;
		pos = pathToSplit.find_last_of('\\');
		if (pos != std::wstring::npos)
		{
			split = split.substr(pos+1);
		}

		if (split.empty())
		{
			// Trying to open an empty root directory entry
			if (!blobFile.ReadBlock(mHeader.mRootDirectoryHandle,&entry,sizeof(entry)))
			{
				return 0;
			}
			return mHeader.mRootDirectoryHandle;
		}

		while (searchHandle)
		{
			if (!blobFile.ReadBlock(searchHandle,&entry,sizeof(entry)))
			{
				return 0;
			}
			if (!_wcsicmp(entry.mName,split.c_str()))
			{
				return searchHandle;
			}
			searchHandle = entry.mNext;
		}

		if (!searchHandle && createMissing && !split.empty())
		{
			entry.Init(split.c_str());

			LONGLONG handle = blobFile.AllocateBlock(sizeof(entry));

			if (!LinkEntryToDirectory(mHeader,blobFile,handle,entry,directoryHandle))
			{
				return 0;
			}
			return handle;
		}

		return 0;
	}

	static LONGLONG UnlinkEntryInDirectory(EleFS::EleFSHeader &mHeader, BlobFile &blobFile, const WCHAR *filename, LONGLONG searchHandle, FileDirectoryEntry &entry, LONGLONG directoryHandle, bool unlinkFullDir = false)
	{
		LONGLONG prev = 0;
		entry.Init();

		std::wstring pathToSplit(filename);
		std::wstring split = pathToSplit;
		size_t pos;
		pos = pathToSplit.find_last_of('\\');
		if (pos != std::wstring::npos)
		{
			split = split.substr(pos+1);
		}

		if (split.empty())
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
			return FALSE;
		}

		while (searchHandle)
		{
			if (!blobFile.ReadBlock(searchHandle,&entry,sizeof(entry)))
			{
				return FALSE;
			}
			if (!_wcsicmp(entry.mName,split.c_str()))
			{
				if (!unlinkFullDir && entry.mIsDirectory && entry.mHandle)
				{
					SetLastError(ERROR_DIR_NOT_EMPTY);
					return FALSE;
				}

				FileDirectoryEntry prevEntry;
				if (prev)
				{
					// Unlink from this level link list
					blobFile.ReadBlock(prev,&prevEntry,sizeof(prevEntry));
					prevEntry.mNext = entry.mNext;
					blobFile.WriteBlock(prev,&prevEntry,sizeof(prevEntry));
				}
				else
				{
					// Unlink from this parent link list
					blobFile.ReadBlock(directoryHandle,&prevEntry,sizeof(prevEntry));
					prevEntry.mHandle = entry.mNext;
					blobFile.WriteBlock(directoryHandle,&prevEntry,sizeof(prevEntry));
				}

				return searchHandle;
			}
			prev = searchHandle;
			searchHandle = entry.mNext;
		}

		SetLastError(ERROR_PATH_NOT_FOUND);
		return 0;
	}


	EleFS::File *EleFS::FileOpen(const WCHAR *filename, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, bool isDirectoryRequest)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		bool needLock = false;
		if ((dwCreationDisposition == CREATE_NEW) ||
			(dwCreationDisposition == TRUNCATE_EXISTING) ||
			(dwCreationDisposition == OPEN_ALWAYS) ||
			(dwCreationDisposition == CREATE_ALWAYS)
			)
		{
			needLock = true;
		}
		FSLOCK(needLock);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,filename,entry);
		LONGLONG searchHandle = 0;
		LONGLONG firstEntryInDirectory = entry.mHandle;

		if (dwCreationDisposition == CREATE_NEW)
		{
			FileDirectoryEntry tempEntry;
			LONGLONG temp = FindEntryInDirectory(mHeader,blobFile,filename,firstEntryInDirectory,tempEntry,directoryHandle);
			if (temp)
			{
				SetLastError(ERROR_FILE_EXISTS);
				return 0;
			}
		}
		else if ((dwCreationDisposition == OPEN_EXISTING) || (dwCreationDisposition == TRUNCATE_EXISTING))
		{
			searchHandle = FindEntryInDirectory(mHeader,blobFile,filename,firstEntryInDirectory,entry,directoryHandle);
			if (!searchHandle)
			{
				SetLastError(ERROR_FILE_NOT_FOUND);
				return 0;
			}
			GetSystemTimeAsFileTime(&entry.mLastAccessTime);

			if ((dwCreationDisposition == TRUNCATE_EXISTING) && !entry.mIsDirectory && entry.mHandle)
			{
				blobFile.ResizeBlock(entry.mHandle,0);
				entry.mFileSize = 0;
			}
		}
		else if (dwCreationDisposition == OPEN_ALWAYS)
		{
			searchHandle = FindEntryInDirectory(mHeader,blobFile,filename,firstEntryInDirectory,entry,directoryHandle);
			if (searchHandle)
			{
				GetSystemTimeAsFileTime(&entry.mLastAccessTime);
			}
			else
			{
				dwCreationDisposition = CREATE_NEW;	// Use the if below
			}
		}
		else if (dwCreationDisposition == CREATE_ALWAYS)
		{
			DeleteFile(filename);
			firstEntryInDirectory = 0;
		}

		if ((dwCreationDisposition == CREATE_NEW) || (dwCreationDisposition == CREATE_ALWAYS))
		{
			searchHandle = FindEntryInDirectory(mHeader,blobFile,filename,firstEntryInDirectory,entry,directoryHandle,true);
			if (!searchHandle)
			{
				SetLastError(ERROR_FILE_NOT_FOUND);
				return 0;
			}

			GetSystemTimeAsFileTime(&entry.mCreationTime);
			entry.mLastAccessTime = entry.mCreationTime;
			entry.mLastWriteTime = entry.mCreationTime;
			entry.mFileAttributes = dwFlagsAndAttributes;
		}

		if (searchHandle)
		{
			// This fixes VLC trying to play a file
			if (isDirectoryRequest && !entry.mIsDirectory)
			{
				// MPi: TODO: Look for a better alternative to ERROR_NO_MORE_ITEMS
				// During tests with "mirror" this returns: CreateFile status = c0000103
				SetLastError(ERROR_NO_MORE_ITEMS);
				return 0;
			}
			if (needLock)
			{
				blobFile.WriteBlock(searchHandle,&entry,sizeof(entry));
			}
			File *theFile = new File(*this);
			theFile->mEntryHandle = searchHandle;
			theFile->mDataHandle = entry.mHandle;
			theFile->mFileSize = entry.mFileSize;
			theFile->mFilePointer = 0;

			return theFile;
		}

		return 0;
	}

	BOOL EleFS::WriteFile(File *hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}
		if (lpNumberOfBytesWritten)
		{
			*lpNumberOfBytesWritten = 0;
		}
		if (!nNumberOfBytesToWrite)
		{
			return TRUE;
		}

		LONGLONG newSize = hFile->mFilePointer + nNumberOfBytesToWrite;

		LONGLONG blockSize = 0;
		if (hFile->mDataHandle)
		{
			if (!blobFile.GetBlockSize(hFile->mDataHandle, blockSize))
			{
				return FALSE;
			}
		}
		else
		{
			// Attempt to get the most up to date value from the entry first
			FileDirectoryEntry entry;
			blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry));
			if (entry.mHandle)
			{
				hFile->mDataHandle = entry.mHandle;
			}
			else
			{
				hFile->mDataHandle = blobFile.AllocateBlock(newSize);
				entry.mHandle = hFile->mDataHandle;
				blobFile.WriteBlock(hFile->mEntryHandle,&entry,sizeof(entry));
			}
			if (!blobFile.GetBlockSize(hFile->mDataHandle, blockSize))
			{
				return FALSE;
			}
		}
		if (newSize > blockSize)
		{
			blobFile.ResizeBlock(hFile->mDataHandle, newSize);
		}
		if (newSize > hFile->mFileSize)
		{
			hFile->mFileSize = newSize;
			FileDirectoryEntry entry;
			blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry));
			entry.mFileSize = hFile->mFileSize;
			GetSystemTimeAsFileTime(&entry.mLastWriteTime);
			blobFile.WriteBlock(hFile->mEntryHandle,&entry,sizeof(entry));
		}
		blobFile.WriteBlock(hFile->mDataHandle,lpBuffer,nNumberOfBytesToWrite,hFile->mFilePointer);
		hFile->mFilePointer += nNumberOfBytesToWrite;
		if (lpNumberOfBytesWritten)
		{
			*lpNumberOfBytesWritten = nNumberOfBytesToWrite;
		}

		return TRUE;
	}

	BOOL EleFS::ReadFile(File *hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(false);

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}
		if (lpNumberOfBytesRead)
		{
			*lpNumberOfBytesRead = 0;
		}
		if (!nNumberOfBytesToRead)
		{
			return TRUE;
		}

		if (hFile->mFilePointer == hFile->mFileSize)
		{
			SetLastError(ERROR_HANDLE_EOF);
			return TRUE;	// Returns 0 bytes read
		}

		if (hFile->mFilePointer > hFile->mFileSize)
		{
			SetLastError(ERROR_HANDLE_EOF);
			return FALSE;
		}

		DWORD realToRead = nNumberOfBytesToRead;
		LONGLONG calcedEndPos = hFile->mFilePointer + nNumberOfBytesToRead;

		// Clamp any read bytes value to the end of the file
		if (calcedEndPos > hFile->mFileSize)
		{
			realToRead -= (DWORD) (calcedEndPos - hFile->mFileSize);
		}
		if (!blobFile.ReadBlock(hFile->mDataHandle,lpBuffer,realToRead,hFile->mFilePointer))
		{
			return FALSE;
		}
		hFile->mFilePointer += realToRead;
		if (lpNumberOfBytesRead)
		{
			*lpNumberOfBytesRead = realToRead;
		}

		return TRUE;
	}

	BOOL EleFS::SetEndOfFile(File *hFile)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}

		if (!hFile->mFileSize && !hFile->mDataHandle)
		{
			return TRUE;
		}

		if (!hFile->mDataHandle)
		{
			// Attempt to get the most up to date value from the entry first
			FileDirectoryEntry entry;
			if (!blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
			{
				return FALSE;
			}
			if (entry.mHandle)
			{
				hFile->mDataHandle = entry.mHandle;
			}
			else
			{
				hFile->mDataHandle = blobFile.AllocateBlock(hFile->mFileSize);
				entry.mHandle = hFile->mDataHandle;
				if (!blobFile.WriteBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
				{
					return FALSE;
				}
			}
		}

		if (!hFile->mDataHandle)
		{
			SetLastError(ERROR_FILE_CORRUPT);
			return FALSE;
		}

		hFile->mFileSize = hFile->mFilePointer;
		FileDirectoryEntry entry;
		if (!blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}
		entry.mFileSize = hFile->mFileSize;
		GetSystemTimeAsFileTime(&entry.mLastWriteTime);
		if (!blobFile.WriteBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}

		blobFile.ResizeBlock(hFile->mDataHandle,hFile->mFileSize);

		return TRUE;
	}

	BOOL EleFS::CloseFile(File *hFile)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}
		if (!hFile->mBeingDeleted)
		{
			hFile->mBeingDeleted = true;
			delete hFile;
		}
		return TRUE;
	}

	BOOL EleFS::CreateDirectory(const WCHAR *filename)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,filename,entry,true);
		if (directoryHandle)
		{
			return TRUE;
		}
		return FALSE;
	}

	DWORD EleFS::GetFileAttributes(const WCHAR *filename)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(false);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,filename,entry);
		DWORD attrs = INVALID_FILE_ATTRIBUTES;
		if (directoryHandle && entry.mIsDirectory)
		{
			attrs = entry.mFileAttributes | FILE_ATTRIBUTE_DIRECTORY;
		}
		if (directoryHandle)
		{
			LONGLONG searchHandle = FindEntryInDirectory(mHeader,blobFile,filename,entry.mHandle,entry,directoryHandle);
			if (searchHandle)
			{
				attrs = entry.mFileAttributes;
				if (entry.mIsDirectory)
				{
					attrs = attrs | FILE_ATTRIBUTE_DIRECTORY;
				}
			}
			else
			{
				attrs = INVALID_FILE_ATTRIBUTES;
			}
		}

		if (attrs == INVALID_FILE_ATTRIBUTES)
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
		}
		return attrs;
	}

	BOOL EleFS::SetFileAttributes(const WCHAR *filename, DWORD dwFileAttributes)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,filename,entry);
		if (directoryHandle)
		{
			LONGLONG searchHandle = FindEntryInDirectory(mHeader,blobFile,filename,entry.mHandle,entry,directoryHandle);
			if (searchHandle)
			{
				entry.mFileAttributes = dwFileAttributes;
				if (!blobFile.WriteBlock(searchHandle,&entry,sizeof(entry)))
				{
					return FALSE;
				}
			}
			else
			{
				SetLastError(ERROR_PATH_NOT_FOUND);
				return FALSE;
			}
		}
		else
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
			return FALSE;
		}

		return TRUE;
	}

	BOOL EleFS::GetFileTime(File *hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(false);

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}

		// Attempt to get the most up to date value from the entry first
		FileDirectoryEntry entry;
		if (!blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}

		if (lpCreationTime)
		{
			*lpCreationTime = entry.mCreationTime;
		}
		if (lpLastAccessTime)
		{
			*lpLastAccessTime = entry.mLastAccessTime;
		}
		if (lpLastWriteTime)
		{
			*lpLastWriteTime = entry.mLastWriteTime;
		}

		return TRUE;
	}

	BOOL EleFS::SetFileTime(File *hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime, const FILETIME *lpLastWriteTime)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		if (!hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}

		// Attempt to get the most up to date value from the entry first
		FileDirectoryEntry entry;
		if (!blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}

		// Only use valid time values
		if (lpCreationTime && (lpCreationTime->dwHighDateTime || lpCreationTime->dwLowDateTime))
		{
			entry.mCreationTime = *lpCreationTime;
		}
		if (lpLastAccessTime && (lpLastAccessTime->dwHighDateTime || lpLastAccessTime->dwLowDateTime) && (lpLastAccessTime->dwLowDateTime != 0xFFFFFFFF) && (lpLastAccessTime->dwHighDateTime != 0xFFFFFFFF))
		{
			entry.mLastAccessTime = *lpLastAccessTime;
		}
		if (lpLastWriteTime && (lpLastWriteTime->dwHighDateTime || lpLastWriteTime->dwLowDateTime))
		{
			entry.mLastWriteTime = *lpLastWriteTime;
		}

		if (!blobFile.WriteBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}

		return TRUE;
	}

	BOOL EleFS::GetFileInformation(File *hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(false);

		if (!lpFileInformation || !hFile || (&hFile->mFS != this))
		{
			return FALSE;
		}

		// Attempt to get the most up to date value from the entry first
		FileDirectoryEntry entry;
		if (!blobFile.ReadBlock(hFile->mEntryHandle,&entry,sizeof(entry)))
		{
			return FALSE;
		}

		lpFileInformation->dwFileAttributes = entry.mFileAttributes & 0x7fffffff;
		lpFileInformation->dwVolumeSerialNumber = 0;
		lpFileInformation->ftCreationTime = entry.mCreationTime;
		lpFileInformation->ftLastAccessTime = entry.mLastAccessTime;
		lpFileInformation->ftLastWriteTime = entry.mLastWriteTime;
		lpFileInformation->nFileIndexHigh = (DWORD) (hFile->mEntryHandle >> 32);
		lpFileInformation->nFileIndexLow = (DWORD) hFile->mEntryHandle;
		lpFileInformation->nFileSizeHigh = (DWORD) (entry.mFileSize >> 32);
		lpFileInformation->nFileSizeLow = (DWORD) entry.mFileSize;
		lpFileInformation->nNumberOfLinks = 1;
		return TRUE;
	}

	class FindFileInformation
	{
	public:
		FindFileInformation();
		virtual ~FindFileInformation();

		std::list<WIN32_FIND_DATAW> mItems;
		std::list<WIN32_FIND_DATAW>::iterator mIter;
	};

	FindFileInformation::FindFileInformation()
	{
		mIter = mItems.begin();
	}

	FindFileInformation::~FindFileInformation()
	{
	}

	HANDLE EleFS::FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
	{
		SetLastError(ERROR_SUCCESS);
		if (!lpFileName || !lpFindFileData)
		{
			SetLastError(ERROR_INVALID_FUNCTION);
			return INVALID_HANDLE_VALUE;
		}

		LOCK();
		FSLOCK(false);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,lpFileName,entry);
		if (!directoryHandle)
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
			return INVALID_HANDLE_VALUE;
		}

		FindFileInformation *ffinfo = new FindFileInformation;

		// Always the . and .. entries because this container file might be part of a larger file system
		WIN32_FIND_DATAW info;
		ZeroMemory(&info,sizeof(info));
		info.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		info.cFileName[0] = '.';
		info.ftCreationTime = entry.mCreationTime;
		info.ftLastAccessTime = entry.mLastAccessTime;
		info.ftLastWriteTime = entry.mLastWriteTime;
		ffinfo->mItems.push_back(info);
		info.cFileName[1] = '.';
		ffinfo->mItems.push_back(info);

		directoryHandle = entry.mHandle;

		while (directoryHandle)
		{
			if (!blobFile.ReadBlock(directoryHandle,&entry,sizeof(entry)))
			{
				delete ffinfo;
				return INVALID_HANDLE_VALUE;
			}
			WIN32_FIND_DATAW info;
			ZeroMemory(&info,sizeof(info));
			info.dwFileAttributes = entry.mFileAttributes;
			if (entry.mIsDirectory)
			{
				info.dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
			}
			info.ftCreationTime = entry.mCreationTime;
			info.ftLastAccessTime = entry.mLastAccessTime;
			info.ftLastWriteTime = entry.mLastWriteTime;
			info.nFileSizeHigh = (DWORD) (entry.mFileSize >> 32);
			info.nFileSizeLow = (DWORD) entry.mFileSize;
			wcsncpy(info.cFileName,entry.mName,MAX_PATH);
			ffinfo->mItems.push_back(info);

			// Spot the bad case in debug and release
			assert(directoryHandle != entry.mNext);
			if (directoryHandle == entry.mNext)
			{
				break;
			}

			directoryHandle = entry.mNext;
		}

		ffinfo->mIter = ffinfo->mItems.begin();
		if (!FindNextFileW((HANDLE) ffinfo,lpFindFileData))
		{
			delete ffinfo;
			return INVALID_HANDLE_VALUE;
		}
		return (HANDLE) ffinfo;
	}

	BOOL EleFS::FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
	{
		SetLastError(ERROR_SUCCESS);
		if (!hFindFile || (hFindFile == INVALID_HANDLE_VALUE) || !lpFindFileData)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		FindFileInformation *info = (FindFileInformation*) hFindFile;
		if (info->mIter == info->mItems.end())
		{
			SetLastError(ERROR_NO_MORE_FILES);
			return FALSE;
		}
		WIN32_FIND_DATAW &theInfo = *(info->mIter);
		memcpy(lpFindFileData,&theInfo,sizeof(theInfo));
		info->mIter++;

		return TRUE;
	}

	BOOL EleFS::FindClose(HANDLE hFindFile)
	{
		SetLastError(ERROR_SUCCESS);
		if (!hFindFile || (hFindFile == INVALID_HANDLE_VALUE))
		{
			return FALSE;
		}

		FindFileInformation *info = (FindFileInformation*) hFindFile;
		delete info;
		return TRUE;
	}

	BOOL EleFS::DeleteFile(const WCHAR *filename)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		FileDirectoryEntry entry;
		LONGLONG directoryHandle = ParsePathToDirectory(mHeader,blobFile,filename,entry);
		DWORD attrs = INVALID_FILE_ATTRIBUTES;
		LONGLONG ret;
		ret = UnlinkEntryInDirectory(mHeader,blobFile,filename,entry.mHandle,entry,directoryHandle);
		if (ret)
		{
			if (!entry.mIsDirectory && entry.mHandle)
			{
				blobFile.FreeBlock(entry.mHandle);
			}
			blobFile.FreeBlock(ret);
			return TRUE;
		}
		return FALSE;
	}

	BOOL EleFS::Rename(const WCHAR *existingPath, const WCHAR *newPath)
	{
		SetLastError(ERROR_SUCCESS);
		LOCK();
		FSLOCK(true);

		FileDirectoryEntry entry;

		LONGLONG directoryHandleNew = ParsePathToDirectory(mHeader,blobFile,newPath,entry);
		if (!directoryHandleNew)
		{
			SetLastError(ERROR_PATH_NOT_FOUND);
			return FALSE;
		}
		LONGLONG searchHandle = FindEntryInDirectory(mHeader,blobFile,newPath,entry.mHandle,entry,directoryHandleNew);
		if (searchHandle)
		{
			SetLastError(ERROR_FILE_EXISTS);
			return FALSE;
		}
		LONGLONG directoryHandleExisting = ParsePathToDirectory(mHeader,blobFile,existingPath,entry);

		std::wstring split(newPath);
		size_t pos = split.find_last_of('\\');
		if (pos != std::wstring::npos)
		{
			split = split.substr(pos+1);
		}

		if (directoryHandleNew == directoryHandleExisting)
		{
			LONGLONG ret = FindEntryInDirectory(mHeader,blobFile,existingPath,entry.mHandle,entry,directoryHandleExisting);
			if (!ret)
			{
				SetLastError(ERROR_PATH_NOT_FOUND);
				return FALSE;
			}
			wcsncpy(entry.mName,split.c_str(),MAX_PATH);
			// Same directory so just rename the entry
			blobFile.WriteBlock(ret,&entry,sizeof(entry));
		}
		else
		{
			// Otherwise unlink and relink
			LONGLONG ret;
			ret = UnlinkEntryInDirectory(mHeader,blobFile,existingPath,entry.mHandle,entry,directoryHandleExisting,true);
			if (!ret)
			{
				SetLastError(ERROR_PATH_NOT_FOUND);
				return FALSE;
			}
			wcsncpy(entry.mName,split.c_str(),MAX_PATH);
			LinkEntryToDirectory(mHeader,blobFile,ret,entry,directoryHandleNew);
		}

		return TRUE;
	}

}; //< namespace EleFSLib
