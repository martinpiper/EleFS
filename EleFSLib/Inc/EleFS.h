#ifndef _ELEFSLIB_ELEFS_H_
#define _ELEFSLIB_ELEFS_H_

#include <windows.h>
#include <string>

namespace EleFSLib
{

	class EleFS
	{
	public:
		EleFS();
		virtual ~EleFS();

		/// Probes a container file, creates it if it doesn't exist, checks if it is valid.
		bool Initialise(const WCHAR *filename , const void *keyData = 0 , const size_t keyDataLength = 0);

		class File
		{
		public:
			virtual ~File();

			LONGLONG mFilePointer;
			LONGLONG mFileSize;
		private:
			friend EleFS;
			explicit File(EleFS &fs);
			EleFS &mFS;
			LONGLONG mEntryHandle;
			LONGLONG mSize;
			LONGLONG mDataHandle;
			bool mBeingDeleted;
		}; //< class File

		struct EleFSHeader
		{
			EleFSHeader() : mRootDirectoryHandle(0)
			{
			}

			LONGLONG mRootDirectoryHandle;
		};

		bool Lock(const bool forWrite = false);
		void Unlock(void);

		/// Opens a file in the container if it exists. Uses similar similar parameters to CreateFile
		File *FileOpen(const WCHAR *filename, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, bool isDirectoryRequest = false);

		BOOL WriteFile(File *hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten);

		BOOL ReadFile(File *hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead);

		BOOL SetEndOfFile(File *hFile);

		BOOL CloseFile(File *hFile);

		BOOL CreateDirectory(const WCHAR *filename);

		DWORD GetFileAttributes(const WCHAR *filename);

		BOOL SetFileAttributes(const WCHAR *filename, DWORD dwFileAttributes);

		BOOL GetFileTime(File *hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime);

		BOOL SetFileTime(File *hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime, const FILETIME *lpLastWriteTime);

		BOOL GetFileInformation(File *hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);

		HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);

		BOOL FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

		BOOL FindClose(HANDLE hFindFile);

		BOOL DeleteFile(const WCHAR *filename);

		BOOL Rename(const WCHAR *existingPath, const WCHAR *newPath);

		LONGLONG GetLastContainerFileSize(void)
		{
			return mLastContainerFileSize;
		}

	private:
		friend File;

		std::wstring mFilename;

		CRITICAL_SECTION mSection;

		HANDLE mLockedHandle;
		size_t mLockCounter;
		bool mLockedForWrite;

		EleFSHeader mHeader;

		LONGLONG mLastContainerFileSize;
		OVERLAPPED mOverlapped;

		const void *mKeyData;
		size_t mKeyDataLength;
	}; //< class EleFS


}; //< namespace EleFSLib

#endif
