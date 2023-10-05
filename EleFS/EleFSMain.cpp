/*
Options:
/f C:\temp\container.EleFs /l M:\ /s /d /m
/f C:\temp\container.EleFs /l M:\ /m
/p cryptoPassword /f C:\temp\container.EleFs /l M:\ /s /d /m
/p cryptoPassword /f C:\temp\container.EleFs /l M:\ /m
/p cryptoPassword /f E:\temp\container.EleFs /l M:\ /d /s /t 1 /m
/p cryptoPassword /f E:\temp\container.EleFs /l M:\ /d /s /t 5 /m
*/

#define WIN32_NO_STATUS
#include <time.h>
#include <map>
#include <ShlObj.h>
#include <process.h>
#include "dokan/dokan.h"
#include "dokan/fileinfo.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <sddl.h>
#include "EleFSLib/Inc/EleFS.h"

using namespace EleFSLib;

BOOL g_UseStdErr;
BOOL g_DebugMode;
BOOL gTimeOperations;



#pragma comment( lib, "dokan1.lib" )
#pragma comment( lib, "EleFSLib.lib" )

#include "RNPlatform/Inc/SysTime.h"
class AutoTimeOperation : RNReplicaNet::SysTime
{
public:
	AutoTimeOperation(const char *text) : mText(text)
	{
	}

	virtual ~AutoTimeOperation()
	{
		if (gTimeOperations)
		{
			RNReplicaNet::SysTimeType theTime = FloatTime();
			if (theTime < 5.0f)
			{
				printf("Thread %d : Time %f : %s\n", GetCurrentThreadId(), theTime, mText);
			}
			else
			{
				printf("Thread %d : ***Time*** %f : %s\n", GetCurrentThreadId(), theTime, mText);
			}
		}
	}

	void displayTimeToHere(const char *text)
	{
		RNReplicaNet::SysTimeType theTime = FloatTime();
		if (theTime < 5.0f)
		{
			printf("Thread %d : Time Until %s %f : %s\n", GetCurrentThreadId(), text, theTime, mText);
		}
		else
		{
			printf("Thread %d : ***Time*** Until %s %f : %s\n", GetCurrentThreadId(), text, theTime, mText);
		}
	}

	const char *mText;
	time_t mStartTime;
};
#define TIMEOPERATION(s) AutoTimeOperation _timer(s);
#define TIMEOPERATIONUNTILHERE(s) _timer.displayTimeToHere(s);

static void DbgPrint(LPCWSTR format, ...)
{
	if (g_DebugMode)
	{
		const WCHAR *outputString;
		WCHAR *buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = (WCHAR*) _malloca(length * sizeof(WCHAR));
		if (buffer)
		{
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		}
		else
		{
			outputString = format;
		}
		if (g_UseStdErr)
		{
			fputws(outputString, stderr);
		}
		else
		{
			OutputDebugStringW(outputString);
		}

		if (buffer)
		{
			_freea(buffer);
		}
		va_end(argp);
		if (g_UseStdErr)
		{
			fflush(stderr);
		}
	}
}


static WCHAR ContainerPath[MAX_PATH] = L"";
static WCHAR MountPoint[MAX_PATH] = L"M:\\";
static WCHAR UNCName[MAX_PATH] = L"";

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo)
{
	HANDLE handle;
	UCHAR buffer[1024];
	DWORD returnLength;
	WCHAR accountName[256];
	WCHAR domainName[256];
	DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
	DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
	PTOKEN_USER tokenUser;
	SID_NAME_USE snu;

	handle = DokanOpenRequestorToken(DokanFileInfo);
	if (handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"  DokanOpenRequestorToken failed\n");
		return;
	}

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
		&returnLength)) {
			DbgPrint(L"  GetTokenInformation failed: %d\n", GetLastError());
			CloseHandle(handle);
			return;
	}

	CloseHandle(handle);

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
		domainName, &domainLength, &snu)) {
			DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
			return;
	}

	DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

static BOOL AddSeSecurityNamePrivilege() {
	HANDLE token = 0;
	DbgPrint(
		L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
	DWORD err;
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
		err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to lookup privilege value. error = %u\n",
				err);
			return FALSE;
		}
	}

	LUID_AND_ATTRIBUTES attr;
	attr.Attributes = SE_PRIVILEGE_ENABLED;
	attr.Luid = luid;

	TOKEN_PRIVILEGES priv;
	priv.PrivilegeCount = 1;
	priv.Privileges[0] = attr;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
			err = GetLastError();
			if (err != ERROR_SUCCESS) {
				DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);
				return FALSE;
			}
	}

	TOKEN_PRIVILEGES oldPriv;
	DWORD retSize;
	AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
		&retSize);
	err = GetLastError();
	if (err != ERROR_SUCCESS) {
		DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
		CloseHandle(token);
		return FALSE;
	}

	BOOL privAlreadyPresent = FALSE;
	for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
		if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
			oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
				privAlreadyPresent = TRUE;
				break;
		}
	}
	DbgPrint(privAlreadyPresent ? L"  success: privilege already present\n"
		: L"  success: privilege added\n");
	if (token)
		CloseHandle(token);
	return TRUE;
}

#define MirrorCheckFlag(val, flag)                                             \
	if (val & flag) {                                                            \
	DbgPrint(L"\t" L#flag L"\n");                                              \
	}

static EleFSLib::EleFS sFS;

static NTSTATUS DOKAN_CALLBACK
	MirrorCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
	TIMEOPERATION("MirrorCreateFile");
	EleFS::File* handle;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	ACCESS_MASK genericDesiredAccess;
	DWORD error = 0;
	SECURITY_ATTRIBUTES securityAttrib;

	securityAttrib.nLength = sizeof(securityAttrib);
	securityAttrib.lpSecurityDescriptor = SecurityContext->AccessState.SecurityDescriptor;
	securityAttrib.bInheritHandle = FALSE;

	void DOKANAPI DokanMapKernelToUserCreateFileFlags(
		ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG CreateOptions,
		ULONG CreateDisposition, ACCESS_MASK *outDesiredAccess,
		DWORD *outFileAttributesAndFlags, DWORD *outCreationDisposition);

	DokanMapKernelToUserCreateFileFlags(DesiredAccess, FileAttributes, CreateOptions, CreateDisposition, &genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

	DbgPrint(L"CreateFile : %s\n", FileName);

	if (creationDisposition == CREATE_NEW)
	{
		DbgPrint(L"\tCREATE_NEW\n");
	}
	else if (creationDisposition == OPEN_ALWAYS)
	{
		DbgPrint(L"\tOPEN_ALWAYS\n");
	}
	else if (creationDisposition == CREATE_ALWAYS)
	{
		DbgPrint(L"\tCREATE_ALWAYS\n");
	}
	else if (creationDisposition == OPEN_EXISTING)
	{
		DbgPrint(L"\tOPEN_EXISTING\n");
	}
	else if (creationDisposition == TRUNCATE_EXISTING)
	{
		DbgPrint(L"\tTRUNCATE_EXISTING\n");
	}
	else
	{
		DbgPrint(L"\tUNKNOWN creationDisposition!\n");
	}

	PrintUserName(DokanFileInfo);

	/*
	if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
	ShareMode = FILE_SHARE_WRITE;
	else if (ShareMode == 0)
	ShareMode = FILE_SHARE_READ;
	*/

	DbgPrint(L"\tShareMode = 0x%x\n", ShareAccess);

	MirrorCheckFlag(ShareAccess, FILE_SHARE_READ);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_WRITE);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_DELETE);

	DbgPrint(L"\tAccessMode = 0x%x\n", DesiredAccess);

	MirrorCheckFlag(DesiredAccess, GENERIC_READ);
	MirrorCheckFlag(DesiredAccess, GENERIC_WRITE);
	MirrorCheckFlag(DesiredAccess, GENERIC_EXECUTE);

	MirrorCheckFlag(DesiredAccess, DELETE);
	MirrorCheckFlag(DesiredAccess, FILE_READ_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_READ_EA);
	MirrorCheckFlag(DesiredAccess, READ_CONTROL);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_EA);
	MirrorCheckFlag(DesiredAccess, FILE_APPEND_DATA);
	MirrorCheckFlag(DesiredAccess, WRITE_DAC);
	MirrorCheckFlag(DesiredAccess, WRITE_OWNER);
	MirrorCheckFlag(DesiredAccess, SYNCHRONIZE);
	MirrorCheckFlag(DesiredAccess, FILE_EXECUTE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
	if (rootFolder)
	{
		DokanFileInfo->IsDirectory = TRUE;
		DbgPrint(L"\tIs root directory\n");
	}

	DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_DIRECTORY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);


	if (DokanFileInfo->IsDirectory)
	{
		// It is a create directory request
		if (creationDisposition == CREATE_NEW)
		{
			if (!sFS.CreateDirectory(FileName/*, &securityAttrib*/))
			{
				error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);
				status = DokanNtStatusFromWin32(error);
			}
		}
		else if (creationDisposition == OPEN_ALWAYS)
		{
			if (!sFS.CreateDirectory(FileName/*, &securityAttrib*/))
			{
				error = GetLastError();

				if (error != ERROR_ALREADY_EXISTS)
				{
					DbgPrint(L"\terror code = %d\n\n", error);
					status = DokanNtStatusFromWin32(error);
				}
			}
		}
		if (status == STATUS_SUCCESS)
		{
			// FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
			handle = sFS.FileOpen(FileName, genericDesiredAccess, ShareAccess, &securityAttrib, OPEN_EXISTING,	fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, true);

			if (!handle || handle == INVALID_HANDLE_VALUE)
			{
				error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);

				status = DokanNtStatusFromWin32(error);
			}
			else
			{
				DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context
			}
		}
	}
	else
	{
		handle = sFS.FileOpen(FileName, genericDesiredAccess, ShareAccess, &securityAttrib, creationDisposition, fileAttributesAndFlags);

		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			error = GetLastError();
			DbgPrint(L"\terror code = %d\n\n", error);

			status = DokanNtStatusFromWin32(error);
		}
		else
		{
			DokanFileInfo->Context = (ULONG64)handle; // save the file handle in Context

			if (creationDisposition == OPEN_ALWAYS || creationDisposition == CREATE_ALWAYS)
			{
				error = GetLastError();
				if (error == ERROR_ALREADY_EXISTS)
				{
					DbgPrint(L"\tOpen an already existing file\n");
					// Open succeed but we need to inform the driver
					// that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
					return STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}

	DbgPrint(L"\n");
	return status;
}

#pragma warning(push)
#pragma warning(disable : 4305)


static void DOKAN_CALLBACK
	MirrorCloseFile(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		DokanFileInfo)
{
	TIMEOPERATION("MirrorCloseFile");
	SetLastError(ERROR_SUCCESS);
	if (DokanFileInfo->Context)
	{
		DbgPrint(L"CloseFile: %s\n", FileName);
		DbgPrint(L"\terror : not cleanuped file\n\n");
		sFS.CloseFile((EleFSLib::EleFS::File*)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	}
	else
	{
		//DbgPrint(L"Close: %s\n\tinvalid handle\n\n", FileName);
		DbgPrint(L"Close: %s\n\n", FileName);
		return;
	}

	//DbgPrint(L"\n");
	return;
}


static void DOKAN_CALLBACK
	MirrorCleanup(
	LPCWSTR					FileName,
	PDOKAN_FILE_INFO		DokanFileInfo)
{
	TIMEOPERATION("MirrorCleanup");
	if (DokanFileInfo->Context)
	{
		DbgPrint(L"Cleanup: %s\n\n", FileName);
		sFS.CloseFile((EleFSLib::EleFS::File*)DokanFileInfo->Context);
		DokanFileInfo->Context = 0;
	}
	else
	{
		DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", FileName);
		return;
	}


	if (DokanFileInfo->DeleteOnClose)
	{
		// Should already be deleted by CloseHandle
		// if open with FILE_FLAG_DELETE_ON_CLOSE
		DbgPrint(L"\tDeleteOnClose\n");
		if (DokanFileInfo->IsDirectory)
		{
			DbgPrint(L"  DeleteDirectory ");
			if (!sFS.DeleteFile(FileName))
			{
				DbgPrint(L"error code = %d\n\n", GetLastError());
			}
			else
			{
				DbgPrint(L"success\n\n");
			}
		}
		else
		{
			DbgPrint(L"  DeleteFile ");
			if (sFS.DeleteFile(FileName) == 0)
			{
				DbgPrint(L" error code = %d\n\n", GetLastError());
			}
			else
			{
				DbgPrint(L"success\n\n");
			}
		}
	}


	return;
}


struct AutoCloseFile
{
	AutoCloseFile() : mFile(0)
	{
	}

	void SetFile(EleFSLib::EleFS::File *file)
	{
		mFile = file;
	}

	virtual ~AutoCloseFile()
	{
		if (mFile)
		{
			sFS.FindClose(mFile);
			mFile = 0;
		}
	}

	EleFSLib::EleFS::File *mFile;
};

static void printHexDump(unsigned char *buffer, size_t length)
{
	int checksum = 0;
	for (size_t i = 0; i < length; i++)
	{
		checksum += length + buffer[i];
	}
	printf("checksum: %8x\n", checksum);
	if (length > 128)
	{
		length = 128;
	}
	while (length-- > 0)
	{
		printf("%02x", *buffer++);
	}
	printf("\n");
}

static NTSTATUS DOKAN_CALLBACK MirrorReadFile(LPCWSTR FileName, LPVOID Buffer,
											  DWORD BufferLength,
											  LPDWORD ReadLength,
											  LONGLONG Offset,
											  PDOKAN_FILE_INFO DokanFileInfo)
{
	TIMEOPERATION("MirrorReadFile");
	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	ULONG offset = (ULONG)Offset;

	DbgPrint(L"ReadFile : %s\n", FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		handle = sFS.FileOpen(FileName, GENERIC_READ, FILE_SHARE_READ, NULL,OPEN_EXISTING, 0);
		closer.SetFile(handle);
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DWORD error = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error);
			return DokanNtStatusFromWin32(error);
		}
	}

	handle->mFilePointer = Offset;

	if (!sFS.ReadFile(handle, Buffer, BufferLength, ReadLength))
	{
		DWORD error = GetLastError();
		DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n",error, BufferLength, *ReadLength);
		return DokanNtStatusFromWin32(error);

	}
	else
	{
		DbgPrint(L"\tByte to read: %d, Byte read %d, offset %d\n\n", BufferLength,*ReadLength, offset);
//		printHexDump((unsigned char *)Buffer, *ReadLength);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
	MirrorWriteFile(
	LPCWSTR		FileName,
	LPCVOID		Buffer,
	DWORD		NumberOfBytesToWrite,
	LPDWORD		NumberOfBytesWritten,
	LONGLONG			Offset,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorWriteFile");
	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", FileName, Offset, NumberOfBytesToWrite);

	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		handle = sFS.FileOpen(FileName,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
		closer.SetFile(handle);
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle, cleanuped?\n");
			return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
		}
	}

	if (DokanFileInfo->WriteToEndOfFile)
	{
		handle->mFilePointer = handle->mFileSize;
	}
	else
	{
		handle->mFilePointer = Offset;
	}

	if (!sFS.WriteFile(handle, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten))
	{
		DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n", GetLastError(), NumberOfBytesToWrite, NumberOfBytesWritten?*NumberOfBytesWritten:-1);
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}
	else
	{
		DbgPrint(L"\twrite %d, offset %I64d, write length = %d\n\n", *NumberOfBytesWritten, Offset, NumberOfBytesWritten?*NumberOfBytesWritten:-1);
	}

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
	MirrorFlushFileBuffers(
	LPCWSTR		FileName,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorFlushFileBuffers");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"FlushFileBuffers : %s\n", FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return 0;
	}

	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorGetFileInformation(
	LPCWSTR							FileName,
	LPBY_HANDLE_FILE_INFORMATION	HandleFileInformation,
	PDOKAN_FILE_INFO				DokanFileInfo)
{
	TIMEOPERATION("MirrorGetFileInformation");
	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"GetFileInfo : %s\n", FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		TIMEOPERATIONUNTILHERE("before FileOpen");
		handle = sFS.FileOpen(FileName,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
		TIMEOPERATIONUNTILHERE("after FileOpen");
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle, cleanuped?\n");
			return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
		}
		closer.SetFile(handle);
		TIMEOPERATIONUNTILHERE("after SetFile");
	}

	TIMEOPERATIONUNTILHERE("before GetFileInformation");
	if (!sFS.GetFileInformation(handle,HandleFileInformation)) {
		DbgPrint(L"\terror code = %d\n", GetLastError());
	} else {
		DbgPrint(L"\tGetFileInformationByHandle success\n\
				  dwFileAttributes=%x\n\
				  ftCreationTime=%x\n\
				  ftLastAccessTime=%x\n\
				  ftLastWriteTime=%x\n",
				  HandleFileInformation->dwFileAttributes,
				  HandleFileInformation->ftCreationTime,
				  HandleFileInformation->ftLastAccessTime,
				  HandleFileInformation->ftLastWriteTime
				  );

		DbgPrint(L"\
				  nFileSizeHigh=%x\n\
				  nFileSizeLow=%x\n",
				  HandleFileInformation->nFileSizeHigh,
				  HandleFileInformation->nFileSizeLow
				  );
	}

	DbgPrint(L"\n");
	TIMEOPERATIONUNTILHERE("after GetFileInformation");

	return STATUS_SUCCESS;
}

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
#define LOCK(s) AutoLocker _locker(s);

static CRITICAL_SECTION sRecentFolderListLock;
static std::map< std::wstring , time_t> sRecentFolderList;
static WCHAR sDriveLetter;

/*
Use SHChangeNotify() to cause the explorer windows to refresh when shared contents changes.
When directories are accessed by MirrorFindFiles this build a list of recent accesses to directories.
At a regular interval in this thread all those entries can be refreshed with SHChangeNotify(). If the shell
window is open then the entry will be refreshed with a more recent time which causes MirrorFindFiles to be triggered again.
Otherwise old entries that don't get refreshed can be expired from the list.
*/
void __cdecl sShellThread(void *)
{
	while (true)
	{
		Sleep(10000);
		TIMEOPERATION("sShellThread");
		time_t theTime;
		time(&theTime);
		LOCK(&sRecentFolderListLock);
		std::map< std::wstring , time_t>::iterator st = sRecentFolderList.begin();
		while (st != sRecentFolderList.end())
		{
			if ( (theTime - (*st).second) > 10 )
			{
				printf("Expire %ws\n",(*st).first.c_str());

				printf("Sending SHCNE_UPDATEDIR for %ws\n",(*st).first.c_str());
				SHChangeNotify(SHCNE_UPDATEDIR,SHCNF_PATHW, (*st).first.c_str(), 0);

				std::map< std::wstring , time_t>::iterator toDel = st++;
				sRecentFolderList.erase(toDel);
				continue;
			}
			st++;
		}
	}
}

static NTSTATUS DOKAN_CALLBACK
	MirrorFindFiles(
	LPCWSTR				FileName,
	PFillFindData		FillFindData, // function pointer
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorFindFiles");
	HANDLE				hFind;
	WIN32_FIND_DATAW	findData;
	DWORD				error;
	int count = 0;

	DbgPrint(L"FindFiles :%s\n", FileName);

	std::wstring newPath(FileName);
	if (newPath.back() != L'\\')
	{
		newPath += L'\\';
	}
	newPath += L'*';

	// Context for the folder refresh list
	{
		time_t theTime;
		time(&theTime);
		LOCK(&sRecentFolderListLock);
		std::wstring realPath;
		realPath += MountPoint;
		realPath += FileName;
		std::pair<std::map<std::wstring , time_t>::iterator,bool> st = sRecentFolderList.insert(std::pair<std::wstring , time_t>(realPath,theTime));
		if (!st.second)
		{
			(*st.first).second = theTime;
		}
	}

	hFind = sFS.FindFirstFileW(newPath.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid file handle. Error is %u\n\n", GetLastError());
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}

	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);

	do {
		if (!rootFolder || (wcscmp(findData.cFileName, L".") != 0 &&
			wcscmp(findData.cFileName, L"..") != 0))
		{
			FillFindData(&findData, DokanFileInfo);
			count++;
		}
	} while (sFS.FindNextFileW(hFind, &findData) != 0);

	error = GetLastError();
	sFS.FindClose(hFind);

	if (error != ERROR_NO_MORE_FILES) {
		DbgPrint(L"\tFindNextFile error. Error is %u\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\tFindFiles return %d entries in %s\n\n", count, FileName);

	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorDeleteFile(
	LPCWSTR				FileName,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorDeleteFile");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"DeleteFile %s\n", FileName);
	if (!sFS.DeleteFile(FileName))
	{
		return -(int)GetLastError();
	}

	return 0;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorDeleteDirectory(
	LPCWSTR				FileName,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorDeleteDirectory");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"DeleteDirectory %s\n", FileName);
	if (!sFS.DeleteFile(FileName))
	{
		return -(int)GetLastError();
	}
	return 0;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorMoveFile(
	LPCWSTR				FileName, // existing file name
	LPCWSTR				NewFileName,
	BOOL				ReplaceIfExisting,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorMoveFile");
	DbgPrint(L"MoveFile %s -> %s\n\n", FileName, NewFileName);

	if (ReplaceIfExisting)
	{
		sFS.DeleteFile(NewFileName);
	}

	BOOL ret = sFS.Rename(FileName,NewFileName);

	if (ret == FALSE)
	{
		DWORD error = GetLastError();
		DbgPrint(L"\tMoveFile failed code = %d\n", error);
		return -(int)error;
	}
	else
	{
		return 0;
	}
}


static NTSTATUS DOKAN_CALLBACK
	MirrorLockFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	LONGLONG			Length,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorLockFile");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"LockFile %s\n", FileName);

#if 0
	handle = (HANDLE)DokanFileInfo->Context;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}

	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (LockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) {
		DbgPrint(L"\tsuccess\n\n");
		return 0;
	} else {
		DbgPrint(L"\tfail\n\n");
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}
#else
	return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
#endif
}


static NTSTATUS DOKAN_CALLBACK
	MirrorSetEndOfFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorSetEndOfFile");
	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"SetEndOfFile %s, %I64d\n", FileName, ByteOffset);

	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		handle = sFS.FileOpen(FileName,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle, cleanuped?\n");
			return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
		}
		closer.SetFile(handle);
	}

	handle->mFilePointer = ByteOffset;

	if (!sFS.SetEndOfFile(handle)) {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\n");
	return 0;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorSetAllocationSize(
	LPCWSTR				FileName,
	LONGLONG			AllocSize,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorSetAllocationSize");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"SetAllocationSize %s, %I64d\n", FileName, AllocSize);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}

#if 0
	if (GetFileSizeEx(handle, &fileSize)) {
		if (AllocSize < fileSize.QuadPart) {
			fileSize.QuadPart = AllocSize;
			if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
				DbgPrint(L"\tSetAllocationSize: SetFilePointer eror: %d, "
					L"offset = %I64d\n\n", GetLastError(), AllocSize);
				return GetLastError() * -1;
			}
			if (!SetEndOfFile(handle)) {
				DWORD error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);
				return DokanNtStatusFromWin32(error);
			}
		}
	} else {
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}
#endif
	return 0;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorSetFileAttributes(
	LPCWSTR				FileName,
	DWORD				FileAttributes,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorSetFileAttributes");
	// Ignore blank file attributes being set
	if (!FileAttributes)
	{
		return 0;
	}
	DbgPrint(L"SetFileAttributes %s\n", FileName);

	if (!sFS.SetFileAttributes(FileName, FileAttributes))
	{
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\n");
	return 0;
}


static NTSTATUS DOKAN_CALLBACK
	MirrorSetFileTime(
	LPCWSTR				FileName,
	CONST FILETIME*		CreationTime,
	CONST FILETIME*		LastAccessTime,
	CONST FILETIME*		LastWriteTime,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorSetFileTime");
	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"SetFileTime %s $%x\n", FileName, (int)handle);

	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		handle = sFS.FileOpen(FileName,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle, cleanuped?\n");
			return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
		}
		closer.SetFile(handle);
	}

	if (!sFS.SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime))
	{
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}

	DbgPrint(L"\n");
	return 0;
}



static NTSTATUS DOKAN_CALLBACK
	MirrorUnlockFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	LONGLONG			Length,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorUnlockFile");
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"UnlockFile %s\n", FileName);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}

#if 0
	length.QuadPart = Length;
	offset.QuadPart = ByteOffset;

	if (UnlockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) {
		DbgPrint(L"\tsuccess\n\n");
		return 0;
	} else {
		DbgPrint(L"\tfail\n\n");
		return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
	}
#endif
	return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
}

static NTSTATUS DOKAN_CALLBACK
	MirrorGetDiskFreeSpace(
	PULONGLONG			FreeBytesAvailable,
	PULONGLONG			TotalNumberOfBytes,
	PULONGLONG			TotalNumberOfFreeBytes,
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorGetDiskFreeSpace");
	// Some sensible defaults if the disk free space code doesn't work
	*FreeBytesAvailable = (ULONGLONG)512* (ULONGLONG)1024* (ULONGLONG)1024* (ULONGLONG)1024;
	*TotalNumberOfBytes = (ULONGLONG)1024* (ULONGLONG)1024* (ULONGLONG)1024 * (ULONGLONG)1024;
	*TotalNumberOfFreeBytes = (ULONGLONG)512* (ULONGLONG)1024* (ULONGLONG)1024 * (ULONGLONG)1024;

	WCHAR drivePath[6];
	drivePath[0] = sDriveLetter;
	drivePath[1] = ':';
	drivePath[2] = 0;

#if 1
#if 1
	ULARGE_INTEGER lFreeBytesAvailableToCaller;
	ULARGE_INTEGER lTotalNumberOfBytes;
	ULARGE_INTEGER lTotalNumberOfFreeBytes;
	if (GetDiskFreeSpaceExW(drivePath,&lFreeBytesAvailableToCaller,&lTotalNumberOfBytes,&lTotalNumberOfFreeBytes))
	{
		*FreeBytesAvailable = lFreeBytesAvailableToCaller.QuadPart;
		*TotalNumberOfBytes = lTotalNumberOfBytes.QuadPart;
		*TotalNumberOfFreeBytes = lTotalNumberOfFreeBytes.QuadPart;
	}
#else
	DWORD spc, bps, fcl, tcl;
	if (GetDiskFreeSpaceW(drivePath,&spc, &bps, &fcl, &tcl))
	{
		*FreeBytesAvailable = ((LONGLONG)fcl)*((LONGLONG)spc)*((LONGLONG)bps);
		*TotalNumberOfFreeBytes = *FreeBytesAvailable;
		*TotalNumberOfBytes = (*FreeBytesAvailable) + sFS.GetLastContainerFileSize();
	}
#endif
#endif

	return 0;
}


static int DOKAN_CALLBACK
	MirrorUnmount(
	PDOKAN_FILE_INFO	DokanFileInfo)
{
	TIMEOPERATION("MirrorUnmount");
	DbgPrint(L"Unmount\n");
	return 0;
}
static NTSTATUS DOKAN_CALLBACK MirrorGetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
	PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo)
{
	TIMEOPERATION("MirrorGetFileSecurity");
	UNREFERENCED_PARAMETER(DokanFileInfo);

	AutoCloseFile closer;
	EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

	DbgPrint(L"GetFileSecurity %s\n", FileName);

	MirrorCheckFlag(*SecurityInformation, FILE_SHARE_READ);
	MirrorCheckFlag(*SecurityInformation, OWNER_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, GROUP_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, SACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, LABEL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
	//  MirrorCheckFlag(*SecurityInformation,
	//                  PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
	MirrorCheckFlag(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

#if 0
	*SecurityInformation &= ~SACL_SECURITY_INFORMATION;
#endif

	BOOLEAN rootFolder = (wcscmp(FileName, L"\\") == 0);
#if 0

	//		if (DokanFileInfo->IsDirectory)
	if (rootFolder)
	{
		// MPi: TODO: Get the security for the container file
		HANDLE handle2 = CreateFile(
			/*L"C:\\temp"*/ContainerPath,
			READ_CONTROL | (((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
			(*SecurityInformation & BACKUP_SECURITY_INFORMATION))
			? ACCESS_SYSTEM_SECURITY
			: 0),
			FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
			NULL, // security attribute
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
			NULL);

		if (!handle2 || handle2 == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle\n\n");
			int error = GetLastError();
			return DokanNtStatusFromWin32(error);
		}

		if (!GetUserObjectSecurity(handle2, SecurityInformation, SecurityDescriptor, BufferLength, LengthNeeded))
		{
			int error = GetLastError();
			if (error == ERROR_INSUFFICIENT_BUFFER)
			{
				DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
				CloseHandle(handle2);
				return STATUS_BUFFER_OVERFLOW /*ERROR_INSUFFICIENT_BUFFER*/;
			}
			else
			{
				DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
				CloseHandle(handle2);
				return DokanNtStatusFromWin32(error);
			}
		}
		CloseHandle(handle2);
		return STATUS_SUCCESS;
	}
	return STATUS_NOT_IMPLEMENTED;
#endif

#if 1
	if (DokanFileInfo->IsDirectory)
	{
		PSECURITY_DESCRIPTOR myDesc;
		ULONG myDescLength;
		// SDDL used by dokan driver
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGX;;;RC)",SDDL_REVISION_1, &myDesc, &myDescLength))
		{
			return STATUS_NOT_IMPLEMENTED;
		}

		if (NULL != LengthNeeded)
		{
			*LengthNeeded = myDescLength;
		}

		if ((NULL == SecurityDescriptor) || (BufferLength < myDescLength))
		{
			LocalFree(myDesc);
			//			return STATUS_BUFFER_OVERFLOW;
			return ERROR_INSUFFICIENT_BUFFER;
		}

#if 1
		LPTSTR pStringBuffer = NULL;
		if (!ConvertSecurityDescriptorToStringSecurityDescriptor(myDesc, SDDL_REVISION_1, *SecurityInformation,&pStringBuffer, NULL))
		{
			LocalFree(myDesc);
			return STATUS_NOT_IMPLEMENTED;
		}
		LocalFree(myDesc);

		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(pStringBuffer, SDDL_REVISION_1, &myDesc, &myDescLength))
		{
			return STATUS_NOT_IMPLEMENTED;
		}

		LocalFree(pStringBuffer);
#endif
		CopyMemory(SecurityDescriptor , myDesc , myDescLength);

		LocalFree(myDesc);
		return STATUS_SUCCESS;
	}

	return STATUS_NOT_IMPLEMENTED;
#endif


#if 1
	if (DokanFileInfo->IsDirectory)
	{
		// SDDL used by dokan driver
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGWGX;;;WD)(A;;GRGX;;;RC)",SDDL_REVISION_1, &SecurityDescriptor, &BufferLength))
		{
			return STATUS_NOT_IMPLEMENTED;
		}

		LPTSTR pStringBuffer = NULL;
		if (!ConvertSecurityDescriptorToStringSecurityDescriptor(SecurityDescriptor, SDDL_REVISION_1, *SecurityInformation,&pStringBuffer, NULL))
		{
			return STATUS_NOT_IMPLEMENTED;
		}

		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(pStringBuffer, SDDL_REVISION_1, &SecurityDescriptor,&BufferLength))
		{
			return STATUS_NOT_IMPLEMENTED;
		}

		if (pStringBuffer != NULL)
			LocalFree(pStringBuffer);

		return STATUS_SUCCESS;
	}
	return STATUS_NOT_IMPLEMENTED;
#endif

#if 0
	if (!handle || handle == INVALID_HANDLE_VALUE)
	{
		handle = sFS.FileOpen(FileName,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			DbgPrint(L"\tinvalid handle, cleanuped?\n");
			return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
		}
		closer.SetFile(handle);
	}

#if 0
	if (!sFS.GetFileSecurity(handle, SecurityInformation, SecurityDescriptor,
		BufferLength, LengthNeeded))
	{
		DWORD error = GetLastError();
		DbgPrint(L"\terror code = %d\n\n", error);
		return DokanNtStatusFromWin32(error);
	}
#endif
#endif

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorSetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
	PDOKAN_FILE_INFO DokanFileInfo) {
	TIMEOPERATION("MirrorSetFileSecurity");
	UNREFERENCED_PARAMETER(SecurityDescriptorLength);

		AutoCloseFile closer;
		EleFSLib::EleFS::File *handle = (EleFSLib::EleFS::File *)DokanFileInfo->Context;

		DbgPrint(L"SetFileSecurity %s\n", FileName);

		if (!handle || handle == INVALID_HANDLE_VALUE)
		{
			handle = sFS.FileOpen(FileName,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);
			if (!handle || handle == INVALID_HANDLE_VALUE)
			{
				DbgPrint(L"\tinvalid handle, cleanuped?\n");
				return DokanNtStatusFromWin32(ERROR_INVALID_FUNCTION);
			}
			closer.SetFile(handle);
		}

#if 0
		if (!sFS.SetFileSecurity(handle, SecurityInformation, SecurityDescriptor)) {
			int error = GetLastError();
			DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
			return DokanNtStatusFromWin32(error);
		}
#endif
		return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorGetVolumeInformation(
	LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo) {
	TIMEOPERATION("MirrorGetVolumeInformation");
	UNREFERENCED_PARAMETER(DokanFileInfo);

		wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"EleFS");
		*VolumeSerialNumber = 0x19831116;
		*MaximumComponentLength = 256;
		*FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
			FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK /*| FILE_PERSISTENT_ACLS*/; // MPi: TODO: Add FILE_PERSISTENT_ACLS support

		// File system name could be anything up to 10 characters.
		// But Windows check few feature availability based on file system name.
		// For this, it is recommended to set NTFS or FAT here.
		wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"NTFS");

		return STATUS_SUCCESS;
}

/*
//Uncomment for personalize disk space
static NTSTATUS DOKAN_CALLBACK MirrorDokanGetDiskFreeSpace(
PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {
UNREFERENCED_PARAMETER(DokanFileInfo);

*FreeBytesAvailable = (ULONGLONG)(512 * 1024 * 1024);
*TotalNumberOfBytes = 9223372036854775807;
*TotalNumberOfFreeBytes = 9223372036854775807;

return STATUS_SUCCESS;
}
*/

/**
* Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
* definition.
* This only for MirrorFindStreams. Link with ntdll.lib still required.
*
* Not needed if you're not using NtQueryInformationFile!
*
* BEGIN
*/
#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#pragma warning(pop)

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
	_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
* END
*/

NTSTATUS DOKAN_CALLBACK
	MirrorFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo) {
	TIMEOPERATION("MirrorFindStreams");
	HANDLE hFind;
		WIN32_FIND_STREAM_DATA findData;
		DWORD error;
		int count = 0;

		DbgPrint(L"FindStreams :%s\n", FileName);

		hFind = FindFirstStreamW(FileName, FindStreamInfoStandard, &findData, 0);

		if (hFind == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
			return DokanNtStatusFromWin32(error);
		}

		FillFindStreamData(&findData, DokanFileInfo);
		count++;

		while (FindNextStreamW(hFind, &findData) != 0) {
			FillFindStreamData(&findData, DokanFileInfo);
			count++;
		}

		error = GetLastError();
		FindClose(hFind);

		if (error != ERROR_HANDLE_EOF) {
			DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
			return DokanNtStatusFromWin32(error);
		}

		DbgPrint(L"\tFindStreams return %d entries in %s\n\n", count, FileName);

		return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorMounted(PDOKAN_FILE_INFO DokanFileInfo) {
	TIMEOPERATION("MirrorMounted");
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DbgPrint(L"Mounted\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK MirrorUnmounted(PDOKAN_FILE_INFO DokanFileInfo) {
	TIMEOPERATION("MirrorUnmounted");
	UNREFERENCED_PARAMETER(DokanFileInfo);

	DbgPrint(L"Unmounted\n");
	return STATUS_SUCCESS;
}

#pragma warning(pop)

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		SetConsoleCtrlHandler(CtrlHandler, FALSE);
		DokanRemoveMountPoint(MountPoint);
		return TRUE;
	default:
		return FALSE;
	}
}

void ShowUsage() {
	fprintf(stderr, "EleFS.exe\n"
		"  /p Password/pass phrase etc. Must be before the /f option. (ex. /p thisIsMyDevicePassword) If there is no password then the device is not encrypted.\n"
		"  /f Container file (ex. /f c:\\Temp\\container.EleFS)\n"
		"  /l MountPoint (ex. /l m)\t\t\t Mount point. Can be M:\\ (drive letter) or empty NTFS folder C:\\mount\\dokan .\n"
		"  /t ThreadCount (ex. /t 5)\t\t\t Number of threads to be used internally by Dokan library.\n\t\t\t\t\t\t More threads will handle more event at the same time.\n"
		"  /d (enable debug output)\t\t\t Enable debug output to an attached debugger.\n"
		"  /s (use stderr for output)\t\t\t Enable debug output to stderr.\n"
		"  /n (use network drive)\t\t\t Show device as network device.\n"
		"  /m (use removable drive)\t\t\t Show device as removable media.\n"
		"  /w (write-protect drive)\t\t\t Read only filesystem.\n"
		"  /o (use mount manager)\t\t\t Register device to Windows mount manager.\n\t\t\t\t\t\t This enables advanced Windows features like recycle bin and more...\n"
		"  /c (mount for current session only)\t\t Device only visible for current user session.\n"
		"  /u (UNC provider name ex. \\localhost\\myfs)\t UNC name used for network volume.\n"
		"  /a Allocation unit size (ex. /a 512)\t\t Allocation Unit Size of the volume. This will behave on the disk file size.\n"
		"  /k Sector size (ex. /k 512)\t\t\t Sector Size of the volume. This will behave on the disk file size.\n"
		"  /r \t\t\t Profile timing for each operation.\n"
		"  /i (Timeout in Milliseconds ex. /i 30000)\t Timeout until a running operation is aborted and the device is unmounted.\n\n"
		"Examples:\n"
		"\tEleFS.exe /p devicePassword /f C:\\Temp\\container.EleFS /l M:\t\t\t# Mount C:\\Temp\\container.EleFS as RootDirectory into a drive of letter M:\\.\n"
		"\tEleFS.exe /f C:\\Temp\\container.EleFS /l C:\\mount\\dokan\t# Mount C:\\Temp\\container.EleFS as RootDirectory into NTFS folder C:\\mount\\dokan.\n"
		"\tEleFS.exe /f C:\\Temp\\container.EleFS /l M: /n /u \\myfs\\myfs1\t# Mount C:\\Temp\\container.EleFS as RootDirectory into a network drive M:\\. with UNC \\\\myfs\\myfs1\n\n"
		"Unmount the drive with CTRL + C in the console or alternatively via \"dokanctl /u MountPoint\".\n");
}

int __cdecl wmain(ULONG argc, PWCHAR argv[])
{
	int status;
	ULONG command;

	InitializeCriticalSection(&sRecentFolderListLock);

	_beginthread(sShellThread,0,0);

	PDOKAN_OPERATIONS dokanOperations = (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	if (dokanOperations == NULL)
	{
		return EXIT_FAILURE;
	}
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
	if (dokanOptions == NULL)
	{
		free(dokanOperations);
		return EXIT_FAILURE;
	}

	if (argc < 3)
	{
		ShowUsage();
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	g_DebugMode = FALSE;
	g_UseStdErr = FALSE;
	gTimeOperations = FALSE;

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	WCHAR *password = 0;

	for (command = 1; command < argc; command++)
	{
		switch (towlower(argv[command][1]))
		{
		case 'r':
			gTimeOperations = TRUE;
			break;
		case 'p':
			command++;
			DbgPrint(L"Using encryption\n");
			password = argv[command];
			break;
		case 'f':
			command++;
			DbgPrint(L"ContainerPath: %ls\n", argv[command]);
			wcscpy_s(ContainerPath, sizeof(ContainerPath) / sizeof(WCHAR), argv[command]);
			sDriveLetter = argv[command][0];
			if (0 != password)
			{
				sFS.Initialise(argv[command] , password , wcslen(password) * sizeof(WCHAR));
			}
			else
			{
				sFS.Initialise(argv[command]);
			}
			break;
		case L'l':
			command++;
			wcscpy_s(MountPoint, sizeof(MountPoint) / sizeof(WCHAR), argv[command]);
			dokanOptions->MountPoint = MountPoint;
			break;
		case L't':
			command++;
			dokanOptions->ThreadCount = (USHORT)_wtoi(argv[command]);
			break;
		case L'd':
			g_DebugMode = TRUE;
			break;
		case L's':
			g_UseStdErr = TRUE;
			break;
		case L'n':
			dokanOptions->Options |= DOKAN_OPTION_NETWORK;
			break;
		case L'm':
			dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
			break;
		case L'w':
			dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
			break;
		case L'o':
			dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
			break;
		case L'c':
			dokanOptions->Options |= DOKAN_OPTION_CURRENT_SESSION;
			break;
		case L'u':
			command++;
			wcscpy_s(UNCName, sizeof(UNCName) / sizeof(WCHAR), argv[command]);
			dokanOptions->UNCName = UNCName;
			DbgPrint(L"UNC Name: %ls\n", UNCName);
			break;
		case L'i':
			command++;
			dokanOptions->Timeout = (ULONG)_wtol(argv[command]);
			break;
		case L'a':
			command++;
			dokanOptions->AllocationUnitSize = (ULONG)_wtol(argv[command]);
			break;
		case L'k':
			command++;
			dokanOptions->SectorSize = (ULONG)_wtol(argv[command]);
			break;
		default:
			fwprintf(stderr, L"unknown command: %s\n", argv[command]);
			free(dokanOperations);
			free(dokanOptions);
			return EXIT_FAILURE;
		}
	}

	if (wcscmp(UNCName, L"") != 0 &&
		!(dokanOptions->Options & DOKAN_OPTION_NETWORK)) {
			fwprintf(
				stderr,
				L"  Warning: UNC provider name should be set on network drive only.\n");
	}

	if (dokanOptions->Options & DOKAN_OPTION_NETWORK &&
		dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER)
	{
		fwprintf(stderr, L"Mount manager cannot be used on network drive.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!(dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) && wcscmp(MountPoint, L"") == 0)
	{
		fwprintf(stderr, L"Mount Point required.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if ((dokanOptions->Options & DOKAN_OPTION_MOUNT_MANAGER) &&	(dokanOptions->Options & DOKAN_OPTION_CURRENT_SESSION))
	{
		fwprintf(stderr, L"Mount Manager always mount the drive for all user sessions.\n");
		free(dokanOperations);
		free(dokanOptions);
		return EXIT_FAILURE;
	}

	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
	{
		fwprintf(stderr, L"Control Handler is not set.\n");
	}

	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	if (!AddSeSecurityNamePrivilege())
	{
		fwprintf(stderr, L"Failed to add security privilege to process\n");
		fwprintf(stderr,
			L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n");
		fwprintf(stderr, L"\t=> Please restart mirror sample with administrator "
			L"rights to fix it\n");
	}

	if (g_DebugMode)
	{
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;
	}
	if (g_UseStdErr)
	{
		dokanOptions->Options |= DOKAN_OPTION_STDERR;
	}

	dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;


	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->ZwCreateFile = MirrorCreateFile;
	dokanOperations->Cleanup = MirrorCleanup;
	dokanOperations->CloseFile = MirrorCloseFile;
	dokanOperations->ReadFile = MirrorReadFile;
	dokanOperations->WriteFile = MirrorWriteFile;
	dokanOperations->FlushFileBuffers = MirrorFlushFileBuffers;
	dokanOperations->GetFileInformation = MirrorGetFileInformation;
	dokanOperations->FindFiles = MirrorFindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = MirrorSetFileAttributes;
	dokanOperations->SetFileTime = MirrorSetFileTime;
	dokanOperations->DeleteFile = MirrorDeleteFile;
	dokanOperations->DeleteDirectory = MirrorDeleteDirectory;
	dokanOperations->MoveFile = MirrorMoveFile;
	dokanOperations->SetEndOfFile = MirrorSetEndOfFile;
	dokanOperations->SetAllocationSize = MirrorSetAllocationSize;
	dokanOperations->LockFile = MirrorLockFile;
	dokanOperations->UnlockFile = MirrorUnlockFile;
	//dokanOperations->GetFileSecurity = MirrorGetFileSecurity;
	//dokanOperations->SetFileSecurity = MirrorSetFileSecurity;
	dokanOperations->SetFileSecurity = NULL;
	dokanOperations->GetDiskFreeSpace = MirrorGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = MirrorGetVolumeInformation;
	dokanOperations->Unmounted = MirrorUnmounted;
	dokanOperations->FindStreams = NULL;//MirrorFindStreams;
	dokanOperations->Mounted = MirrorMounted;

	status = DokanMain(dokanOptions, dokanOperations);
	switch (status) {
	case DOKAN_SUCCESS:
		fprintf(stderr, "Success\n");
		break;
	case DOKAN_ERROR:
		fprintf(stderr, "Error\n");
		break;
	case DOKAN_DRIVE_LETTER_ERROR:
		fprintf(stderr, "Bad Drive letter\n");
		break;
	case DOKAN_DRIVER_INSTALL_ERROR:
		fprintf(stderr, "Can't install driver\n");
		break;
	case DOKAN_START_ERROR:
		fprintf(stderr, "Driver something wrong\n");
		break;
	case DOKAN_MOUNT_ERROR:
		fprintf(stderr, "Can't assign a drive letter\n");
		break;
	case DOKAN_MOUNT_POINT_ERROR:
		fprintf(stderr, "Mount point error\n");
		break;
	case DOKAN_VERSION_ERROR:
		fprintf(stderr, "Version error\n");
		break;
	default:
		fprintf(stderr, "Unknown error: %d\n", status);
		break;
	}

	free(dokanOptions);
	free(dokanOperations);
	return EXIT_SUCCESS;
}
