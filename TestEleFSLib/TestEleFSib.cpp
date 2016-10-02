#include <stdio.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <assert.h>
#include <process.h>
#include <list>
#include "EleFSLib/Inc/EleFS.h"
#include "BlobFileLib/Inc/BlobFile.h"


#pragma comment( lib, "EleFSLib.lib" )

//#define testIterations 10000
#define testIterations 100

void PrintFailed(const char *error)
{
	printf("FAILED: %s\n",error);
	exit(-1);
}

#define CheckBlobHandle(x)	\
	if ( !(x) )	PrintFailed("Blob handle " #x " is null");

#define CheckFail(x)	\
	if ( !(x) )	PrintFailed(#x " failed");

// Run some file operation tests using a repeatable test
void RunTest(int offset)
{
	EleFSLib::EleFS fs;
	CheckFail(fs.Initialise(L"Test2.EleFS"));

	int i;
	for (i=0;i<testIterations;i++)
	{
		EleFSLib::EleFS::File *file;

		WCHAR theName[MAX_PATH];
		swprintf(theName,MAX_PATH,L"ThreadFile%d",(i&15) + offset);

		printf("Iter %d:%d %ws\r",GetCurrentThreadId(),i,theName);

		// If there are lots of iterations then test the delete code as well
		if ( (testIterations >= 1000) && (i < (testIterations/10)) && !((i&255) <= (240 - (i&15))) )
		{
			fs.DeleteFile(theName);
		}

		file = fs.FileOpen(theName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL);
		CheckFail(file);
		if ( (i&255) <= (240 - (i&15)) )
		{
			file->mFilePointer = file->mFileSize;
		}
		DWORD toWrite = (i&15)+1,written;
		CheckFail(fs.WriteFile(file,"Hello World 0123456789", toWrite, &written));
		CheckFail(written == toWrite);
		CheckFail(fs.CloseFile(file));

		if ( (i&7) <= 4 )
		{
			Sleep(1);
		}
	}
}

static volatile bool sThreadended = false;
void OtherThread(void *context)
{
	RunTest((int)context);
	sThreadended = true;
}

static volatile bool sThreadended2 = false;
void OtherThread2(void *context)
{
	RunTest((int)context);
	sThreadended2 = true;
}

void CheckExpectedFindFile(EleFSLib::EleFS &fs, LPCWSTR path, std::list<std::wstring> &expected)
{
	std::list<std::wstring> findResult;

	WIN32_FIND_DATAW ffInfo;
	printf("FF Test of '%ws'\n",path);
	HANDLE ffHandle = fs.FindFirstFileW(path,&ffInfo);
	if (ffHandle != INVALID_HANDLE_VALUE)
	{
		do 
		{
			printf("Name: %ws\n",ffInfo.cFileName);
			findResult.push_back(ffInfo.cFileName);
		} while (fs.FindNextFileW(ffHandle,&ffInfo));
		CheckFail(fs.FindClose(ffHandle));
	}

	std::list<std::wstring>::iterator st,st2;
	st = expected.begin();
	st2 = findResult.begin();
	while ((st != expected.end()) && (st2 != findResult.end()))
	{
		std::wstring name1,name2;
		name1 = *st++;
		name2 = *st2++;
		if (name1 != name2)
		{
			printf("Different expected names '%ws' '%ws'\n",name1.c_str(),name2.c_str());
			PrintFailed("");
		}
	}
	if ((st != expected.end()) || (st2 != findResult.end()))
	{
		PrintFailed("List lengths did not match");
	}
}

int main(int argc, char **argv)
{
#ifdef _WIN32
#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_ALLOC_MEM_DF);

	_CrtMemState stateDiff;
	_CrtMemState stateStart;
	_CrtMemCheckpoint(&stateStart);
#endif
#endif

	// Stack context
	{
		DeleteFile(L"Test.EleFS");

		HANDLE theHandle = CreateFileW(L"Test.EleFS",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
		if (theHandle == INVALID_HANDLE_VALUE)
		{
			PrintFailed("Couldn't open the file");
		}

		BlobFileLib::BlobFile blobFile(theHandle);

		LONGLONG testHandle = 0x123456789abcdef;
		blobFile.SetApplicationData(testHandle);
		if (blobFile.GetApplicationData() != testHandle)
		{
			PrintFailed("Handle mismatch");
		}

		LONGLONG b1,b2,b3,b4;
		// Test multiple new allocations
		b1 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b1);
		b2 = blobFile.AllocateBlock(64);
		CheckBlobHandle(b2);
		b3 = blobFile.AllocateBlock(128);
		CheckBlobHandle(b3);
		b4 = blobFile.AllocateBlock(96);
		CheckBlobHandle(b4);
		// Test end freeing
		CheckFail(blobFile.FreeBlock(b4));
		// Test middle block free
		CheckFail(blobFile.FreeBlock(b2));
		// Test block merge and file size truncate
		CheckFail(blobFile.FreeBlock(b3));
		CheckFail(blobFile.FreeBlock(b1));

		// Test block allocation when there are free blocks
		// Block splitting allocation
		b1 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b1);
		b2 = blobFile.AllocateBlock(64);
		CheckBlobHandle(b2);
		b3 = blobFile.AllocateBlock(128);
		CheckBlobHandle(b3);
		b4 = blobFile.AllocateBlock(96);
		CheckBlobHandle(b4);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b3));
		b1 = blobFile.AllocateBlock(32);	// Block split
		CheckBlobHandle(b1);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b2));
		CheckFail(blobFile.FreeBlock(b4));

		// Non-extending allocation
		b1 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b1);
		b2 = blobFile.AllocateBlock(64);
		CheckBlobHandle(b2);
		b3 = blobFile.AllocateBlock(128);
		CheckBlobHandle(b3);
		b4 = blobFile.AllocateBlock(96);
		CheckBlobHandle(b4);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b3));
		b1 = blobFile.AllocateBlock(150);	// No file extend
		CheckBlobHandle(b1);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b2));
		CheckFail(blobFile.FreeBlock(b4));


		// Extending allocation
		b1 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b1);
		b2 = blobFile.AllocateBlock(64);
		CheckBlobHandle(b2);
		b3 = blobFile.AllocateBlock(128);
		CheckBlobHandle(b3);
		b4 = blobFile.AllocateBlock(96);
		CheckBlobHandle(b4);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b3));
		b1 = blobFile.AllocateBlock(250);	// File extend
		CheckBlobHandle(b1);
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b2));
		CheckFail(blobFile.FreeBlock(b4));


		// Test resize with various scenarios
		b1 = blobFile.AllocateBlock(256);
		CheckBlobHandle(b1);
		CheckFail(blobFile.ResizeBlock(b1,320));	// File extend
		CheckFail(blobFile.ResizeBlock(b1,256));	// File truncate
		CheckFail(blobFile.FreeBlock(b1));

		b1 = blobFile.AllocateBlock(256);
		CheckBlobHandle(b1);
		b2 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b2);
		CheckFail(blobFile.ResizeBlock(b1,64));	// Creates a free block
		CheckFail(blobFile.ResizeBlock(b1,256));	// Uses the whole free block
		CheckFail(blobFile.ResizeBlock(b1,64));	// Creates a free block
		CheckFail(blobFile.ResizeBlock(b1,128));	// Uses part of the free block
		b3 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b3);
		CheckFail(blobFile.ResizeBlock(b1,256));
		b4 = blobFile.AllocateBlock(32);
		CheckBlobHandle(b4);
		CheckFail(blobFile.ResizeBlock(b1,16));	// Causes a chain of more than one block to be unlinked and moved to the free list

		char *testBlock = (char*) malloc(65536);
		assert(testBlock);
		char *testBlock2 = (char*) malloc(65536);
		assert(testBlock2);
		int i,j;
		for (i=0;i<256;i++)
		{
			for (j=0;j<256;j++)
			{
				testBlock[i+(j*256)] = (char) i+j;
			}
		}

		DWORD numBytes;
		if (!blobFile.WriteBlock(b1,testBlock,65536,0,&numBytes))
		{
			PrintFailed("Could not write to block\n");
		}
		// Aligned block length = 64
		if (numBytes != 64)
		{
			PrintFailed("Could not write expected number of bytes\n");
		}

		if (!blobFile.ReadBlock(b1,testBlock2,65536,16,&numBytes))
		{
			PrintFailed("Could not read from block\n");
		}
		// Aligned block length minus 16 = 48
		if (numBytes != 48)
		{
			PrintFailed("Could not read expected number of bytes\n");
		}
		if (memcmp(testBlock+16,testBlock2,48))
		{
			PrintFailed("Offset read didn't find expected data\n");
		}

		CheckFail(blobFile.ResizeBlock(b1,1024));
		if (!blobFile.WriteBlock(b1,testBlock,65536,0,&numBytes))
		{
			PrintFailed("Could not write to block\n");
		}
		// 0x410 because there is a merged free block used, so we have extra old header data being used for the block data
		if (numBytes != 0x410)
		{
			PrintFailed("Could not write expected number of bytes\n");
		}

		if (!blobFile.ReadBlock(b1,testBlock2,65536,16,&numBytes))
		{
			PrintFailed("Could not read from block\n");
		}
		if (numBytes != 0x400)
		{
			PrintFailed("Could not read expected number of bytes\n");
		}
		if (memcmp(testBlock+16,testBlock2,0x400))
		{
			PrintFailed("Offset read didn't find expected data\n");
		}

		// Test freeing all blocks
		CheckFail(blobFile.FreeBlock(b1));
		CheckFail(blobFile.FreeBlock(b2));
		CheckFail(blobFile.FreeBlock(b3));
		CheckFail(blobFile.FreeBlock(b4));

		CloseHandle(theHandle);


		DeleteFile(L"Test2.EleFS");
		EleFSLib::EleFS fs;
		CheckFail(fs.Initialise(L"Test2.EleFS"));

		EleFSLib::EleFS::File *file;

		CheckFail(fs.CreateDirectory(L"Directory1"));

		std::list<std::wstring> expected;
		expected.push_back(L".");
		expected.push_back(L"..");
		CheckExpectedFindFile(fs, L"\\Directory1\\", expected);

		file = fs.FileOpen(L"RootMoo.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL);
		CheckFail(fs.CloseFile(file));

		CheckFail(fs.CreateDirectory(L"Directory1"));
		CheckFail(fs.CreateDirectory(L"Directory1\\\\Directory2"));
		CheckFail(fs.CreateDirectory(L"Directory3\\Directory4"));

		file = fs.FileOpen(L"Directory1\\Directory2\\Moo.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL);

		if (!fs.WriteFile(file,testBlock,256,&numBytes))
		{
			PrintFailed("Failed to write EleFS file");
		}
		if (numBytes != 256)
		{
			PrintFailed("Failed to get the expected number of written bytes");
		}

		CheckFail(fs.CloseFile(file));

		file = fs.FileOpen(L"Directory1\\Directory2\\Moo.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL);

		if (!fs.WriteFile(file,testBlock,256,&numBytes))
		{
			PrintFailed("Failed to write EleFS file");
		}
		if (numBytes != 256)
		{
			PrintFailed("Failed to get the expected number of written bytes");
		}

		CheckFail(fs.CloseFile(file));


		DWORD attrs;
		attrs = fs.GetFileAttributes(L"\\");
		CheckFail(attrs == FILE_ATTRIBUTE_DIRECTORY);
		attrs = fs.GetFileAttributes(L"\\Directory1\\Directory2\\");
		CheckFail(attrs == FILE_ATTRIBUTE_DIRECTORY);
		attrs = fs.GetFileAttributes(L"Directory1\\Directory2\\Moo.txt");
		CheckFail(attrs == FILE_ATTRIBUTE_NORMAL);
		attrs = fs.GetFileAttributes(L"Directory1\\Directory2\\ReallyNotThereFile.txt");
		CheckFail(attrs == INVALID_FILE_ATTRIBUTES);



		file = fs.FileOpen(L"Directory1\\Directory2\\Moo.txt",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL);

		ZeroMemory(testBlock2,65536);

		// Deliberate large read should still report 256 bytes
		if (!fs.ReadFile(file,testBlock2,65536,&numBytes))
		{
			PrintFailed("Failed to read EleFS file");
		}
		if (numBytes != 256)
		{
			PrintFailed("Failed to get the expected number of written bytes");
		}

		if (memcmp(testBlock,testBlock2,256))
		{
			PrintFailed("Read didn't find expected data\n");
		}

		BY_HANDLE_FILE_INFORMATION info;
		if (!fs.GetFileInformation(file,&info))
		{
			PrintFailed("Couldn't get file info\n");
		}
		CheckFail(info.dwFileAttributes == FILE_ATTRIBUTE_NORMAL);

		expected.clear();
		expected.push_back(L".");
		expected.push_back(L"..");
		expected.push_back(L"Directory3");
		expected.push_back(L"RootMoo.txt");
		expected.push_back(L"Directory1");
		CheckExpectedFindFile(fs, L"\\*", expected);

		expected.clear();
		expected.push_back(L".");
		expected.push_back(L"..");
		expected.push_back(L"Directory4");
		CheckExpectedFindFile(fs, L"\\Directory3\\*", expected);

		expected.clear();
		expected.push_back(L".");
		expected.push_back(L"..");
		expected.push_back(L"Directory2");
		CheckExpectedFindFile(fs, L"\\Directory1\\*", expected);

		expected.clear();
		expected.push_back(L".");
		expected.push_back(L"..");
		expected.push_back(L"Moo.txt");
		CheckExpectedFindFile(fs, L"\\Directory1\\Directory2\\*", expected);

		ZeroMemory(testBlock2,65536);

		file->mFilePointer = 32;
		CheckFail(fs.SetEndOfFile(file));

		// Deliberate large read should still report 16 bytes
		file->mFilePointer = 16;
		if (!fs.ReadFile(file,testBlock2,65536,&numBytes))
		{
			PrintFailed("Failed to read EleFS file");
		}
		if (numBytes != 16)
		{
			PrintFailed("Failed to get the expected number of written bytes");
		}

		if (memcmp(testBlock+16,testBlock2,16))
		{
			PrintFailed("Read didn't find expected data\n");
		}

		FILETIME created,accessed,written;
		CheckFail(fs.GetFileTime(file,&created,&accessed,&written));
		created.dwLowDateTime++;
		accessed.dwLowDateTime++;
		written.dwLowDateTime++;
		CheckFail(fs.SetFileTime(file,&created,&accessed,&written));
		FILETIME created2,accessed2,written2;
		CheckFail(fs.GetFileTime(file,&created2,&accessed2,&written2));
		CheckFail(!memcmp(&created, &created2, sizeof(created)));
		CheckFail(!memcmp(&accessed, &accessed2, sizeof(accessed)));
		CheckFail(!memcmp(&written, &written2, sizeof(written)));

		delete file;

		CheckFail(fs.SetFileAttributes(L"RootMoo.txt",FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE));
		attrs = fs.GetFileAttributes(L"RootMoo.txt");
		CheckFail(attrs == (FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE));

		CheckFail(fs.Rename(L"RootMoo.txt",L"RootMoo2.txt"));
		CheckFail(fs.Rename(L"RootMoo2.txt",L"Directory3\\RootMoo2.txt"));

		CheckFail(fs.DeleteFile(L"Directory3\\RootMoo2.txt"));


		printf("Check threaded access\n");
		// First create the base test file without other threads
		RunTest(0);
		// Now run three threads all doing the same thing
		_beginthread(OtherThread,0,(void*)1000000);
		_beginthread(OtherThread2,0,(void*)2000000);
		RunTest(3000000);
		while (!(sThreadended && sThreadended2))
		{
			Sleep(1);
		}

		// The files from the threads should be identical to the files created outside of the threads test.
		printf("\nChecking file contents\n");
		for (i=0;i<16;i++)
		{
			EleFSLib::EleFS::File *files[3];
			BY_HANDLE_FILE_INFORMATION info[3];

			int j;
			for (j=0;j<3;j++)
			{
				WCHAR theName[MAX_PATH];
				swprintf(theName,MAX_PATH,L"ThreadFile%d",i + (j*1000000));
				files[j] = fs.FileOpen(theName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL);
				CheckFail(files[j]);
				CheckFail(fs.GetFileInformation(files[j],info+j));
				CheckFail(info[0].dwFileAttributes == info[j].dwFileAttributes);
				CheckFail(info[0].nFileSizeLow == info[j].nFileSizeLow);
				CheckFail(info[j].nFileSizeLow <= 65536);
			}

			DWORD bytesRead;
			CheckFail(fs.ReadFile(files[0],testBlock,65536,&bytesRead));
			CheckFail(bytesRead == info[0].nFileSizeLow);

			for (j=1;j<3;j++)
			{
				CheckFail(fs.ReadFile(files[j],testBlock2,65536,&bytesRead));
				CheckFail(bytesRead == info[j].nFileSizeLow);
				if (memcmp(testBlock,testBlock2,bytesRead))
				{
					PrintFailed("File contents mismatch");
				}
			}

			for (j=0;j<3;j++)
			{
				CheckFail(fs.CloseFile(files[j]));
			}
		}


		free(testBlock);
		free(testBlock2);

	} //< End of stack context

#ifdef _WIN32
#ifdef _DEBUG
	_CrtMemState stateEnd;
	_CrtMemCheckpoint(&stateEnd);
	int anyDiff = _CrtMemDifference(&stateDiff,&stateStart,&stateEnd);
	_CrtMemDumpAllObjectsSince(&stateDiff);
	if (anyDiff)
	{
		PrintFailed("Memory leak problems");
	}

#endif
#endif

	printf("TEST PASSED!\n");

	return 0;
}
