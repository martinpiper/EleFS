#include <windows.h>
#include <assert.h>
#include <map>
#include "BlobFileLib/Inc/BlobFile.h"

namespace BlobFileLib
{

#define kBlockSizeAlign 64	// Must be a least sizeof(BlockLink) plus a little bit extra to be avoid too much fragmentation and a power of two in size.

#pragma pack(push,1)
	struct BlockLink
	{
		BlockLink() : mBlockDataSize(0) , mNext(0)
		{
		}

		LONGLONG mBlockDataSize;
		LONGLONG mNext;
	};
#pragma pack(pop)

	struct BlockInfo
	{
		LONGLONG mPrevious;
		LONGLONG mNext;
		LONGLONG mBlockDataSize;
	};


	BlobFile::BlobFile(HANDLE fileHandle) : mLockedHandle(fileHandle)
	{
		assert((kBlockSizeAlign >= (sizeof(BlockLink)+32)) && "kBlockSizeAlign is too small");
	}

	BlobFile::~BlobFile()
	{
	}

	bool BlobFile::SetApplicationData(const LONGLONG handle)
	{
		ScopedHeader header(mHeader,mLockedHandle);
		mHeader.mApplicationData = handle;
		return true;
	}

	LONGLONG BlobFile::GetApplicationData(void)
	{
		ScopedHeader header(mHeader,mLockedHandle);
		return mHeader.mApplicationData;
	}


	LONGLONG BlobFile::AllocateBlock(const LONGLONG size)
	{
		ScopedHeader header(mHeader,mLockedHandle);

		return InternalAllocateBlock(size);
	}

	LONGLONG BlobFile::InternalAllocateBlock(const LONGLONG size)
	{
		LONGLONG alignedSize = (size + kBlockSizeAlign - 1) & ~(((LONGLONG)kBlockSizeAlign)-1);
		if (!size)
		{
			alignedSize = kBlockSizeAlign;
		}

		DWORD numBytes;
		LARGE_INTEGER fileSize;

		LONGLONG sizeToAllocate = alignedSize;
		LONGLONG newHandle = 0;
		LONGLONG lastBlockUpdated = 0;


		// See if there is a free block that can begin to accommodate this allocation request
		if (mHeader.mFreeBlock)
		{
			newHandle = mHeader.mFreeBlock;
			while (sizeToAllocate && mHeader.mFreeBlock)
			{
				LARGE_INTEGER filePos;
				lastBlockUpdated = mHeader.mFreeBlock;
				filePos.QuadPart = mHeader.mFreeBlock;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				BlockLink blockLink;
				mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

				LONGLONG availableSize = blockLink.mBlockDataSize - sizeof(BlockLink);

				mHeader.mFreeBlock = blockLink.mNext;
				// If the requested size is larger than the block, or the block is too small to split...
				// Also check for not creating a split block with too little free size by using (sizeToAllocate + kBlockSizeAlign)
				if (((sizeToAllocate + kBlockSizeAlign) > availableSize) || (availableSize < (kBlockSizeAlign*2)))
				{
					// Use the entire block for this new request.
					if (sizeToAllocate > availableSize)
					{
						sizeToAllocate -= availableSize;
					}
					else
					{
						// Last block to allocate so unlink it here
						blockLink.mNext = 0;
						sizeToAllocate = 0;
					}

					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				}
				else
				{
					LONGLONG backupNextFree = blockLink.mNext;

					// Split this block, it will also be the last block to allocate for this request
					blockLink.mNext = 0;
					blockLink.mBlockDataSize = sizeToAllocate + sizeof(BlockLink);

					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
					availableSize -= blockLink.mBlockDataSize;

					// The split position
					filePos.QuadPart = lastBlockUpdated + sizeToAllocate + sizeof(BlockLink);
					// This is the new head free block
					mHeader.mFreeBlock = filePos.QuadPart;
					blockLink.mNext = backupNextFree;
					blockLink.mBlockDataSize = availableSize + sizeof(BlockLink);
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

					sizeToAllocate = 0;
				}
			}
		}

		if (sizeToAllocate)
		{
			alignedSize = (sizeToAllocate + kBlockSizeAlign - 1) & ~(((LONGLONG)kBlockSizeAlign)-1);

			// If there is any size left to request then allocate it at the end of the file
			if (lastBlockUpdated)
			{
				// Get the end position we are going to write to
				LARGE_INTEGER endPos;
				GetFileSizeEx(mLockedHandle,&endPos);

				// Remember to update lastBlockUpdated if it exists, if which case this is a BlockLink
				fileSize.QuadPart = lastBlockUpdated;
				SetFilePointerEx(mLockedHandle,fileSize,0,FILE_BEGIN);
				BlockLink oldBlockLink;
				mCrypto.ReadFile(mLockedHandle,&oldBlockLink,sizeof(oldBlockLink),&numBytes,0);
				oldBlockLink.mNext = endPos.QuadPart;
				SetFilePointerEx(mLockedHandle,fileSize,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&oldBlockLink,sizeof(oldBlockLink),&numBytes,0);
			}

			// Then write a new BlockLink at the end of the file
			fileSize.QuadPart = 0;
			SetFilePointerEx(mLockedHandle,fileSize,&fileSize,FILE_END);
			if (!lastBlockUpdated)
			{
				newHandle = fileSize.QuadPart;
			}
			BlockLink blockLink;
			blockLink.mBlockDataSize = alignedSize + sizeof(BlockLink);
			mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

			LARGE_INTEGER movement;
			movement.QuadPart = alignedSize;
			SetFilePointerEx(mLockedHandle,movement,0,FILE_CURRENT);
			SetEndOfFile(mLockedHandle);
		}

		return newHandle;
	}

	bool BlobFile::FreeBlock(LONGLONG handle)
	{
		if (!IsValidHandle(handle))
		{
			return false;
		}

		ScopedHeader header(mHeader,mLockedHandle);
		return InternalFreeBlock(handle);
	}

	bool BlobFile::InternalFreeBlock(LONGLONG handle)
	{
		DWORD numBytes;

		LONGLONG previousFreeHead = mHeader.mFreeBlock;
		LONGLONG oldBlockPos = 0;

		LONGLONG pos = handle;

		std::map<LONGLONG,BlockInfo> blockPos;

		mHeader.mFreeBlock = handle;

		// Loop through all blocks in this block
		while (pos) 
		{
			LARGE_INTEGER filePos;
			filePos.QuadPart = pos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

			BlockLink blockLink;
			mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
			if (numBytes < sizeof(BlockLink))
			{
				// MPi: TODO: Handle the corrupt block
				pos = 0;
			}
			else
			{
				BlockInfo info;
				info.mBlockDataSize = blockLink.mBlockDataSize;
				info.mPrevious = oldBlockPos;
				oldBlockPos = pos;
				pos = blockLink.mNext;
				// If it is the last BlockLink then point it to what the header said
				if (!blockLink.mNext && previousFreeHead)
				{
					blockLink.mNext = previousFreeHead;
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				}
				info.mNext = blockLink.mNext;
				blockPos.insert(std::pair<LONGLONG,BlockInfo>(filePos.QuadPart,info));
			}
		}

		// Block optimization...
		// Add the next XX blocks from the existing free list.
		pos = previousFreeHead;
		size_t added = 0;
		while ((added < 10) && pos)
		{
			added++;

			LARGE_INTEGER filePos;
			filePos.QuadPart = pos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

			BlockLink blockLink;
			DWORD numBytes;
			mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
			if (numBytes < sizeof(BlockLink))
			{
				// MPi: TODO: Handle the corrupt block
				pos = 0;
			}
			else
			{
				BlockInfo info;
				info.mBlockDataSize = blockLink.mBlockDataSize;
				info.mPrevious = oldBlockPos;
				oldBlockPos = pos;
				info.mNext = blockLink.mNext;
				blockPos.insert(std::pair<LONGLONG,BlockInfo>(pos,info));
				pos = blockLink.mNext;
			}
		}

		// Then go through all the blocks in the map and see if any blocks can be merged
		std::map<LONGLONG,BlockInfo>::iterator st = blockPos.begin();
		while (st != blockPos.end())
		{
			BlockInfo &info1 = (*st).second;
			std::map<LONGLONG,BlockInfo>::iterator next = st;
			next++;
			if (next == blockPos.end())
			{
				break;
			}
			BlockInfo &info2 = (*next).second;
			// If the first block is right next to the second block
			if ( ((*st).first + info1.mBlockDataSize) == (*next).first )
			{
				// Merge the blocks by removing info2 from the link list
				info1.mBlockDataSize += info2.mBlockDataSize;
				std::map<LONGLONG,BlockInfo>::iterator found;
				found = blockPos.find(info2.mPrevious);
				if (found != blockPos.end())
				{
					BlockInfo &toUpdate = (*found).second;
					toUpdate.mNext = info2.mNext;

					// Update the file next block link
					LARGE_INTEGER filePos;
					filePos.QuadPart = (*found).first;
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					BlockLink blockLink;
					mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
					blockLink.mNext = toUpdate.mNext;
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				}

				found = blockPos.find(info2.mNext);
				if (found != blockPos.end())
				{
					// This one only unlinks the BlockInfo from the map, it doesn't need to update the file because it only has
					// next links.
					BlockInfo &toUpdate = (*found).second;
					toUpdate.mPrevious = info2.mPrevious;
				}

				if (mHeader.mFreeBlock == (*next).first)
				{
					mHeader.mFreeBlock = info2.mNext;
				}

				// Update the merged block in the file
				LARGE_INTEGER filePos;
				filePos.QuadPart = (*st).first;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				BlockLink blockLink;
				mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				blockLink.mNext = info1.mNext;
				blockLink.mBlockDataSize = info1.mBlockDataSize;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

				// Remove the merged block from the list
				blockPos.erase(next);
				continue;
			}

			st++;
		}

		// Then check if a free block is at the end of the file and truncate the file
		LARGE_INTEGER fileSize;
		GetFileSizeEx(mLockedHandle, &fileSize);

		std::map<LONGLONG,BlockInfo>::iterator found = --blockPos.end();
		BlockInfo &info = (*found).second;

		if (fileSize.QuadPart == ((*found).first + info.mBlockDataSize))
		{
			// Time to shrink the file
			LARGE_INTEGER filePos;
			filePos.QuadPart = (*found).first;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
			SetEndOfFile(mLockedHandle);

			if (mHeader.mFreeBlock == (*found).first)
			{
				mHeader.mFreeBlock = info.mNext;
			}

			if (info.mPrevious)
			{
				// Update the previous block to point to the next block
				filePos.QuadPart = info.mPrevious;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

				BlockLink oldBlockLink;
				mCrypto.ReadFile(mLockedHandle,&oldBlockLink,sizeof(oldBlockLink),&numBytes,0);
				oldBlockLink.mNext = info.mNext;

				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&oldBlockLink,sizeof(oldBlockLink),&numBytes,0);

				blockPos.erase(found);
			}
		}

		return true;
	}

	bool BlobFile::ResizeBlock(LONGLONG handle, const LONGLONG size)
	{
		if (!IsValidHandle(handle))
		{
			return false;
		}

		ScopedHeader header(mHeader,mLockedHandle);

		LONGLONG alignedSize = (size + kBlockSizeAlign - 1) & ~(((LONGLONG)kBlockSizeAlign)-1);
		if (!size)
		{
			alignedSize = kBlockSizeAlign;
		}

		DWORD numBytes;

		LONGLONG currentBlockPos = handle;

		BlockLink blockLink;
		while(alignedSize > 0)
		{
			LARGE_INTEGER filePos;
			filePos.QuadPart = currentBlockPos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

			mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

			LONGLONG availableSize = blockLink.mBlockDataSize - sizeof(BlockLink);
			// If there is a next block then adjust the size, eventually giving us the final resultant size of the block we end up on.
			if (blockLink.mNext && (alignedSize >= availableSize))
			{
				alignedSize -= availableSize;
			}
			else
			{
				break;
			}

			if (blockLink.mNext)
			{
				currentBlockPos = blockLink.mNext;
			}
			else
			{
				break;
			}
		}

		LARGE_INTEGER fileSize;
		GetFileSizeEx(mLockedHandle, &fileSize);

		LONGLONG availableSize = blockLink.mBlockDataSize - sizeof(BlockLink);

		// Check for there being no more blocks first
		if (!blockLink.mNext)
		{
			// If the current last block is at the end of the file then it can be extended or truncated
			if ((currentBlockPos + blockLink.mBlockDataSize) == fileSize.QuadPart)
			{
				blockLink.mBlockDataSize = alignedSize + sizeof(BlockLink);

				LARGE_INTEGER filePos;
				filePos.QuadPart = currentBlockPos;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

				filePos.QuadPart = currentBlockPos + blockLink.mBlockDataSize;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				SetEndOfFile(mLockedHandle);
				return true;
			}

			if (alignedSize > availableSize)
			{
				LONGLONG toAllocate = alignedSize-availableSize;
				LARGE_INTEGER filePos;
				// Spot the case where the existing used block and the next free block are right next to each other.
				if ( (currentBlockPos + blockLink.mBlockDataSize) == mHeader.mFreeBlock )
				{
					filePos.QuadPart = mHeader.mFreeBlock;
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					BlockLink tempLink;
					mCrypto.ReadFile(mLockedHandle,&tempLink,sizeof(BlockLink),&numBytes,0);
					if ((toAllocate + kBlockSizeAlign) >= tempLink.mBlockDataSize)
					{
						// Use it all
						blockLink.mBlockDataSize += tempLink.mBlockDataSize;
						mHeader.mFreeBlock = tempLink.mNext;
						if (toAllocate > tempLink.mBlockDataSize)
						{
							toAllocate -= tempLink.mBlockDataSize;
						}
						else
						{
							toAllocate = 0;
						}
					}
				}
				if (toAllocate > 0)
				{
					LONGLONG newChain;
					// Check if the next free block can accommodate the allocation request
					newChain = InternalAllocateBlock(toAllocate);
					blockLink.mNext = newChain;
				}
				// Now check for a new used block directly after the current block and merge it
				if ( (currentBlockPos + blockLink.mBlockDataSize) == blockLink.mNext)
				{
					// Merge it
					filePos.QuadPart = blockLink.mNext;
					SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
					BlockLink tempLink;
					mCrypto.ReadFile(mLockedHandle,&tempLink,sizeof(tempLink),&numBytes,0);
					blockLink.mNext = tempLink.mNext;
					blockLink.mBlockDataSize += tempLink.mBlockDataSize;
				}

				filePos.QuadPart = currentBlockPos;
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				return true;
			}

			if ((alignedSize + kBlockSizeAlign) < availableSize)
			{
				LARGE_INTEGER filePos;
				filePos.QuadPart = currentBlockPos;

				// Split this block, it will also be the last block to update for this request
				blockLink.mBlockDataSize = alignedSize + sizeof(BlockLink);

				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				availableSize -= blockLink.mBlockDataSize;

				// The split position
				filePos.QuadPart = currentBlockPos + blockLink.mBlockDataSize;
				blockLink.mNext = 0;
				blockLink.mBlockDataSize = availableSize + sizeof(BlockLink);
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				// Finally place this old allocated block onto the free list
				return InternalFreeBlock(filePos.QuadPart);
			}

			// Do nothing, the size change is small
			return true;
		}
		else
		{
			// Split the chain and maybe split the block if it has enough size
			if ((alignedSize + kBlockSizeAlign) < availableSize)
			{
				LARGE_INTEGER filePos;
				filePos.QuadPart = currentBlockPos;

				LONGLONG backupNextFree = blockLink.mNext;

				// Split this block, it will also be the last block to update for this request
				blockLink.mNext = 0;
				blockLink.mBlockDataSize = alignedSize + sizeof(BlockLink);

				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
				availableSize -= blockLink.mBlockDataSize;

				// The split position
				filePos.QuadPart = currentBlockPos + blockLink.mBlockDataSize;
				blockLink.mNext = backupNextFree;
				blockLink.mBlockDataSize = availableSize + sizeof(BlockLink);
				SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
				mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

				// Finally place these old allocated blocks onto the free list
				return InternalFreeBlock(filePos.QuadPart);
			}

			// Otherwise just unlink
			LONGLONG backupNextFree = blockLink.mNext;
			LARGE_INTEGER filePos;
			filePos.QuadPart = currentBlockPos;
			blockLink.mNext = 0;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
			mCrypto.WriteFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);
			// Finally place these old allocated blocks onto the free list
			return InternalFreeBlock(backupNextFree);
		}

		return true;
	}

	bool BlobFile::BlockReadWrite(LONGLONG handle, void *data, const DWORD size, const bool read, const LONGLONG offset, DWORD *sizeProcessed)
	{
		if (!IsValidHandle(handle))
		{
			return false;
		}

		ScopedHeader header(mHeader,mLockedHandle);

		if (sizeProcessed)
		{
			*sizeProcessed = 0;
		}

		char *theData = (char *) data;

		DWORD numBytes;
		LONGLONG realOffset = offset;

		LONGLONG currentBlockPos = handle;

		BlockLink blockLink;
		while(realOffset)
		{
			LARGE_INTEGER filePos;
			filePos.QuadPart = currentBlockPos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

			if (!mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0))
			{
				return false;
			}

			LONGLONG availableSize = blockLink.mBlockDataSize - sizeof(BlockLink);
			if (realOffset < availableSize)
			{
				break;
			}
			realOffset -= availableSize;
			currentBlockPos = blockLink.mNext;
		}

		DWORD toProcess = size;

		while (currentBlockPos && toProcess)
		{
			LARGE_INTEGER filePos;
			filePos.QuadPart = currentBlockPos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
			if (!mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0))
			{
				return false;
			}

			LONGLONG maxThisBlock = blockLink.mBlockDataSize - sizeof(BlockLink);
			assert(maxThisBlock >= realOffset);
			maxThisBlock -= realOffset;
			if (maxThisBlock > toProcess)
			{
				maxThisBlock = toProcess;
			}
			filePos.QuadPart = currentBlockPos + sizeof(BlockLink) + realOffset;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);
			if (read)
			{
				if (!mCrypto.ReadFile(mLockedHandle,theData,(DWORD)maxThisBlock,&numBytes,0))
				{
					return false;
				}
			}
			else
			{
				if (!mCrypto.WriteFile(mLockedHandle,theData,(DWORD)maxThisBlock,&numBytes,0))
				{
					return false;
				}
			}

			if (sizeProcessed)
			{
				*sizeProcessed = (*sizeProcessed) + (DWORD) maxThisBlock;
			}

			realOffset = 0;
			toProcess -= (DWORD) maxThisBlock;
			currentBlockPos = blockLink.mNext;
			theData += (DWORD) maxThisBlock;
		}

		return true;
	}

	bool BlobFile::ReadBlock(LONGLONG handle, void *dest, const DWORD size, const LONGLONG offset, DWORD *sizeRead)
	{
		return BlockReadWrite(handle,dest,size,true,offset,sizeRead);
	}

	bool BlobFile::WriteBlock(LONGLONG handle, const void *src, const DWORD size, const LONGLONG offset, DWORD *sizeWritten)
	{
		return BlockReadWrite(handle,(void*)src,size,false,offset,sizeWritten);
	}

	bool BlobFile::GetBlockSize(LONGLONG handle,LONGLONG &theSize)
	{
		theSize = 0;
		if (!IsValidHandle(handle))
		{
			return false;
		}

		ScopedHeader header(mHeader,mLockedHandle);

		DWORD numBytes;
		LONGLONG currentBlockPos = handle;

		while(currentBlockPos > 0)
		{
			BlockLink blockLink;
			LARGE_INTEGER filePos;
			filePos.QuadPart = currentBlockPos;
			SetFilePointerEx(mLockedHandle,filePos,0,FILE_BEGIN);

			mCrypto.ReadFile(mLockedHandle,&blockLink,sizeof(blockLink),&numBytes,0);

			LONGLONG availableSize = blockLink.mBlockDataSize - sizeof(BlockLink);
			theSize += availableSize;

			currentBlockPos = blockLink.mNext;
		}

		return true;
	}

	bool BlobFile::IsValidHandle(LONGLONG &handle)
	{
		if (handle == kFirstBlockHandle)
		{
			handle = sizeof(Header);
		}

		LARGE_INTEGER endPos;
		GetFileSizeEx(mLockedHandle,&endPos);

		if (endPos.QuadPart <= sizeof(Header))
		{
			return false;
		}

		if ((handle + sizeof(BlockLink)) >= endPos.QuadPart)
		{
			return false;
		}

		return true;
	}


}; //< namespace BlobFileLib
