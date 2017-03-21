/** @file

  Copyright (c) 2013-2014, ARM Ltd. All rights reserved.<BR>
  Copyright (c) 2017, Linaro. All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/BaseMemoryLib.h>
#include <Library/BdsLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/BlockIo.h>
#include <Protocol/DevicePathFromText.h>

#include "AndroidBootApp.h"

#define IS_DEVICE_PATH_NODE(node,type,subtype) (((node)->Type == (type)) && ((node)->SubType == (subtype)))

#define ALIGN(x, a)        (((x) + ((a) - 1)) & ~((a) - 1))

STATIC FASTBOOT_PLATFORM_PROTOCOL          *mPlatform;

EFI_STATUS
EFIAPI
AndroidBootAppEntryPoint (
  IN EFI_HANDLE                            ImageHandle,
  IN EFI_SYSTEM_TABLE                      *SystemTable
  )
{
  EFI_STATUS                          Status;
  CHAR16                              *BootPathStr;
  EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL  *EfiDevicePathFromTextProtocol;
  EFI_DEVICE_PATH                     *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL            *Node, *NextNode;
  EFI_BLOCK_IO_PROTOCOL               *BlockIo;
  HARDDRIVE_DEVICE_PATH               *PartitionPath;
  UINT32                              MediaId, BlockSize;
  VOID                                *Buffer;
  EFI_HANDLE                          Handle;
  ANDROID_BOOTIMG_HEADER              *Header;
  UINT32                              Size;

  BootPathStr = (CHAR16 *)PcdGetPtr (PcdAndroidBootDevicePath);
  ASSERT (BootPathStr != NULL);
  Status = gBS->LocateProtocol (&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID **)&EfiDevicePathFromTextProtocol);
  ASSERT_EFI_ERROR(Status);
  DevicePath = (EFI_DEVICE_PATH *)EfiDevicePathFromTextProtocol->ConvertTextToDevicePath (BootPathStr);
  ASSERT (DevicePath != NULL);

  /* Find DevicePath node of Partition */
  NextNode = DevicePath;
  while (1) {
    Node = NextNode;
    if (IS_DEVICE_PATH_NODE (Node, MEDIA_DEVICE_PATH, MEDIA_HARDDRIVE_DP)) {
      PartitionPath = (HARDDRIVE_DEVICE_PATH *)Node;
      break;
    }
    NextNode = NextDevicePathNode (Node);
  }

  Status = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &DevicePath, &Handle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlockIo,
                  gImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to get BlockIo: %r\n", Status));
    return Status;
  }

  MediaId = BlockIo->Media->MediaId;
  BlockSize = BlockIo->Media->BlockSize;
  Buffer = AllocatePages (1);
  if (Buffer == NULL) {
    return EFI_BUFFER_TOO_SMALL;
  }
  /* Load header of boot.img */
  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      MediaId,
                      PartitionPath->PartitionStart,
                      BlockSize,
                      Buffer
                      );
  Header = (ANDROID_BOOTIMG_HEADER *)Buffer;
  /* Get real size of abootimg */
  Size = ALIGN (Header->KernelSize, Header->PageSize) +
         ALIGN (Header->RamdiskSize, Header->PageSize) +
         ALIGN (Header->SecondStageBootloaderSize, Header->PageSize) +
         Header->PageSize;
  Size = ALIGN (Size, BlockSize);
  FreePages (Buffer, 1);

  /* Both PartitionStart and PartitionSize are counted as block size. */
  Buffer = AllocatePages (EFI_SIZE_TO_PAGES (Size));
  if (Buffer == NULL) {
    return EFI_BUFFER_TOO_SMALL;
  }

  /* Load header of boot.img */
  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      MediaId,
                      PartitionPath->PartitionStart,
                      Size,
                      Buffer
                      );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Failed to read blocks: %r\n", Status));
    goto EXIT;
  }

  Status = gBS->LocateProtocol (&gAndroidFastbootPlatformProtocolGuid, NULL, (VOID **) &mPlatform);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Fastboot: Couldn't open Fastboot Platform Protocol: %r\n", Status));
    goto EXIT;
  }

  Status = BootAndroidBootImg (mPlatform, PartitionPath->PartitionSize, Buffer);

EXIT:
  FreePages (Buffer, EFI_SIZE_TO_PAGES (PartitionPath->PartitionSize));
  return Status;
}
