/** @file

  Copyright (c) 2013-2015, ARM Ltd. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "AndroidFastbootApp.h"

#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>

#include <Library/BdsLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <libfdt.h>

#define ALIGN(x, a)     (((x) + ((a) - 1)) & ~((a) - 1))

// Additional size that could be used for FDT entries added by the UEFI OS Loader
#define FDT_ADDITIONAL_ENTRIES_SIZE       0x400

// Device Path representing an image in memory
#pragma pack(1)
typedef struct {
  MEMMAP_DEVICE_PATH                      Node1;
  EFI_DEVICE_PATH_PROTOCOL                End;
} MEMORY_DEVICE_PATH;
#pragma pack()

/* It's the value of arm64 efi stub kernel */
#define KERNEL_IMAGE_STEXT_OFFSET         0x12C
#define KERNEL_IMAGE_RAW_SIZE_OFFSET      0x130

#define FDT_SIZE_OFFSET                   0x4

STATIC CONST MEMORY_DEVICE_PATH MemoryDevicePathTemplate =
{
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_MEMMAP_DP,
      {
        (UINT8)(sizeof (MEMMAP_DEVICE_PATH)),
        (UINT8)((sizeof (MEMMAP_DEVICE_PATH)) >> 8),
      },
    }, // Header
    0, // StartingAddress (set at runtime)
    0  // EndingAddress   (set at runtime)
  }, // Node1
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
  } // End
};

EFI_STATUS
PrepareFdt (
  IN EFI_PHYSICAL_ADDRESS             FdtBlobBase,
  IN UINTN                           *FdtBlobSize,
  IN OUT CHAR16                      *KernelArgs
  )
{
  VOID                               *fdt;
  INTN                                err;
  INTN                                node;
  INT32                               lenp;
  CONST VOID                         *BootArg;
  UINTN                               OriginalFdtSize;
  EFI_STATUS                          Status;
  EFI_PHYSICAL_ADDRESS                NewFdtBlobBase;
  UINTN                               NewFdtBlobSize;
  CHAR16                              Arg[BOOTIMG_KERNEL_ARGS_SIZE];
  UINTN                               Size;

  //
  // Sanity checks on the original FDT blob.
  //
  err = fdt_check_header ((VOID*)(UINTN)FdtBlobBase);
  if (err != 0) {
    Print (L"ERROR: Device Tree header not valid (err:%d)\n", err);
    return EFI_INVALID_PARAMETER;
  }

  // The original FDT blob might have been loaded partially.
  // Check that it is not the case.
  OriginalFdtSize = (UINTN)fdt_totalsize ((VOID*)(UINTN)FdtBlobBase);
  if (OriginalFdtSize > *FdtBlobSize) {
    Print (L"ERROR: Incomplete FDT. Only %d/%d bytes have been loaded.\n",
           FdtBlobSize, OriginalFdtSize);
    return EFI_INVALID_PARAMETER;
  }

  //
  // Relocate the FDT to its final location since some platform may update FDT.
  //
  Size = OriginalFdtSize + FDT_ADDITIONAL_ENTRIES_SIZE;
  NewFdtBlobSize = ALIGN (Size, EFI_PAGE_SIZE);

  // Try anywhere there is available space.
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData,
                  EFI_SIZE_TO_PAGES (NewFdtBlobSize), &NewFdtBlobBase);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return EFI_OUT_OF_RESOURCES;
  } else {
    DEBUG ((EFI_D_WARN, "WARNING: Loaded FDT at random address 0x%lX.\nWARNING: There is a risk of accidental overwriting by other code/data.\n", NewFdtBlobBase));
  }

  // Load the Original FDT tree into the new region
  err = fdt_open_into ((VOID*)(UINTN) FdtBlobBase,
            (VOID*)(UINTN)(NewFdtBlobBase), NewFdtBlobSize);
  if (err) {
    DEBUG ((EFI_D_ERROR, "fdt_open_into(): %a\n", fdt_strerror (err)));
    gBS->FreePages (NewFdtBlobBase, EFI_SIZE_TO_PAGES (NewFdtBlobSize));
    return EFI_INVALID_PARAMETER;
  }

  // If we succeeded to generate the new Device Tree then free the old Device Tree
  gBS->FreePages (FdtBlobBase, EFI_SIZE_TO_PAGES (OriginalFdtSize));

  fdt = (VOID*)(UINTN)NewFdtBlobBase;

  node = fdt_subnode_offset (fdt, 0, "chosen");
  if (node < 0) {
    // The 'chosen' node does not exist, create it
    node = fdt_add_subnode (fdt, 0, "chosen");
    if (node < 0) {
      DEBUG ((EFI_D_ERROR, "Error on finding 'chosen' node\n"));
      Status = EFI_INVALID_PARAMETER;
      goto FAIL_COMPLETE_FDT;
    }
  }

  // Merge bootargs into command line arguments
  BootArg = fdt_getprop (fdt, node, "bootargs", &lenp);
  if (BootArg != NULL) {
    AsciiStrToUnicodeStrS (BootArg, Arg, BOOTIMG_KERNEL_ARGS_SIZE);
    // StrCatS() is using the size of CHAR16
    StrCatS (KernelArgs, BOOTIMG_KERNEL_ARGS_SIZE >> 1, L" ");
    StrCatS (KernelArgs, BOOTIMG_KERNEL_ARGS_SIZE >> 1, Arg);
  }

  // Update the real size of the Device Tree
  fdt_pack ((VOID*)(UINTN)(NewFdtBlobBase));

  *FdtBlobSize = (UINTN)fdt_totalsize ((VOID*)(UINTN)(NewFdtBlobBase));

  Status = gBS->InstallConfigurationTable (
                  &gFdtTableGuid,
                  (VOID *)(UINTN)NewFdtBlobBase
                  );
  return Status;

FAIL_COMPLETE_FDT:
  gBS->FreePages (NewFdtBlobBase, EFI_SIZE_TO_PAGES (NewFdtBlobSize));

  return EFI_SUCCESS;
}

EFI_STATUS
BootAndroidBootImg (
  IN FASTBOOT_PLATFORM_PROTOCOL      *Platform,
  IN UINTN                            BufferSize,
  IN VOID                            *Buffer
  )
{
  EFI_STATUS                          Status;
  CHAR8                               KernelArgs[BOOTIMG_KERNEL_ARGS_SIZE];
  VOID                               *Kernel;
  UINTN                               KernelSize;
  VOID                               *Ramdisk;
  UINTN                               RamdiskSize;
  MEMORY_DEVICE_PATH                  KernelDevicePath;
  EFI_HANDLE                          ImageHandle;
  EFI_PHYSICAL_ADDRESS                FdtBase;
  UINTN                               FdtSize, Index;
  UINT8                              *FdtPtr;
  VOID                               *NewKernelArg;
  EFI_LOADED_IMAGE_PROTOCOL          *ImageInfo;
  CHAR16                             *PlatformKernelArgs;

  Status = ParseAndroidBootImg (
            Buffer,
            &Kernel,
            &KernelSize,
            &Ramdisk,
            &RamdiskSize,
            KernelArgs
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  /* Install Fdt that is attached at the end of kernel */
  KernelSize = *(UINT32 *)((EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + KERNEL_IMAGE_STEXT_OFFSET) +
               *(UINT32 *)((EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + KERNEL_IMAGE_RAW_SIZE_OFFSET);

  /* FDT is at the end of kernel image */
  FdtBase = (EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + KernelSize;
  FdtPtr = (UINT8 *)(FdtBase + FDT_SIZE_OFFSET);
  for (Index = 0, FdtSize = 0; Index < sizeof (UINT32); Index++) {
    FdtSize |= *FdtPtr << ((sizeof (UINT32) - 1 - Index) * 8);
    FdtPtr++;
  }

  NewKernelArg = AllocateZeroPool (BOOTIMG_KERNEL_ARGS_SIZE);
  if (NewKernelArg == NULL) {
    DEBUG ((DEBUG_ERROR, "Fail to allocate memory\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  // Set the ramdisk in command line arguments
  UnicodeSPrint (
    (CHAR16 *)NewKernelArg, BOOTIMG_KERNEL_ARGS_SIZE,
    L"initrd=0x%x,0x%x ",
    (UINTN)Ramdisk, (UINTN)RamdiskSize
    );
  // Merge kernel arguments from Android boot image into command line arguments
  AsciiStrToUnicodeStrS (KernelArgs, NewKernelArg + StrLen (NewKernelArg) * sizeof (CHAR16), BOOTIMG_KERNEL_ARGS_SIZE >> 1);
  // StrCatS() is using the size of CHAR16
  StrCatS ((CHAR16 *)NewKernelArg, BOOTIMG_KERNEL_ARGS_SIZE >> 1, L" ");
  // Merge platform arguemnts into command line arguments
  PlatformKernelArgs = Platform->GetKernelArgs ();
  if (PlatformKernelArgs) {
    StrCatS ((CHAR16 *)NewKernelArg, BOOTIMG_KERNEL_ARGS_SIZE >> 1, PlatformKernelArgs);
  }

  Status = PrepareFdt (FdtBase, &FdtSize, NewKernelArg);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Couldn't Boot Linux: %d\n", Status));
    return EFI_DEVICE_ERROR;
    FreePool (NewKernelArg);
    return EFI_INVALID_PARAMETER;
  }

  KernelDevicePath = MemoryDevicePathTemplate;

  // Have to cast to UINTN before casting to EFI_PHYSICAL_ADDRESS in order to
  // appease GCC.
  KernelDevicePath.Node1.StartingAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) Kernel;
  KernelDevicePath.Node1.EndingAddress   = (EFI_PHYSICAL_ADDRESS)(UINTN) Kernel + KernelSize;

  Status = gBS->LoadImage (TRUE, gImageHandle, (EFI_DEVICE_PATH *)&KernelDevicePath, (VOID*)(UINTN)Kernel, KernelSize, &ImageHandle);

  // Set kernel arguments
  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);
  ImageInfo->LoadOptions = NewKernelArg;
  ImageInfo->LoadOptionsSize = StrLen (NewKernelArg) * sizeof (CHAR16);

  // Before calling the image, enable the Watchdog Timer for  the 5 Minute period
  gBS->SetWatchdogTimer (5 * 60, 0x0000, 0x00, NULL);
  // Start the image
  Status = gBS->StartImage (ImageHandle, NULL, NULL);
  // Clear the Watchdog Timer after the image returns
  gBS->SetWatchdogTimer (0x0000, 0x0000, 0x0000, NULL);
  return EFI_SUCCESS;
}
