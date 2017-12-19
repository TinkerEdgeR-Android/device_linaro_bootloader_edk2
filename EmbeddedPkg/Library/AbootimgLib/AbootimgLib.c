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

#include <Library/AbootimgLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/Abootimg.h>
#include <Protocol/LoadedImage.h>

#include <libfdt.h>

// Check Val (unsigned) is a power of 2 (has only one bit set)
#define IS_POWER_OF_2(Val)                (Val != 0 && ((Val & (Val - 1)) == 0))

// Offset in Kernel Image
#define KERNEL_SIZE_OFFSET                0x10
#define KERNEL_MAGIC_OFFSET               0x38
#define KERNEL_MAGIC                      "ARMd"

typedef struct {
  MEMMAP_DEVICE_PATH                      Node1;
  EFI_DEVICE_PATH_PROTOCOL                End;
} MEMORY_DEVICE_PATH;

STATIC ABOOTIMG_PROTOCOL                 *mAbootimg;

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

STATIC
EFI_STATUS
CheckKernelImageHeader (
  IN  VOID                  *Kernel
  )
{
  if (Kernel == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  /* Check magic number of uncompressed Kernel Image */
  if (AsciiStrnCmp ((VOID *)((UINTN)Kernel + KERNEL_MAGIC_OFFSET), KERNEL_MAGIC, 4) == 0) {
    return EFI_SUCCESS;
  }
  return EFI_INVALID_PARAMETER;
}

EFI_STATUS
AbootimgGetImgSize (
  IN  VOID    *BootImg,
  OUT UINTN   *ImgSize
  )
{
  ANDROID_BOOTIMG_HEADER   *Header;

  Header = (ANDROID_BOOTIMG_HEADER *) BootImg;

  if (AsciiStrnCmp (Header->BootMagic, BOOT_MAGIC, BOOT_MAGIC_LENGTH) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  ASSERT (IS_POWER_OF_2 (Header->PageSize));

  /* Get real size of abootimg */
  *ImgSize = ALIGN_VALUE (Header->KernelSize, Header->PageSize) +
             ALIGN_VALUE (Header->RamdiskSize, Header->PageSize) +
             ALIGN_VALUE (Header->SecondStageBootloaderSize, Header->PageSize) +
             Header->PageSize;
  return EFI_SUCCESS;
}

EFI_STATUS
AbootimgGetKernelInfo (
  IN  VOID    *BootImg,
  OUT VOID   **Kernel,
  OUT UINTN   *KernelSize
  )
{
  ANDROID_BOOTIMG_HEADER   *Header;

  Header = (ANDROID_BOOTIMG_HEADER *) BootImg;

  if (AsciiStrnCmp (Header->BootMagic, BOOT_MAGIC, BOOT_MAGIC_LENGTH) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Header->KernelSize == 0) {
    return EFI_NOT_FOUND;
  }

  ASSERT (IS_POWER_OF_2 (Header->PageSize));

  *KernelSize = Header->KernelSize;
  *Kernel = BootImg + Header->PageSize;
  return EFI_SUCCESS;
}

EFI_STATUS
AbootimgGetRamdiskInfo (
  IN  VOID    *BootImg,
  OUT VOID   **Ramdisk,
  OUT UINTN   *RamdiskSize
  )
{
  ANDROID_BOOTIMG_HEADER   *Header;
  UINT8                    *BootImgBytePtr;

  // Cast to UINT8 so we can do pointer arithmetic
  BootImgBytePtr = (UINT8 *) BootImg;

  Header = (ANDROID_BOOTIMG_HEADER *) BootImg;

  if (AsciiStrnCmp (Header->BootMagic, BOOT_MAGIC, BOOT_MAGIC_LENGTH) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  ASSERT (IS_POWER_OF_2 (Header->PageSize));

  *RamdiskSize = Header->RamdiskSize;

  if (Header->RamdiskSize != 0) {
    *Ramdisk = (VOID *) (BootImgBytePtr
                 + Header->PageSize
                 + ALIGN_VALUE (Header->KernelSize, Header->PageSize));
  }
  return EFI_SUCCESS;
}

EFI_STATUS
AbootimgGetKernelArgs (
  IN  VOID    *BootImg,
  OUT CHAR8   *KernelArgs
  )
{
  ANDROID_BOOTIMG_HEADER   *Header;

  Header = (ANDROID_BOOTIMG_HEADER *) BootImg;
  AsciiStrnCpyS (KernelArgs, BOOTIMG_KERNEL_ARGS_SIZE, Header->KernelArgs,
    BOOTIMG_KERNEL_ARGS_SIZE);

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
GetAttachedFdt (
  IN VOID                            *Kernel,
  OUT VOID                           **Fdt
  )
{
  UINTN                      RawKernelSize;
  INTN                       err;

  // Get real kernel size.
  RawKernelSize = *(UINT32 *)((EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + KERNEL_IMAGE_STEXT_OFFSET) +
                  *(UINT32 *)((EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + KERNEL_IMAGE_RAW_SIZE_OFFSET);

  /* FDT is at the end of kernel image */
  *Fdt = (VOID *)((EFI_PHYSICAL_ADDRESS)(UINTN)Kernel + RawKernelSize);

  //
  // Sanity checks on the FDT blob.
  //
  err = fdt_check_header ((VOID*)(UINTN)*Fdt);
  if (err != 0) {
    Print (L"ERROR: Device Tree header not valid (err:%d)\n", err);
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
InstallFdt (
  IN  VOID                  *BootImg,
  IN  EFI_PHYSICAL_ADDRESS   FdtBase,
  OUT VOID                  *KernelArgs
  )
{
  VOID                      *Ramdisk;
  UINTN                      RamdiskSize;
  CHAR8                      ImgKernelArgs[BOOTIMG_KERNEL_ARGS_SIZE];
  INTN                       err;
  EFI_STATUS                 Status;
  EFI_PHYSICAL_ADDRESS       NewFdtBase;

  Status = gBS->LocateProtocol (&gAbootimgProtocolGuid, NULL, (VOID **) &mAbootimg);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = AbootimgGetRamdiskInfo (
            BootImg,
            &Ramdisk,
            &RamdiskSize
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = AbootimgGetKernelArgs (
            BootImg,
            ImgKernelArgs
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (ImgKernelArgs != NULL) {
    // Get kernel arguments from Android boot image
    AsciiStrToUnicodeStrS (ImgKernelArgs, KernelArgs, BOOTIMG_KERNEL_ARGS_SIZE);
    // Set the ramdisk in command line arguments
    UnicodeSPrint (
      (CHAR16 *)KernelArgs + StrLen (KernelArgs), BOOTIMG_KERNEL_ARGS_SIZE,
      L" initrd=0x%x,0x%x",
      (UINTN)Ramdisk, (UINTN)RamdiskSize
      );

    // Append platform kernel arguments
    Status = mAbootimg->AppendArgs (KernelArgs, BOOTIMG_KERNEL_ARGS_SIZE);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  Status = mAbootimg->UpdateDtb (FdtBase, &NewFdtBase);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Sanity checks on the new FDT blob.
  //
  err = fdt_check_header ((VOID*)(UINTN)NewFdtBase);
  if (err != 0) {
    Print (L"ERROR: Device Tree header not valid (err:%d)\n", err);
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->InstallConfigurationTable (
                  &gFdtTableGuid,
                  (VOID *)(UINTN)NewFdtBase
                  );
  return Status;
}

EFI_STATUS
AbootimgBoot (
  IN VOID                            *Buffer,
  IN UINTN                            BufferSize
  )
{
  EFI_STATUS                          Status;
  VOID                               *Kernel;
  UINTN                               KernelSize;
  MEMORY_DEVICE_PATH                  KernelDevicePath;
  EFI_HANDLE                          ImageHandle;
  VOID                               *NewKernelArg;
  EFI_LOADED_IMAGE_PROTOCOL          *ImageInfo;
  VOID                               *Fdt;

  Status = AbootimgGetKernelInfo (
            Buffer,
            &Kernel,
            &KernelSize
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = CheckKernelImageHeader (Kernel);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  NewKernelArg = AllocateZeroPool (BOOTIMG_KERNEL_ARGS_SIZE << 1);
  if (NewKernelArg == NULL) {
    DEBUG ((DEBUG_ERROR, "Fail to allocate memory\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = GetAttachedFdt (Kernel, &Fdt);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = InstallFdt (Buffer, (UINTN)Fdt, NewKernelArg);
  if (EFI_ERROR (Status)) {
    FreePool (NewKernelArg);
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (&KernelDevicePath, &MemoryDevicePathTemplate, sizeof (MemoryDevicePathTemplate));

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

EFI_STATUS
AbootimgBootKernel (
  IN VOID                            *Buffer,
  IN UINTN                            BufferSize,
  IN VOID                            *ImgBuffer,
  IN UINTN                            ImgBufferSize
  )
{
  EFI_STATUS                          Status;
  VOID                               *ImgKernel;
  UINTN                               ImgKernelSize;
  VOID                               *DwnldKernel;
  UINTN                               DwnldKernelSize;
  EFI_HANDLE                          ImageHandle;
  VOID                               *NewKernelArg;
  EFI_LOADED_IMAGE_PROTOCOL          *ImageInfo;
  MEMORY_DEVICE_PATH                  KernelDevicePath;
  VOID                               *Fdt;

  Status = AbootimgGetKernelInfo (
            Buffer,
            &DwnldKernel,
            &DwnldKernelSize
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = CheckKernelImageHeader (DwnldKernel);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = AbootimgGetKernelInfo (
            ImgBuffer,
            &ImgKernel,
            &ImgKernelSize
            );
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = CheckKernelImageHeader (ImgKernel);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  /*
   * FDT location:
   *   1. at the end of flattern image.
   *   2. in the boot image of storage device.
   */
  Status = GetAttachedFdt (DwnldKernel, &Fdt);
  if (EFI_ERROR (Status)) {
    Status = GetAttachedFdt (ImgKernel, &Fdt);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }
  NewKernelArg = AllocateZeroPool (BOOTIMG_KERNEL_ARGS_SIZE << 1);
  if (NewKernelArg == NULL) {
    DEBUG ((DEBUG_ERROR, "Fail to allocate memory\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  Status = InstallFdt (ImgBuffer, (UINTN)Fdt, NewKernelArg);
  if (EFI_ERROR (Status)) {
    FreePool (NewKernelArg);
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (&KernelDevicePath, &MemoryDevicePathTemplate, sizeof (MemoryDevicePathTemplate));

  // Have to cast to UINTN before casting to EFI_PHYSICAL_ADDRESS in order to
  // appease GCC.
  KernelDevicePath.Node1.StartingAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) DwnldKernel;
  KernelDevicePath.Node1.EndingAddress   = (EFI_PHYSICAL_ADDRESS)(UINTN) DwnldKernel + DwnldKernelSize;

  Status = gBS->LoadImage (TRUE, gImageHandle, (EFI_DEVICE_PATH *)&KernelDevicePath, (VOID*)(UINTN)DwnldKernel, DwnldKernelSize, &ImageHandle);

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
