
NTSTATUS entry(_DRIVER_OBJECT *DriverObject,_UNICODE_STRING *RegistryPath)

{
  NTSTATUS NVar1;
  _DEVICE_OBJECT *local_38;
  _UNICODE_STRING local_30;
  _UNICODE_STRING local_20 [2];
  
  if (((DAT_00013108 == 0) || (DAT_00013108 == 0x2b992ddfa232)) &&
     (DAT_00013108 = (_DAT_fffff78000000320 ^ 0x13108) & 0xffffffffffff, DAT_00013108 == 0)) {
    DAT_00013108 = 0x2b992ddfa232;
  }
  _DAT_00013100 = ~DAT_00013108;
  local_38 = (_DEVICE_OBJECT *)0x0;
  DbgPrint("Entering DriverEntry");
  RtlInitUnicodeString(&local_30,L"\\Device\\MsIo");
  NVar1 = IoCreateDevice(DriverObject,0,&local_30,0x8010,0,'\0',&local_38);
  if (NVar1 < 0) {
    DbgPrint("ERROR: IoCreateDevice failed");
  }
  else {
    *(code **)&DriverObject->DispatchDeviceIOControl = ioctl;
    *(code **)&DriverObject->DispatchClose = ioctl;
    *(code **)&DriverObject->DispatchCreate = ioctl;
    *(code **)&DriverObject->DriverUnload = DriverUnload;
    RtlInitUnicodeString(local_20,L"\\DosDevices\\MsIo");
    NVar1 = IoCreateSymbolicLink(local_20,&local_30);
    if (NVar1 < 0) {
      DbgPrint("ERROR: IoCreateSymbolicLink failed");
      IoDeleteDevice(local_38);
    }
  }
  DbgPrint("Leaving DriverEntry");
  return NVar1;
}


void DriverUnload(longlong param_1)

{
  NTSTATUS NVar1;
  _UNICODE_STRING local_18;
  
  DbgPrint("Entering MsIoUnload");
  RtlInitUnicodeString(&local_18,L"\\DosDevices\\MsIo");
  NVar1 = IoDeleteSymbolicLink(&local_18);
  if (-1 < NVar1) {
    IoDeleteDevice(*(_DEVICE_OBJECT **)(param_1 + 8));
    DbgPrint("Leaving MsIoUnload");
    return;
  }
  DbgPrint("ERROR: IoDeleteSymbolicLink");
  DbgPrint("Leaving MsIoUnload");
  return;
}



NTSTATUS ioctl(_DEVICE_OBJECT *DeviceObject,_IRP *Irp)

{
  UCHAR MajorFunction;
  uint InputBufferLength;
  ULONG UVar1;
  NTSTATUS NVar2;
  _IO_STACK_LOCATION *CurrentStackLocation;
  undefined8 *SystemBuffer;
  byte bVar3;
  ushort uVar4;
  undefined4 uVar5;
  ulonglong InputBufferLength0;
  ulonglong uVar6;
  char *pcVar7;
  undefined2 local_res10;
  undefined4 local_res12;
  char local_res16;
  longlong local_48;
  ulonglong local_40;
  undefined8 local_38;
  longlong local_30;
  longlong local_28 [3];
  
  DbgPrint("---Entry MsIoDispatch---");
  CurrentStackLocation = Irp->CurrentStackLocation;
  SystemBuffer = (undefined8 *)Irp->SystemBuffer;
  (Irp->IoStatus).Status = 0;
  (Irp->IoStatus).Information = 0;
  MajorFunction = CurrentStackLocation->MajorFunction;
  InputBufferLength = *(uint *)&CurrentStackLocation->InputBufferLength;
  InputBufferLength0 = (ulonglong)InputBufferLength;
  if (MajorFunction == '\0') {
    pcVar7 = "IRP_MJ_CREATE";
  }
  else {
    if (MajorFunction != '\x02') {
      if (MajorFunction == '\x0e') {
        DbgPrint("IRP_MJ_DEVICE_CONTROL");
        UVar1 = CurrentStackLocation->IoControlCode;
        if (UVar1 == 0x80102040) {
          DbgPrint("IOCTL_MSIO_MAPPHYSTOLIN");
          if (InputBufferLength != 0) {
            CopyMemoryBlock(&local_48,SystemBuffer,InputBufferLength0);
            uVar6 = MapArbitraryPhysicalMemory(local_40,local_48,&local_30,&local_38,local_28);
            if (-1 < (int)uVar6) {
              CopyMemoryBlock(SystemBuffer,&local_48,InputBufferLength0);
              (Irp->IoStatus).Information = InputBufferLength0;
            }
            (Irp->IoStatus).Status = (int)uVar6;
            goto LAB_0001167f;
          }
        }
        else {
          if (UVar1 == 0x80102044) {
            DbgPrint("IOCTL_MSIO_UNMAPPHYSADDR");
            if (InputBufferLength != 0) {
              CopyMemoryBlock(&local_48,SystemBuffer,InputBufferLength0);
              InputBufferLength0 = UnmapPhysicalMemory(local_38,local_30,local_28[0]);
              (Irp->IoStatus).Status = (LONG)InputBufferLength0;
              goto LAB_0001167f;
            }
          }
          else {
            if (UVar1 == 0x80102050) {
              DbgPrint("IOCTL_MSIO_READPORT");
              if (InputBufferLength != 0) {
                CopyMemoryBlock((undefined8 *)&local_res10,SystemBuffer,InputBufferLength0);
                if (local_res16 == '\x01') {
                  bVar3 = in(local_res10);
                  *(uint *)SystemBuffer = (uint)bVar3;
                  (Irp->IoStatus).Information = 4;
                }
                else {
                  if (local_res16 == '\x02') {
                    uVar4 = in(local_res10);
                    *(uint *)SystemBuffer = (uint)uVar4;
                    (Irp->IoStatus).Information = 4;
                  }
                  else {
                    if (local_res16 == '\x04') {
                      uVar5 = in(local_res10);
                      *(undefined4 *)SystemBuffer = uVar5;
                      (Irp->IoStatus).Information = 4;
                    }
                    else {
                      *(undefined4 *)SystemBuffer = local_res12;
                      (Irp->IoStatus).Information = 4;
                    }
                  }
                }
                goto LAB_0001167f;
              }
            }
            else {
              if (UVar1 == 0x80102054) {
                DbgPrint("IOCTL_MSIO_WRITEPORT");
                if (InputBufferLength != 0) {
                  CopyMemoryBlock((undefined8 *)&local_res10,SystemBuffer,InputBufferLength0);
                  if (local_res16 == '\x01') {
                    out(local_res10,(undefined)local_res12);
                  }
                  else {
                    if (local_res16 == '\x02') {
                      out(local_res10,(undefined2)local_res12);
                    }
                    else {
                      if (local_res16 == '\x04') {
                        out(local_res10,local_res12);
                      }
                    }
                  }
                  goto LAB_0001167f;
                }
              }
              else {
                DbgPrint("ERROR: Unknown IRP_MJ_DEVICE_CONTROL");
              }
            }
          }
        }
        (Irp->IoStatus).Status = -0x3ffffff3;
      }
      goto LAB_0001167f;
    }
    pcVar7 = "IRP_MJ_CLOSE";
  }
  DbgPrint(pcVar7);
LAB_0001167f:
  NVar2 = (Irp->IoStatus).Status;
  IofCompleteRequest(Irp,'\0');
  DbgPrint("Leaving MsIoDispatch");
  return NVar2;
}


ulonglong MapArbitraryPhysicalMemory
                    (ulonglong param_1,longlong param_2,longlong *param_3,undefined8 *param_4,
                    undefined8 *param_5)

{
  undefined8 *puVar1;
  UCHAR UVar2;
  UCHAR UVar3;
  uint uVar4;
  ULONGLONG local_res10 [2];
  ULONG local_res20 [2];
  PVOID local_98;
  longlong local_90;
  ulonglong local_88;
  ulonglong local_80;
  _UNICODE_STRING local_78;
  _OBJECT_ATTRIBUTES local_68;
  
  local_98 = (PVOID)0x0;
  local_res10[0] = param_2;
  DbgPrint("Entering MapPhysicalMemoryToLinearSpace");
  RtlInitUnicodeString(&local_78,L"\\Device\\PhysicalMemory");
  puVar1 = param_5;
  local_68.ObjectName = &local_78;
  *param_4 = 0;
  *param_5 = 0;
  local_68.Length = 0x30;
  local_68.RootDirectory = (void *)0x0;
  local_68.Attributes = 0x40;
  local_68.SecurityDescriptor = (void *)0x0;
  local_68.SecurityQualityOfService = (void *)0x0;
  uVar4 = ZwOpenSection((HANDLE *)param_4,0xf001f,&local_68);
  if ((int)uVar4 < 0) {
    DbgPrint("ERROR: ZwOpenSection failed");
  }
  else {
    uVar4 = ObReferenceObjectByHandle(*param_4,0xf001f,0,0,puVar1,0);
    if ((int)uVar4 < 0) {
      DbgPrint("ERROR: ObReferenceObjectByHandle failed");
    }
    else {
      local_88 = param_1 & 0xffffffff;
      local_90 = local_88 + local_res10[0];
      local_res20[0] = 0;
      UVar2 = HalTranslateBusAddress(Isa,0,local_88,local_res20,&local_88);
      local_res20[0] = 0;
      UVar3 = HalTranslateBusAddress(Isa,0,local_90,local_res20,&local_90);
      if ((UVar2 == '\0') || (UVar3 == '\0')) {
        DbgPrint("ERROR: HalTranslateBusAddress failed");
      }
      else {
        local_res10[0] = local_90 - local_88;
        local_80 = local_88;
        uVar4 = ZwMapViewOfSection((HANDLE)*param_4,(HANDLE)0xffffffffffffffff,&local_98,0,
                                   local_res10[0],&local_80,local_res10,1,0,0x204);
        if (uVar4 == 0xc0000018) {
          uVar4 = ZwMapViewOfSection((HANDLE)*param_4,(HANDLE)0xffffffffffffffff,&local_98,0,
                                     local_res10[0],&local_80,local_res10,1,0,4);
        }
        if ((int)uVar4 < 0) {
          DbgPrint("ERROR: ZwMapViewOfSection failed");
        }
        else {
          local_98 = (PVOID)((longlong)local_98 + (local_88 - local_80));
          *(PVOID *)param_3 = local_98;
        }
      }
    }
  }
  if ((int)uVar4 < 0) {
    ZwClose((HANDLE)*param_4);
  }
  DbgPrint("Leaving MapPhysicalMemoryToLinearSpace");
  return (ulonglong)uVar4;
}


ulonglong UnmapPhysicalMemory(HANDLE param_1,PVOID param_2,longlong param_3)

{
  uint uVar1;
  
  DbgPrint("Entering UnmapPhysicalMemory");
  uVar1 = ZwUnmapViewOfSection((HANDLE)0xffffffffffffffff,param_2);
  if ((int)uVar1 < 0) {
    DbgPrint("ERROR: UnmapViewOfSection failed");
  }
  if (param_3 != 0) {
    ObfDereferenceObject(param_3);
  }
  ZwClose(param_1);
  DbgPrint("Leaving UnmapPhysicalMemory");
  return (ulonglong)uVar1;
}
