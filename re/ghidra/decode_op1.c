// Ghidra decompilation of decode_op1  (entry=00105138)

int FUN_00105138(undefined8 param_1,long *param_2,uint *param_3,long param_4,uint param_5)

{
  long *plVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  void *pvVar8;
  long lVar9;
  int local_84;
  int local_6c;
  uint local_68;
  long local_50;
  int local_14;
  
  uVar4 = FUN_0010509c(param_1);
  uVar3 = 0;
  if (param_5 != 0) {
    uVar3 = uVar4 / param_5;
  }
  uVar3 = (uVar4 - uVar3 * param_5) / 2;
  uVar4 = 0;
  if (param_5 != 0) {
    uVar4 = uVar3 / param_5;
  }
  iVar7 = uVar3 - uVar4 * param_5;
  uVar4 = iVar7 + 1;
  uVar6 = 0;
  if (param_5 != 0) {
    uVar6 = uVar4 / param_5;
  }
  *param_3 = (uint)*(byte *)(param_4 + (ulong)(uVar4 - uVar6 * param_5));
  if (((int)*param_3 < 6) && (0 < (int)*param_3)) {
    pvVar8 = calloc((long)(int)*param_3,8);
    *param_2 = (long)pvVar8;
    if (*param_2 == 0) {
      local_14 = 1;
    }
    else {
      local_50 = *param_2;
      uVar4 = iVar7 + 2;
      uVar6 = 0;
      if (param_5 != 0) {
        uVar6 = uVar4 / param_5;
      }
      uVar4 = (uint)*(byte *)(param_4 + (ulong)(uVar4 - uVar6 * param_5));
      pvVar8 = calloc((long)(int)(uVar4 * *param_3),0x10);
      if (pvVar8 == (void *)0x0) {
        local_14 = 1;
      }
      else {
        uVar5 = FUN_0010583c(param_4,param_5);
        uVar6 = 0;
        if (param_5 != 0) {
          uVar6 = (uVar5 ^ uVar3) / param_5;
        }
        local_68 = (uVar5 ^ uVar3) - uVar6 * param_5;
        for (local_6c = 0; local_6c < (int)uVar4; local_6c = local_6c + 1) {
          plVar1 = (long *)((long)pvVar8 + (long)local_6c * 0x10);
          bVar2 = *(byte *)(param_4 + (ulong)local_68);
          uVar3 = 0;
          if (param_5 != 0) {
            uVar3 = (local_68 + 1) / param_5;
          }
          iVar7 = (local_68 + 1) - uVar3 * param_5;
          lVar9 = FUN_00105900(param_4,param_5,(uint)bVar2,iVar7);
          *plVar1 = lVar9;
          if (*plVar1 == 0) {
            return 1;
          }
          uVar3 = iVar7 + (uint)bVar2;
          uVar6 = 0;
          if (param_5 != 0) {
            uVar6 = uVar3 / param_5;
          }
          uVar3 = uVar3 - uVar6 * param_5;
          uVar6 = (uint)*(byte *)(param_4 + (ulong)uVar3);
          uVar3 = uVar3 + 1;
          uVar5 = 0;
          if (param_5 != 0) {
            uVar5 = uVar3 / param_5;
          }
          iVar7 = uVar3 - uVar5 * param_5;
          lVar9 = FUN_00105900(param_4,param_5,uVar6,iVar7);
          plVar1[1] = lVar9;
          if (plVar1[1] == 0) {
            return 1;
          }
          uVar6 = iVar7 + uVar6;
          uVar3 = 0;
          if (param_5 != 0) {
            uVar3 = uVar6 / param_5;
          }
          uVar6 = FUN_0010583c(param_4,param_5,uVar6 - uVar3 * param_5);
          uVar3 = 0;
          if (param_5 != 0) {
            uVar3 = (uVar6 ^ local_68) / param_5;
          }
          local_68 = (uVar6 ^ local_68) - uVar3 * param_5;
        }
        for (local_84 = 0; local_84 < (int)*param_3; local_84 = local_84 + 1) {
          iVar7 = 0;
          if (*param_3 != 0) {
            iVar7 = (int)uVar4 / (int)*param_3;
          }
          iVar7 = FUN_00105eb0(local_50,(void *)((long)pvVar8 + (long)(local_84 * iVar7) * 0x10),
                               iVar7,1);
          if (iVar7 != 0) {
            str_coordinates_free(pvVar8,uVar4);
            if (iVar7 != -2) {
              return iVar7;
            }
            return 1;
          }
          local_50 = local_50 + 8;
        }
        str_coordinates_free(local_84 - *param_3,pvVar8,uVar4);
        local_14 = 0;
      }
    }
  }
  else {
    local_14 = 0x15;
  }
  return local_14;
}

