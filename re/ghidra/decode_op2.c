// Ghidra decompilation of decode_op2  (entry=001054f4)

int FUN_001054f4(undefined8 param_1,long *param_2,uint *param_3,undefined8 param_4,uint param_5)

{
  undefined8 *puVar1;
  int iVar2;
  long lVar3;
  uint uVar4;
  void *pvVar5;
  undefined8 uVar6;
  uint uVar7;
  int local_84;
  int local_6c;
  long local_58;
  int local_24;
  byte local_20 [4];
  int local_1c;
  long local_18;
  
  lVar3 = tpidr_el0;
  local_18 = *(long *)(lVar3 + 0x28);
  uVar4 = FUN_0010509c(param_1);
  uVar7 = 0;
  if (param_5 != 0) {
    uVar7 = uVar4 / param_5;
  }
  uVar7 = uVar4 - uVar7 * param_5 >> 1;
  uVar4 = 0;
  if (param_5 != 0) {
    uVar4 = uVar7 / param_5;
  }
  local_1c = (uVar7 - uVar4 * param_5) + 1;
  FUN_00105b68(local_20,&local_1c,1,param_4,param_5);
  *param_3 = (uint)local_20[0];
  if (((int)*param_3 < 6) && (0 < (int)*param_3)) {
    pvVar5 = calloc((long)(int)*param_3,8);
    *param_2 = (long)pvVar5;
    if (*param_2 == 0) {
      local_24 = 1;
    }
    else {
      local_58 = *param_2;
      FUN_00105b68(local_20,&local_1c,1,param_4,param_5);
      uVar7 = (uint)local_20[0];
      pvVar5 = calloc((long)(int)(uVar7 * *param_3),0x10);
      if (pvVar5 == (void *)0x0) {
        local_24 = 1;
      }
      else {
        local_1c = local_1c + 0x20;
        for (local_6c = 0; local_6c < (int)uVar7; local_6c = local_6c + 1) {
          FUN_00105b68(local_6c - uVar7);
          puVar1 = (undefined8 *)((long)pvVar5 + (long)local_6c * 0x10);
          uVar6 = FUN_00105c64(&local_1c,local_20[0],param_4,param_5);
          *puVar1 = uVar6;
          FUN_00105b68(local_20,&local_1c,1,param_4,param_5);
          uVar6 = FUN_00105c64(&local_1c,local_20[0],param_4,param_5);
          puVar1[1] = uVar6;
        }
        for (local_84 = 0; local_84 < (int)*param_3; local_84 = local_84 + 1) {
          iVar2 = 0;
          if (*param_3 != 0) {
            iVar2 = (int)uVar7 / (int)*param_3;
          }
          local_24 = FUN_00105eb0(local_58,(void *)((long)pvVar5 + (long)(local_84 * iVar2) * 0x10),
                                  iVar2,2);
          if (local_24 != 0) {
            str_coordinates_free(pvVar5,uVar7);
            if (local_24 == -2) {
              local_24 = 1;
            }
            goto LAB_00105808;
          }
          local_58 = local_58 + 8;
        }
        str_coordinates_free(local_84 - *param_3,pvVar5,uVar7);
        local_24 = 0;
      }
    }
  }
  else {
    local_24 = 0x15;
  }
LAB_00105808:
  lVar3 = tpidr_el0;
  lVar3 = *(long *)(lVar3 + 0x28) - local_18;
  if (lVar3 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(lVar3);
  }
  return local_24;
}

