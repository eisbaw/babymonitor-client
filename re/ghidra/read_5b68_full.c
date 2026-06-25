// Ghidra decompilation of read_5b68_full  (entry=00105b68)

void FUN_00105b68(long param_1,uint *param_2,int param_3,long param_4,uint param_5)

{
  uint uVar1;
  undefined4 local_30;
  undefined1 local_29;
  undefined4 local_28;
  
  for (local_28 = 0; local_28 < param_3; local_28 = local_28 + 1) {
    if (param_5 <= *param_2) {
      uVar1 = 0;
      if (param_5 != 0) {
        uVar1 = *param_2 / param_5;
      }
      *param_2 = *param_2 - uVar1 * param_5;
    }
    local_29 = '\0';
    for (local_30 = 0; (int)local_30 < 8; local_30 = local_30 + 1) {
      local_29 = local_29 +
                 (char)((uint)*(byte *)(param_4 + (int)*param_2) % 2 << (ulong)(local_30 & 0x1f));
      *param_2 = *param_2 + 1;
    }
    *(char *)(param_1 + local_28) = local_29;
  }
  return;
}

