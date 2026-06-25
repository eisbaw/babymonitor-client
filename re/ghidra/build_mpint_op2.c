// Ghidra decompilation of build_mpint_op2  (entry=00105c64)

void * FUN_00105c64(uint *param_1,int param_2,long param_3,uint param_4)

{
  long lVar1;
  uint uVar2;
  void *pvVar3;
  uint local_8c;
  char local_88;
  int local_84;
  undefined1 auStack_1c [4];
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);
  pvVar3 = calloc((long)(int)(param_2 << 1 | 1),1);
  for (local_84 = 0; local_84 < param_2; local_84 = local_84 + 1) {
    if (param_4 <= *param_1) {
      uVar2 = 0;
      if (param_4 != 0) {
        uVar2 = *param_1 / param_4;
      }
      *param_1 = *param_1 - uVar2 * param_4;
    }
    local_88 = '\0';
    for (local_8c = 0; (int)local_8c < 8; local_8c = local_8c + 1) {
      local_88 = local_88 +
                 (char)((*(byte *)(param_3 + (int)*param_1) & 1) << (ulong)(local_8c & 0x1f));
      *param_1 = *param_1 + 1;
    }
    __memset_chk(auStack_1c,0,3,3);
    FUN_00105a70(auStack_1c,3,&DAT_00102b69,local_88);
    __strcat_chk(pvVar3,auStack_1c,0xffffffffffffffff);
  }
  lVar1 = tpidr_el0;
  lVar1 = *(long *)(lVar1 + 0x28) - local_18;
  if (lVar1 == 0) {
    return pvVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(lVar1);
}

