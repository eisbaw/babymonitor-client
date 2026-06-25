// Ghidra decompilation of build_mpint_op1  (entry=00105900)

void * FUN_00105900(long param_1,uint param_2,int param_3,int param_4)

{
  long lVar1;
  uint uVar2;
  int local_84;
  void *local_60;
  undefined1 auStack_1c [4];
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);
  local_60 = calloc((long)(int)(param_3 << 1 | 1),1);
  if (local_60 == (void *)0x0) {
    local_60 = (void *)0x0;
  }
  else {
    for (local_84 = 0; local_84 < param_3; local_84 = local_84 + 1) {
      __memset_chk(auStack_1c,0,3,3);
      uVar2 = 0;
      if (param_2 != 0) {
        uVar2 = (uint)(param_4 + local_84) / param_2;
      }
      FUN_00105a70(auStack_1c,3,&DAT_00102b69,
                   *(undefined1 *)(param_1 + (ulong)((param_4 + local_84) - uVar2 * param_2)));
      __strcat_chk(local_60,auStack_1c,0xffffffffffffffff);
    }
  }
  lVar1 = tpidr_el0;
  lVar1 = *(long *)(lVar1 + 0x28) - local_18;
  if (lVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(lVar1);
  }
  return local_60;
}

