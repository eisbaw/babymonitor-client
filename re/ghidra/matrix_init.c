// Ghidra decompilation of matrix_init  (entry=001065f8)

int FUN_001065f8(undefined8 *param_1,undefined8 *param_2,int param_3)

{
  long lVar1;
  int *__ptr;
  int local_64;
  int local_60;
  void *local_50;
  undefined8 *local_40;
  int local_2c;
  undefined8 local_28;
  undefined8 local_20;
  long local_18;
  
  lVar1 = tpidr_el0;
  local_18 = *(long *)(lVar1 + 0x28);
  local_50 = calloc(0x40,(long)(param_3 * (param_3 + 1)));
  if (local_50 == (void *)0x0) {
    local_2c = 1;
  }
  else {
    __ptr = (int *)calloc(0x20,1);
    if (__ptr == (int *)0x0) {
      free(local_50);
      local_2c = 1;
    }
    else {
      *(void **)(__ptr + 2) = local_50;
      *__ptr = param_3 + 1;
      __ptr[1] = param_3;
      *(code **)(__ptr + 4) = FUN_001069b0;
      *(code **)(__ptr + 6) = FUN_001069fc;
      local_40 = param_2;
      for (local_60 = 0; local_60 < param_3; local_60 = local_60 + 1) {
        local_2c = FUN_00106a38(*local_40,local_40[1],&local_28);
        if (local_2c != *(int *)PTR_MP_OK_001160e8) {
          free(local_50);
          free(__ptr);
          FUN_00106b30(local_28,local_20);
          goto LAB_00106870;
        }
        for (local_64 = param_3 + -1; -1 < local_64; local_64 = local_64 + -1) {
          local_50 = (void *)((long)local_50 + 0x40);
          local_2c = mp_rat_expt(local_28,(long)local_64);
          if (local_2c != *(int *)PTR_MP_OK_001160e8) {
            free(local_50);
            free(__ptr);
            FUN_00106b30(local_28,local_20);
            goto LAB_00106870;
          }
        }
        local_50 = (void *)((long)local_50 + 0x40);
        local_2c = mp_rat_copy(local_20);
        if (local_2c - *(int *)PTR_MP_OK_001160e8 != 0) {
          FUN_00106b30(local_2c - *(int *)PTR_MP_OK_001160e8,local_28,local_20);
          goto LAB_00106870;
        }
        FUN_00106b30(0,local_28,local_20);
        local_40 = local_40 + 2;
      }
      *param_1 = __ptr;
      local_2c = 0;
    }
  }
LAB_00106870:
  lVar1 = tpidr_el0;
  lVar1 = *(long *)(lVar1 + 0x28) - local_18;
  if (lVar1 == 0) {
    return local_2c;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(lVar1);
}

