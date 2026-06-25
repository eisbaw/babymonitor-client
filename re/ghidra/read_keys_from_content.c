// Ghidra decompilation of read_keys_from_content  (entry=00104974)

int read_keys_from_content(undefined8 param_1,undefined8 *param_2,undefined4 *param_3,long param_4)

{
  undefined4 local_14;
  
  *param_2 = 0;
  *param_3 = 0;
  local_14 = FUN_00104a34(param_4,param_4 + 0xe);
  if (local_14 == 0) {
    local_14 = FUN_00104b28(param_1,param_2,param_3,param_4 + 0x36,
                            *(int *)(param_4 + 2) - *(int *)(param_4 + 10));
  }
  return local_14;
}

