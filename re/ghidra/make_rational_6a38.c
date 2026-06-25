// Ghidra decompilation of make_rational_6a38  (entry=00106a38)

int FUN_00106a38(undefined8 param_1,undefined8 param_2,long *param_3)

{
  undefined *puVar1;
  long lVar2;
  int local_14;
  
  puVar1 = PTR_MP_OK_001160e8;
  lVar2 = mp_rat_alloc();
  if (lVar2 == 0) {
    local_14 = 1;
  }
  else {
    local_14 = mp_rat_read_string(lVar2,0x10,param_1);
    if (local_14 == *(int *)puVar1) {
      *param_3 = lVar2;
      lVar2 = mp_rat_alloc();
      if (lVar2 == 0) {
        local_14 = 1;
      }
      else {
        local_14 = mp_rat_read_string(lVar2,0x10,param_2);
        if (local_14 == *(int *)puVar1) {
          param_3[1] = lVar2;
          local_14 = *(int *)puVar1;
        }
      }
    }
  }
  return local_14;
}

