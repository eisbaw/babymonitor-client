// Ghidra decompilation of parse  (entry=00104eec)

/* WARNING: Removing unreachable block (ram,0x00104f64) */

undefined4 parse(char *param_1,undefined8 param_2,int param_3)

{
  undefined4 uVar1;
  void *pvVar2;
  char *pcVar3;
  void *pvVar4;
  int iVar5;
  int local_84;
  char *local_80;
  
  pvVar2 = calloc((long)param_3,0x10);
  local_80 = param_1;
  for (local_84 = 0; iVar5 = local_84 + param_3 * -2, iVar5 < 0 != SBORROW4(local_84,param_3 * 2);
      local_84 = local_84 + 1) {
    pcVar3 = strchr(local_80,0x2c);
    iVar5 = (int)pcVar3 - (int)local_80;
    pvVar4 = calloc((long)(iVar5 + 1),1);
    __memcpy_chk(pvVar4,local_80,(long)iVar5,0xffffffffffffffff);
    if (local_84 % 2 == 0) {
      *(void **)((long)pvVar2 + (long)(local_84 / 2) * 0x10) = pvVar4;
    }
    else {
      *(void **)((long)pvVar2 + (long)(local_84 / 2) * 0x10 + 8) = pvVar4;
    }
    local_80 = pcVar3 + 1;
  }
  uVar1 = FUN_00105eb0(iVar5,param_2,pvVar2,param_3,1);
  str_coordinates_free(pvVar2,param_3);
  return uVar1;
}

