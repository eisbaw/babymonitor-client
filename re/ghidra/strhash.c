// Ghidra decompilation of strhash  (entry=0010509c)

int FUN_0010509c(long param_1)

{
  int iVar1;
  undefined4 local_34;
  undefined4 local_2c;
  
  local_2c = 0;
  iVar1 = __strlen_chk(param_1,0xffffffffffffffff);
  if (0 < iVar1) {
    for (local_34 = 0; local_34 < iVar1; local_34 = local_34 + 1) {
      local_2c = local_2c * 0x1f + (uint)*(byte *)(param_1 + local_34);
    }
  }
  iVar1 = abs(local_2c);
  return iVar1;
}

