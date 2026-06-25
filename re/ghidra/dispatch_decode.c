// Ghidra decompilation of dispatch_decode  (entry=00104b28)

undefined4
FUN_00104b28(undefined8 param_1,undefined8 param_2,undefined8 param_3,long param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 local_14;
  
  uVar2 = FUN_0010509c(param_1);
  uVar3 = 0;
  if (param_5 != 0) {
    uVar3 = uVar2 / param_5;
  }
  uVar3 = (uVar2 - uVar3 * param_5) / 2;
  uVar2 = 0;
  if (param_5 != 0) {
    uVar2 = uVar3 / param_5;
  }
  uVar3 = (uint)*(byte *)(param_4 + (ulong)(uVar3 - uVar2 * param_5));
  if (uVar3 < 3) {
    iVar1 = uVar3 - 1;
    if (iVar1 == 0) {
      local_14 = FUN_00105138(param_1,param_2,param_3,param_4,param_5);
    }
    else {
      local_14 = FUN_001054f4(iVar1,param_1,param_2,param_3,param_4,param_5);
    }
  }
  else {
    local_14 = 0x15;
  }
  return local_14;
}

