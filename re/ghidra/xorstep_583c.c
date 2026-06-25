// Ghidra decompilation of xorstep_583c  (entry=0010583c)

uint FUN_0010583c(long param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar1 = 0;
  if (param_2 != 0) {
    uVar1 = param_3 / param_2;
  }
  uVar2 = 0;
  if (param_2 != 0) {
    uVar2 = (param_3 + 1) / param_2;
  }
  uVar3 = 0;
  if (param_2 != 0) {
    uVar3 = (param_3 + 2) / param_2;
  }
  uVar4 = 0;
  if (param_2 != 0) {
    uVar4 = (param_3 + 3) / param_2;
  }
  return (uint)*(byte *)(param_1 + (ulong)((param_3 + 1) - uVar2 * param_2)) << 0x10 |
         (uint)*(byte *)(param_1 + (ulong)(param_3 - uVar1 * param_2)) << 0x18 |
         (uint)*(byte *)(param_1 + (ulong)((param_3 + 2) - uVar3 * param_2)) << 8 |
         (uint)*(byte *)(param_1 + (ulong)((param_3 + 3) - uVar4 * param_2));
}

