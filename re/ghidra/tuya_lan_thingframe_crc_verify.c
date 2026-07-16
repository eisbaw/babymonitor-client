// Ghidra decompilation of thingframe_crc_verify  (entry=00263168)

void FUN_00263168(long param_1)

{
  uint uVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;
  byte *pbVar5;
  ulong uVar6;
  byte *local_40;
  long local_38;

  lVar2 = tpidr_el0;
  local_38 = *(long *)(lVar2 + 0x28);
  uVar1 = *(uint *)(param_1 + 0x28);
  uVar3 = *(int *)(param_1 + 0x18) + 8;
  uVar6 = (ulong)uVar3;
  FUN_00263220(&local_40,param_1,1);
  if (uVar3 == 0) {
    uVar4 = 0;
    uVar3 = 0;
    if (local_40 == (byte *)0x0) goto LAB_002631f0;
  }
  else {
    uVar3 = 0xffffffff;
    pbVar5 = local_40;
    do {
      uVar6 = uVar6 - 1;
      uVar3 = *(uint *)(&DAT_00154dc4 + ((ulong)(*pbVar5 ^ uVar3) & 0xff) * 4) ^ uVar3 >> 8;
      pbVar5 = pbVar5 + 1;
    } while (uVar6 != 0);
    uVar3 = ~uVar3;
  }
  uVar4 = uVar3;
  free(local_40);
LAB_002631f0:
  if (*(long *)(lVar2 + 0x28) == local_38) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar1 == uVar4);
}
