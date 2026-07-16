// Ghidra decompilation of thingframe_outbound  (entry=002636cc)

void FUN_002636cc(undefined8 *param_1,undefined4 param_2,undefined4 param_3,void *param_4,
                 size_t param_5)

{
  size_t sVar1;
  long lVar2;
  undefined8 uVar3;
  undefined1 *__dest;
  uint uVar4;
  ulong uVar5;
  uint uVar6;
  byte *pbVar7;
  byte *local_50;
  long local_48;

  uVar3 = DAT_00143a88;
  lVar2 = tpidr_el0;
  local_48 = *(long *)(lVar2 + 0x28);
  sVar1 = param_5;
  if (param_5 == 0) {
    sVar1 = 0xffffffffffffffff;
  }
  *param_1 = &PTR_FUN_002c5b20;
  *(undefined1 *)((long)param_1 + 0x2f) = 1;
  param_1[1] = uVar3;
  param_1[3] = 0;
  param_1[4] = 0;
  *(undefined8 *)((long)param_1 + 0x27) = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 2) = param_3;
  *(undefined4 *)((long)param_1 + 0x14) = param_2;
  *(int *)(param_1 + 3) = (int)param_5 + 8;
                    /* try { // try from 0026373c to 00263743 has its CatchHandler @ 002637fc */
  __dest = (undefined1 *)thunk_FUN_0023abf0(sVar1);
  *__dest = 0;
  memset(__dest + 1,0,sVar1 - 1);
  param_1[4] = __dest;
  memcpy(__dest,param_4,param_5);
                    /* try { // try from 00263770 to 0026377f has its CatchHandler @ 002637fc */
  FUN_00263220(&local_50,param_1,0);
  uVar6 = (int)param_5 + 0x10;
  uVar5 = (ulong)uVar6;
  if (uVar6 == 0) {
    uVar6 = 0;
    uVar4 = 0;
    if (local_50 == (byte *)0x0) goto LAB_002637d0;
  }
  else {
    uVar6 = 0xffffffff;
    pbVar7 = local_50;
    do {
      uVar5 = uVar5 - 1;
      uVar6 = *(uint *)(&DAT_00154dc4 + ((ulong)(*pbVar7 ^ uVar6) & 0xff) * 4) ^ uVar6 >> 8;
      pbVar7 = pbVar7 + 1;
    } while (uVar5 != 0);
    uVar6 = ~uVar6;
  }
  free(local_50);
  uVar4 = uVar6;
LAB_002637d0:
  *(uint *)(param_1 + 5) = uVar4;
  if (*(long *)(lVar2 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
