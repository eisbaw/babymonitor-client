// Ghidra decompilation of thingframe_parse  (entry=0026349c)

void FUN_0026349c(long *param_1,undefined8 param_2,ulong param_3)

{
  long lVar1;
  int iVar2;
  undefined4 uVar3;
  undefined1 *puVar4;
  long lVar5;
  ulong uVar6;
  void *local_58;
  long *local_50;
  long local_48;

  lVar5 = DAT_00143a88;
  lVar1 = tpidr_el0;
  local_48 = *(long *)(lVar1 + 0x28);
  *param_1 = (long)&PTR_FUN_002c5b20;
  param_1[1] = lVar5;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  *(undefined8 *)((long)param_1 + 0x27) = 0;
  *(undefined1 *)((long)param_1 + 0x2f) = 1;
  param_1[6] = 0;
                    /* try { // try from 00263500 to 00263507 has its CatchHandler @ 00263650 */
  iVar2 = FUN_002626c0(param_2);
  if (iVar2 != (int)param_1[1]) goto LAB_0026360c;
                    /* try { // try from 00263514 to 0026355f has its CatchHandler @ 00263654 */
  uVar3 = FUN_002626c0(param_2);
  *(undefined4 *)(param_1 + 2) = uVar3;
  uVar3 = FUN_002626c0(param_2);
  *(undefined4 *)((long)param_1 + 0x14) = uVar3;
  uVar3 = FUN_002626c0(param_2);
  *(undefined4 *)(param_1 + 3) = uVar3;
  *(byte *)((long)param_1 + 0x2e) =
       (ulong)*(uint *)((long)param_1 + 0x14) < 0x24 &
       (byte)(0x800280000 >> ((ulong)*(uint *)((long)param_1 + 0x14) & 0x3f));
  uVar3 = FUN_002626c0(param_2);
  *(undefined4 *)((long)param_1 + 0x1c) = uVar3;
  uVar6 = (ulong)((int)param_1[3] - 0xc);
                    /* try { // try from 0026356c to 00263573 has its CatchHandler @ 0026364c */
  puVar4 = (undefined1 *)thunk_FUN_0023abf0(uVar6 + 1);
  *puVar4 = 0;
  memset(puVar4 + 1,0,uVar6);
  param_1[4] = (long)puVar4;
                    /* try { // try from 0026358c to 0026359b has its CatchHandler @ 00263648 */
  FUN_00262880(&local_58,param_2,uVar6);
  if (local_58 != (void *)0x0) {
    memcpy((void *)param_1[4],local_58,uVar6);
    if ((param_3 & 1) != 0) {
                    /* try { // try from 002635b4 to 002635cf has its CatchHandler @ 00263634 */
      uVar3 = FUN_002626c0(param_2);
      *(undefined4 *)(param_1 + 5) = uVar3;
      uVar6 = (**(code **)(*param_1 + 0x20))(param_1);
      if ((uVar6 & 1) == 0) goto LAB_002635dc;
    }
    *(undefined1 *)((long)param_1 + 0x2c) = 1;
  }
LAB_002635dc:
  if ((local_50 != (long *)0x0) &&
     (lVar5 = FUN_0023cb40(0xffffffffffffffff,local_50 + 1), lVar5 == 0)) {
    (**(code **)(*local_50 + 0x10))(local_50);
    FUN_001f9ca4(local_50);
  }
LAB_0026360c:
  if (*(long *)(lVar1 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
