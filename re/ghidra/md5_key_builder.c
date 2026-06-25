// Ghidra decompilation of md5_key_builder  (entry=00113474)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00113474(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  byte local_80 [8];
  undefined8 uStack_78;
  void *local_70;
  byte local_68 [8];
  undefined8 uStack_60;
  void *local_58;
  ulong local_50;
  undefined8 uStack_48;
  void *local_40;
  long local_38;
  
  lVar1 = tpidr_el0;
  local_38 = *(long *)(lVar1 + 0x28);
  if ((DAT_00139070 & 1) == 0) {
    local_50 = CONCAT71(_DAT_00139071,DAT_00139070);
    uStack_48 = ram0x00139078;
    local_40 = DAT_00139080;
  }
  else {
    FUN_001172b0(&local_50,DAT_00139080,ram0x00139078);
  }
                    /* try { // try from 001134d8 to 001134e3 has its CatchHandler @ 001135a8 */
  FUN_00113318(&local_50,param_2);
  if ((local_50 & 1) != 0) {
    operator_delete(local_40);
  }
  FUN_001135d8(local_68,param_2,param_1);
  if ((local_68[0] & 1) == 0) {
    local_80[0] = local_68[0];
    uStack_78 = uStack_60;
    local_70 = local_58;
  }
  else {
                    /* try { // try from 00113524 to 0011352b has its CatchHandler @ 0011357c */
    FUN_001172b0(local_80,local_58,uStack_60);
  }
                    /* try { // try from 0011352c to 00113537 has its CatchHandler @ 00113584 */
  FUN_00113318(local_80,param_2);
  if ((local_80[0] & 1) != 0) {
    operator_delete(local_70);
  }
  if ((local_68[0] & 1) != 0) {
    operator_delete(local_58);
  }
  if (*(long *)(lVar1 + 0x28) == local_38) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

