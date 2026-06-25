// Ghidra decompilation of getConfig  (entry=001136e0)

undefined8
FUN_001136e0(long *param_1,undefined8 param_2,undefined8 param_3,long param_4,long param_5)

{
  void *pvVar1;
  ulong uVar2;
  ulong uVar3;
  long lVar4;
  long lVar5;
  undefined *puVar6;
  uint uVar7;
  long lVar8;
  size_t __size;
  void *__ptr;
  undefined8 uVar9;
  undefined1 *__s;
  ulong auStack_260 [2];
  undefined1 auStack_250 [8];
  byte local_248 [8];
  ulong local_240;
  void *local_238;
  byte local_230 [8];
  ulong local_228;
  void *local_220;
  undefined1 auStack_218 [432];
  long local_68;
  
  lVar4 = tpidr_el0;
  uVar9 = 0;
  local_68 = *(long *)(lVar4 + 0x28);
  if ((param_4 == 0) || (param_5 == 0)) goto LAB_00113924;
  FUN_001139cc(local_230,param_1,param_4);
                    /* try { // try from 00113734 to 00113743 has its CatchHandler @ 0011399c */
  FUN_001139cc(local_248,param_1,param_5);
  uVar2 = (ulong)(local_230[0] >> 1);
  if ((local_230[0] & 1) != 0) {
    uVar2 = local_228;
  }
  if (uVar2 == 0) {
LAB_00113900:
    uVar9 = 0;
  }
  else {
    uVar2 = (ulong)(local_248[0] >> 1);
    if ((local_248[0] & 1) != 0) {
      uVar2 = local_240;
    }
    if (uVar2 == 0) goto LAB_00113900;
                    /* try { // try from 0011377c to 0011378b has its CatchHandler @ 00113984 */
    uVar9 = (**(code **)(*param_1 + 0xf8))(param_1,param_3);
                    /* try { // try from 00113794 to 001137ab has its CatchHandler @ 00113980 */
    lVar8 = (**(code **)(*param_1 + 0x108))
                      (param_1,uVar9,"getAssets","()Landroid/content/res/AssetManager;");
                    /* try { // try from 001137b4 to 001137c3 has its CatchHandler @ 0011396c */
    if ((lVar8 == 0) || (lVar8 = FUN_00113ac0(param_1,param_3,lVar8), lVar8 == 0))
    goto LAB_00113900;
                    /* try { // try from 001137c8 to 001137cf has its CatchHandler @ 00113968 */
    uVar9 = AAssetManager_fromJava(param_1);
                    /* try { // try from 001137d0 to 001137df has its CatchHandler @ 00113964 */
    lVar8 = AAssetManager_open(uVar9,"t_cdc.tcfg",0);
    if (lVar8 == 0) goto LAB_00113900;
                    /* try { // try from 001137e8 to 001137ef has its CatchHandler @ 00113960 */
    __size = AAsset_getLength(lVar8);
    __ptr = malloc(__size);
                    /* try { // try from 001137fc to 0011380b has its CatchHandler @ 0011395c */
    uVar7 = AAsset_read(lVar8,__ptr,__size);
    lVar5 = -((ulong)uVar7 + 0xf & 0x1fffffff0);
    __s = auStack_250 + lVar5;
    memset(__s,0,(long)(int)uVar7);
    pvVar1 = (void *)((ulong)local_230 | 1);
    if ((local_230[0] & 1) != 0) {
      pvVar1 = local_220;
    }
                    /* try { // try from 00113854 to 0011385f has its CatchHandler @ 00113958 */
    FUN_00111f04(auStack_218,pvVar1,0x10);
    uVar2 = (ulong)(local_248[0] >> 1);
    pvVar1 = (void *)((ulong)local_248 | 1);
    if ((local_248[0] & 1) != 0) {
      uVar2 = local_240;
      pvVar1 = local_238;
    }
    uVar3 = DAT_001390a8;
    puVar6 = DAT_001390b0;
    if ((DAT_001390a0 & 1) == 0) {
      uVar3 = (ulong)(DAT_001390a0 >> 1);
      puVar6 = &DAT_001390a1;
    }
                    /* try { // try from 001138a0 to 001138e7 has its CatchHandler @ 00113970 */
    *(ulong *)((long)auStack_260 + lVar5) = uVar3;
    *(undefined8 *)((long)auStack_260 + lVar5 + 8) = 0;
    FUN_00111f80(auStack_218,pvVar1,puVar6,0,__ptr,(long)(int)uVar7,__s,uVar2);
    uVar9 = (**(code **)(*param_1 + 0x538))(param_1,__s);
    free(__ptr);
    AAsset_close(lVar8);
    FUN_00111f58(auStack_218);
  }
  if ((local_248[0] & 1) != 0) {
    operator_delete(local_238);
  }
  if ((local_230[0] & 1) != 0) {
    operator_delete(local_220);
  }
LAB_00113924:
  if (*(long *)(lVar4 + 0x28) != local_68) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar9;
}

