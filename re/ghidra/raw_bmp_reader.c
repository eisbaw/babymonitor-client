// Ghidra decompilation of raw_bmp_reader  (entry=00113b5c)

void FUN_00113b5c(byte *param_1,long *param_2,undefined8 param_3,ulong param_4)

{
  char *pcVar1;
  byte bVar2;
  long lVar3;
  uint uVar4;
  undefined8 uVar5;
  size_t __size;
  void *__src;
  long lVar6;
  ulong __n;
  void *__dest;
  long local_70;
  ulong uStack_68;
  void *local_60;
  long local_58;
  
  lVar3 = tpidr_el0;
  local_58 = *(long *)(lVar3 + 0x28);
  lVar6 = *param_2;
  param_1[0] = 0;
  param_1[1] = 0;
  uVar5 = (**(code **)(lVar6 + 0xf8))();
  lVar6 = (**(code **)(*param_2 + 0x108))
                    (param_2,uVar5,"getAssets","()Landroid/content/res/AssetManager;");
  if ((lVar6 != 0) && (lVar6 = FUN_00113ac0(param_2,param_3,lVar6), lVar6 != 0)) {
    uVar5 = AAssetManager_fromJava(param_2,lVar6);
    pcVar1 = "t_s_daily.bmp";
    if ((param_4 & 1) == 0) {
      pcVar1 = "t_s.bmp";
    }
    lVar6 = AAssetManager_open(uVar5,pcVar1,0);
    if (lVar6 != 0) {
      __size = AAsset_getLength();
      __src = malloc(__size);
                    /* try { // try from 00113c24 to 00113c33 has its CatchHandler @ 00113d04 */
      uVar4 = AAsset_read(lVar6,__src,__size);
      if (0xffffffef < uVar4) {
        if (*(long *)(lVar3 + 0x28) == local_58) {
                    /* WARNING: Subroutine does not return */
          FUN_001171f4(&local_70);
        }
        goto LAB_00113d30;
      }
      __n = (ulong)(int)uVar4;
      if (uVar4 < 0x17) {
        __dest = (void *)((ulong)&local_70 | 1);
        local_70 = CONCAT71(local_70._1_7_,(char)(uVar4 << 1));
        if (uVar4 != 0) goto LAB_00113c7c;
      }
      else {
        __dest = operator_new((__n | 0xf) + 1);
        local_70 = (__n | 0xf) + 2;
        uStack_68 = __n;
        local_60 = __dest;
LAB_00113c7c:
        memcpy(__dest,__src,__n);
      }
      bVar2 = *param_1;
      *(undefined1 *)((long)__dest + __n) = 0;
      if ((bVar2 & 1) != 0) {
        operator_delete(*(void **)(param_1 + 0x10));
      }
      *(ulong *)(param_1 + 8) = uStack_68;
      *(long *)param_1 = local_70;
      *(void **)(param_1 + 0x10) = local_60;
      free(__src);
                    /* try { // try from 00113cb8 to 00113cbf has its CatchHandler @ 00113d04 */
      AAsset_close(lVar6);
    }
  }
  if (*(long *)(lVar3 + 0x28) == local_58) {
    return;
  }
LAB_00113d30:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

