// Ghidra decompilation of frame35_builder  (entry=00264a3c)

void FUN_00264a3c(undefined8 *param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                 size_t param_5,long param_6,uint param_7)

{
  void *__dest;
  ulong uVar1;
  size_t __n;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  int iVar5;
  long lVar6;
  long *plVar7;
  void *__src;
  undefined8 *puVar8;
  long *plVar9;
  undefined8 local_510;
  undefined4 local_508;
  undefined1 local_500;
  undefined1 local_4ff;
  undefined8 local_4fe;
  uint local_4f6;
  long local_3a8;
  long lStack_3a0;
  long local_68;

  lVar3 = tpidr_el0;
  local_68 = *(long *)(lVar3 + 0x28);
  *(undefined1 *)((long)param_1 + 0x2f) = 1;
  *param_1 = &PTR_FUN_002c5ba8;
  *(undefined8 *)((long)param_1 + 0x27) = 0;
  param_1[3] = 0;
  param_1[2] = 0;
  param_1[10] = 0;
  param_1[9] = 0;
  uVar4 = DAT_00143a38;
  param_1[4] = 0;
  param_1[6] = 0;
  *(undefined2 *)(param_1 + 7) = 0;
  param_1[8] = 0;
  param_1[1] = uVar4;
  if (param_6 == 0) {
                    /* try { // try from 00264bb0 to 00264bd3 has its CatchHandler @ 00264ddc */
    __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame ctor, input key is null...",
                        "ThingFrameV3_5",0x116);
  }
  else {
    *(undefined4 *)(param_1 + 2) = param_3;
    *(undefined4 *)((long)param_1 + 0x14) = param_2;
    *(int *)(param_1 + 3) = (int)param_5 + 0x1c;
                    /* try { // try from 00264ad0 to 00264ad7 has its CatchHandler @ 00264df8 */
    lVar6 = FUN_0023abf0(0x1b0);
    *(undefined1 *)(lVar6 + 0x1a8) = 0;
                    /* try { // try from 00264ae0 to 00264b17 has its CatchHandler @ 00264e00 */
    FUN_001ea96c();
    if (0xf < param_7) {
      param_7 = 0x10;
    }
    local_3a8 = 0;
    lStack_3a0 = 0;
    __memcpy_chk(&local_3a8,param_6,param_7,0x10);
    iVar5 = FUN_001ea9ac(lVar6,2,&local_3a8,0x80);
    *(bool *)(lVar6 + 0x1a8) = iVar5 == 0;
    local_3a8 = lVar6;
                    /* try { // try from 00264b28 to 00264b2f has its CatchHandler @ 00264de8 */
    plVar7 = (long *)FUN_0023abf0(0x20);
    plVar9 = plVar7 + 1;
    *plVar9 = 0;
    *plVar7 = (long)&PTR_FUN_002c5c08;
    plVar7[2] = 0;
    plVar7[3] = lVar6;
    local_508 = 0;
    local_510 = 0;
                    /* try { // try from 00264b54 to 00264bab has its CatchHandler @ 00264e10 */
    FUN_001ea168(&local_3a8);
    FUN_001e22e4(&local_500);
    iVar5 = FUN_001e2990(&local_500,PTR_FUN_002c7c60,&local_3a8,0,0);
    if (iVar5 == 0) {
                    /* try { // try from 00264bd8 to 00264bf7 has its CatchHandler @ 00264e10 */
      FUN_001e2bf8(&local_500,&local_510,0xc);
    }
    else {
      __android_log_print(3,"Thing-Network","[%s:%d]mbedtls_ctr_drbg_seed failed with error code %d"
                          ,"GenerateGcmNonce",0x181);
    }
    FUN_001e2348(&local_500);
    FUN_001ea1dc(&local_3a8);
    local_500 = *(undefined1 *)((long)param_1 + 0x39);
    local_4ff = *(undefined1 *)(param_1 + 7);
    local_3a8 = 0;
    lStack_3a0 = 0;
    local_4fe = NEON_rev32(param_1[2],1);
    uVar2 = (*(uint *)(param_1 + 3) & 0xff00ff00) >> 8 | (*(uint *)(param_1 + 3) & 0xff00ff) << 8;
    local_4f6 = uVar2 >> 0x10 | uVar2 << 0x10;
    __src = malloc(param_5);
    if (__src == (void *)0x0) {
                    /* try { // try from 00264cb4 to 00264cdb has its CatchHandler @ 00264dd8 */
      __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame ctor, malloc %d bytes failed...",
                          "ThingFrameV3_5",0x127,param_5);
      lVar6 = FUN_0023cb40(0xffffffffffffffff,plVar9);
    }
    else {
                    /* try { // try from 00264c3c to 00264caf has its CatchHandler @ 00264de4 */
      if ((*(char *)(lVar6 + 0x1a8) == '\0') ||
         (iVar5 = FUN_001eb9d0(lVar6,1,param_5,&local_510,0xc,&local_500,0xe,param_4,__src,0x10,
                               &local_3a8), iVar5 != 0)) {
        printf("[%s:%d] encrypt failed\n","ThingFrameV3_5",300);
        __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame ctor, GcmEncrypt failed...",
                            "ThingFrameV3_5",0x12d);
      }
      else {
        uVar2 = *(uint *)(param_1 + 3);
        puVar8 = (undefined8 *)malloc((ulong)uVar2);
        uVar1 = 0;
        if (0xc < uVar2) {
          uVar1 = (ulong)uVar2 - 0xc;
        }
        __dest = (void *)((long)puVar8 + 0xc);
        param_1[4] = puVar8;
        *puVar8 = local_510;
        __n = 0;
        if (param_5 <= uVar1) {
          __n = uVar1 - param_5;
        }
        *(undefined4 *)(puVar8 + 1) = local_508;
        memset((void *)((long)__dest + param_5),0,__n);
        memcpy(__dest,__src,param_5);
        ((long *)((long)__dest + param_5))[1] = lStack_3a0;
        *(long *)((long)__dest + param_5) = local_3a8;
                    /* try { // try from 00264d7c to 00264d8f has its CatchHandler @ 00264dd4 */
        FUN_00250268(&DAT_0013f6ec,__src,param_5);
      }
      free(__src);
      lVar6 = FUN_0023cb40(0xffffffffffffffff,plVar9);
    }
    if (lVar6 == 0) {
      (**(code **)(*plVar7 + 0x10))(plVar7);
      FUN_001f9ca4(plVar7);
      if (*(long *)(lVar3 + 0x28) == local_68) {
        return;
      }
      goto LAB_00264dd0;
    }
  }
  if (*(long *)(lVar3 + 0x28) == local_68) {
    return;
  }
LAB_00264dd0:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
