// Ghidra decompilation of frame35_parser  (entry=00263ebc)

void FUN_00263ebc(undefined8 *param_1,undefined8 param_2,void *param_3,uint param_4)

{
  uint uVar1;
  long lVar2;
  bool bVar3;
  char cVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  void *pvVar8;
  undefined4 *__ptr;
  long lVar9;
  char *pcVar10;
  undefined8 uVar11;
  size_t sVar12;
  uint uVar13;
  long local_e8;
  undefined8 local_e0;
  ulong local_d8;
  undefined8 local_d0;
  void *local_c8;
  undefined8 *local_c0;
  undefined8 local_b8;
  void *local_b0;
  long *local_a8;
  undefined8 *local_a0;
  long *local_98;
  undefined1 local_90;
  undefined1 local_8f;
  undefined8 local_8e;
  uint local_86;
  undefined8 local_80;
  undefined8 uStack_78;
  undefined8 local_68;
  undefined4 local_60;
  long local_58;

  lVar2 = tpidr_el0;
  local_58 = *(long *)(lVar2 + 0x28);
  *(undefined1 *)((long)param_1 + 0x2f) = 1;
  *param_1 = &PTR_FUN_002c5ba8;
  *(undefined8 *)((long)param_1 + 0x27) = 0;
  param_1[3] = 0;
  param_1[2] = 0;
  param_1[10] = 0;
  param_1[9] = 0;
  uVar11 = DAT_00143a38;
  param_1[4] = 0;
  param_1[6] = 0;
  *(undefined2 *)(param_1 + 7) = 0;
  param_1[8] = 0;
  param_1[1] = uVar11;
                    /* try { // try from 00263f3c to 00263f43 has its CatchHandler @ 002644fc */
  iVar5 = FUN_002626c0(param_2);
  if (iVar5 != *(int *)(param_1 + 1)) goto LAB_00263fac;
                    /* try { // try from 00263f50 to 0026401f has its CatchHandler @ 00264500 */
  cVar4 = FUN_002627a0(param_2);
  if (cVar4 == '\0') {
    *(undefined1 *)((long)param_1 + 0x39) = 0;
    cVar4 = FUN_002627a0(param_2);
    *(char *)(param_1 + 7) = cVar4;
    if (cVar4 == '\0') {
      uVar6 = FUN_002626c0(param_2);
      *(undefined4 *)(param_1 + 2) = uVar6;
      uVar6 = FUN_002626c0(param_2);
      *(undefined4 *)((long)param_1 + 0x14) = uVar6;
      __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame, frame type: %d...\n",
                          "ThingFrameV3_5",0x2f,uVar6);
      iVar5 = FUN_002626c0(param_2);
      *(int *)(param_1 + 3) = iVar5;
      local_60 = 0;
      local_68 = 0;
      *(bool *)((long)param_1 + 0x2f) = *(int *)((long)param_1 + 0x14) != 0x15;
                    /* try { // try from 00264040 to 0026404f has its CatchHandler @ 002644f8 */
      FUN_00262880(&local_a0,param_2,0xc);
      if (local_a0 == (undefined8 *)0x0) {
        uVar11 = 0x3e;
        pcVar10 = "[%s:%d]v3.5 frame, readbyte nonce value error";
LAB_002642a4:
                    /* try { // try from 002642a4 to 002642bb has its CatchHandler @ 002644e8 */
        __android_log_print(3,"Thing-Network",pcVar10,"ThingFrameV3_5",uVar11);
      }
      else {
        local_60 = *(undefined4 *)(local_a0 + 1);
        local_68 = *local_a0;
        pvVar8 = malloc((long)(iVar5 + -0x1b));
        sVar12 = (size_t)(iVar5 + -0x1c);
        param_1[4] = pvVar8;
        memset(pvVar8,0,sVar12);
        if (pvVar8 == (void *)0x0) {
          uVar11 = 0x45;
          pcVar10 = "[%s:%d]v3.5 frame, alloc nonce error";
          goto LAB_002642a4;
        }
                    /* try { // try from 00264094 to 002640a3 has its CatchHandler @ 002644e4 */
        FUN_00262880(&local_b0,param_2,sVar12);
        if (local_b0 == (void *)0x0) {
                    /* try { // try from 002642c0 to 002642e3 has its CatchHandler @ 002644a4 */
          __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame, readbyte data value error",
                              "ThingFrameV3_5",0x4a);
        }
        else {
          memcpy((void *)param_1[4],local_b0,sVar12);
          local_80 = 0;
          uStack_78 = 0;
                    /* try { // try from 002640bc to 002640cb has its CatchHandler @ 002644d4 */
          FUN_00262880(&local_c0,param_2,0x10);
          if (local_c0 == (undefined8 *)0x0) {
                    /* try { // try from 002642e8 to 0026430b has its CatchHandler @ 002644a0 */
            __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame, readbyte gcm tag value error",
                                "ThingFrameV3_5",0x52);
          }
          else {
            uStack_78 = local_c0[1];
            local_80 = *local_c0;
                    /* try { // try from 002640dc to 002640e3 has its CatchHandler @ 002644c4 */
            iVar7 = FUN_002626c0(param_2);
            if (iVar7 == *(int *)((long)param_1 + 0xc)) {
              local_90 = *(undefined1 *)((long)param_1 + 0x39);
              *(undefined1 *)((long)param_1 + 0x2d) = 1;
              local_8f = *(undefined1 *)(param_1 + 7);
              uVar13 = (uint)((ulong)param_1[2] >> 0x20);
              local_8e = NEON_rev32(param_1[2],1);
              uVar1 = (*(uint *)(param_1 + 3) & 0xff00ff00) >> 8 |
                      (*(uint *)(param_1 + 3) & 0xff00ff) << 8;
              local_86 = uVar1 >> 0x10 | uVar1 << 0x10;
              local_d8 = 0;
              local_d0 = 0;
              local_c8 = (void *)0x0;
              if ((uVar13 | 4) == 0x15) {
                    /* try { // try from 00264138 to 00264193 has its CatchHandler @ 002644ac */
                uVar11 = FUN_00247894(0);
                FUN_001fa998(&local_d8,uVar11);
                bVar3 = (local_d8 & 1) != 0;
                uVar13 = *(uint *)((long)param_1 + 0x14);
                param_3 = (void *)((ulong)&local_d8 | 1);
                if (bVar3) {
                  param_3 = local_c8;
                }
                param_4 = (uint)((byte)local_d8 >> 1);
                if (bVar3) {
                  param_4 = (uint)local_d0;
                }
              }
              if (uVar13 == 0x42) {
                uVar11 = FUN_00247894(2);
                FUN_001fa998(&local_d8,uVar11);
                bVar3 = (local_d8 & 1) != 0;
                param_3 = (void *)((ulong)&local_d8 | 1);
                if (bVar3) {
                  param_3 = local_c8;
                }
                param_4 = (uint)((byte)local_d8 >> 1);
                if (bVar3) {
                  param_4 = (uint)local_d0;
                }
              }
                    /* try { // try from 002641b4 to 002641bb has its CatchHandler @ 002644a8 */
              uVar11 = FUN_0023abf0(0x1b0);
                    /* try { // try from 002641bc to 002641cb has its CatchHandler @ 00264490 */
              FUN_0026b1a8(uVar11,param_3,param_4);
                    /* try { // try from 002641cc to 002641d7 has its CatchHandler @ 002644a8 */
              FUN_00264528(&local_e8,uVar11);
              __ptr = (undefined4 *)calloc(1,sVar12);
              if (__ptr == (undefined4 *)0x0) {
                    /* try { // try from 00264338 to 0026435b has its CatchHandler @ 0026447c */
                __android_log_print(3,"Thing-Network",
                                    "[%s:%d]alloc memory failed before gcm decrypt...",
                                    "ThingFrameV3_5",0x78);
              }
              else {
                if (*(char *)(local_e8 + 0x1a8) == '\0') {
                  iVar7 = -1;
LAB_00264364:
                    /* try { // try from 00264364 to 0026438f has its CatchHandler @ 00264480 */
                  __android_log_print(3,"Thing-Network","[%s:%d][%s:%d] decrypt failed %d\n",
                                      "ThingFrameV3_5",0x7e,"ThingFrameV3_5",0x7e,iVar7);
                }
                else {
                    /* try { // try from 002641fc to 0026421f has its CatchHandler @ 00264480 */
                  iVar7 = FUN_001eba60(local_e8,sVar12,&local_68,0xc,&local_90,0xe,&local_80,0x10,
                                       param_1[4],__ptr);
                  if (iVar7 != 0) goto LAB_00264364;
                  *(undefined1 *)((long)param_1 + 0x2c) = 1;
                  if (*(char *)((long)param_1 + 0x2f) != '\0') {
                    *(undefined4 *)((long)param_1 + 0x1c) = *__ptr;
                    /* try { // try from 00264240 to 00264263 has its CatchHandler @ 00264478 */
                    __android_log_print(3,"Thing-Network","[%s:%d]v3.5 frame, code value: %d...\n",
                                        "ThingFrameV3_5",0x87);
                    if (*(int *)((long)param_1 + 0x14) != 9) {
                      uVar13 = 4;
                      goto LAB_00264428;
                    }
                    free(__ptr);
                    uVar11 = 0x8b;
                    pcVar10 = "[%s:%d]v3.5 frame, heart_beat type, return";
LAB_0026445c:
                    /* try { // try from 0026445c to 00264473 has its CatchHandler @ 00264478 */
                    __android_log_print(3,"Thing-Network",pcVar10,"ThingFrameV3_5",uVar11);
                    goto LAB_00264398;
                  }
                  uVar13 = 0;
LAB_00264428:
                  sVar12 = (size_t)(int)((iVar5 + -0x1c) - uVar13);
                  pvVar8 = malloc(sVar12);
                  param_1[6] = pvVar8;
                  if (pvVar8 == (void *)0x0) {
                    uVar11 = 0x91;
                    pcVar10 = "[%s:%d]v3.5 frame, decrypt data error";
                    goto LAB_0026445c;
                  }
                  memcpy(pvVar8,(void *)((long)__ptr + (ulong)uVar13),sVar12);
                }
                free(__ptr);
              }
LAB_00264398:
              FUN_002470e4(local_e0);
              if ((local_d8 & 1) != 0) {
                free(local_c8);
              }
            }
            else {
                    /* try { // try from 00264310 to 00264333 has its CatchHandler @ 002644c4 */
              __android_log_print(3,"Thing-Network","[%s:%d]footer check failed","ThingFrameV3_5",
                                  0x58);
            }
          }
          FUN_0026367c(local_b8);
        }
        if ((local_a8 != (long *)0x0) &&
           (lVar9 = FUN_0023cb40(0xffffffffffffffff,local_a8 + 1), lVar9 == 0)) {
          (**(code **)(*local_a8 + 0x10))(local_a8);
          FUN_001f9ca4(local_a8);
        }
      }
      if ((local_98 != (long *)0x0) &&
         (lVar9 = FUN_0023cb40(0xffffffffffffffff,local_98 + 1), lVar9 == 0)) {
        (**(code **)(*local_98 + 0x10))(local_98);
        FUN_001f9ca4(local_98);
      }
      goto LAB_00263fac;
    }
    uVar11 = 0x29;
    pcVar10 = "[%s:%d]v3.5 frame, readbyte reserved value error";
  }
  else {
    uVar11 = 0x23;
    pcVar10 = "[%s:%d]v3.5 frame, readbyte value error";
  }
  __android_log_print(3,"Thing-Network",pcVar10,"ThingFrameV3_5",uVar11);
LAB_00263fac:
  if (*(long *)(lVar2 + 0x28) != local_58) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
