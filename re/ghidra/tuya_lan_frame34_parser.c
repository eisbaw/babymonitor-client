// Ghidra decompilation of frame34_parser  (entry=00253564)

void FUN_00253564(long param_1,undefined4 *param_2,undefined8 *param_3,size_t *param_4)

{
  undefined4 uVar1;
  uint uVar2;
  byte bVar3;
  long lVar4;
  long *plVar5;
  long *plVar6;
  bool bVar7;
  int iVar8;
  undefined4 uVar9;
  void *pvVar10;
  void *__dest;
  undefined1 *puVar11;
  undefined8 *puVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  long lVar15;
  byte *pbVar16;
  byte *pbVar17;
  long *plVar18;
  undefined8 *puVar19;
  uint *__src;
  long *plVar20;
  size_t sVar21;
  ulong __n;
  undefined8 uVar22;
  byte *local_d0;
  undefined1 auStack_c8 [8];
  undefined8 local_c0;
  size_t sStack_b8;
  void *local_b0;
  int local_a4;
  undefined4 local_a0;
  undefined4 uStack_9c;
  long *local_98;
  long *local_90;
  long *plStack_88;
  ulong local_80;
  ulong local_78;
  long local_68;

  lVar4 = tpidr_el0;
  local_68 = *(long *)(lVar4 + 0x28);
  uVar1 = *param_2;
  sVar21 = *param_4;
  __src = (uint *)*param_3;
  __android_log_print(3,"Thing-Network",
                      "[%s:%d]biznetservice.createSocket2.lambda, going to callback frame, sock: %d, data len: %d, netId %d"
                      ,"operator()",0xa2,uVar1,sVar21,*(undefined8 *)(param_1 + 0x48));
  uVar2 = *__src;
  uVar2 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
  uVar2 = uVar2 >> 0x10 | uVar2 << 0x10;
  pvVar10 = (void *)thunk_FUN_0023abf0(sVar21);
  local_b0 = pvVar10;
  memcpy(pvVar10,__src,sVar21);
  local_c0 = 0;
  sStack_b8 = sVar21;
  if (uVar2 == 0x6699) {
                    /* try { // try from 00253744 to 0025374b has its CatchHandler @ 00253c44 */
    plVar20 = (long *)FUN_0023abf0(0x58);
    pbVar17 = *(byte **)(param_1 + 0x40);
    pbVar16 = *(byte **)(pbVar17 + 0x10);
    bVar7 = (*pbVar17 & 1) == 0;
    if (bVar7) {
      pbVar16 = pbVar17 + 1;
    }
    uVar2 = (uint)(*pbVar17 >> 1);
    if (!bVar7) {
      uVar2 = *(uint *)(pbVar17 + 8);
    }
                    /* try { // try from 00253770 to 00253777 has its CatchHandler @ 00253c10 */
    FUN_00263ebc(plVar20,auStack_c8,pbVar16,uVar2);
    goto LAB_0025378c;
  }
  plVar20 = (long *)0x0;
  if (uVar2 != 0x55aa) goto LAB_0025378c;
                    /* try { // try from 00253614 to 0025361b has its CatchHandler @ 00253c44 */
  plVar20 = (long *)FUN_0023abf0(0x58);
  pbVar16 = *(byte **)(param_1 + 0x40);
  bVar3 = *pbVar16;
  local_d0 = *(byte **)(pbVar16 + 0x10);
  plVar20[1] = DAT_00143a88;
  *(undefined1 *)((long)plVar20 + 0x2f) = 1;
  if ((bVar3 & 1) == 0) {
    local_d0 = pbVar16 + 1;
  }
  plVar20[3] = 0;
  plVar20[4] = 0;
  plVar20[2] = 0;
  *(undefined8 *)((long)plVar20 + 0x27) = 0;
  plVar20[6] = 0;
  *plVar20 = (long)&PTR_FUN_002c5b58;
  plVar18 = plVar20 + 7;
  plVar20[8] = 0;
  *plVar18 = 0;
  plVar20[10] = 0;
  plVar20[9] = 0;
                    /* try { // try from 00253680 to 00253687 has its CatchHandler @ 00253c18 */
  __dest = (void *)thunk_FUN_0023abf0(sVar21);
  memcpy(__dest,pvVar10,sVar21);
                    /* try { // try from 00253698 to 002536d7 has its CatchHandler @ 00253c1c */
  iVar8 = FUN_002626c0(auStack_c8);
  if (iVar8 == (int)plVar20[1]) {
    uVar9 = FUN_002626c0(auStack_c8);
    *(undefined4 *)(plVar20 + 2) = uVar9;
    uVar9 = FUN_002626c0(auStack_c8);
    *(undefined4 *)((long)plVar20 + 0x14) = uVar9;
    uVar9 = FUN_002626c0(auStack_c8);
    *(undefined4 *)(plVar20 + 3) = uVar9;
    uVar9 = FUN_002626c0(auStack_c8);
    *(undefined4 *)((long)plVar20 + 0x1c) = uVar9;
    uVar2 = (int)plVar20[3] - 0x24;
    __n = (ulong)uVar2 - 4;
    if (uVar2 < 5) {
      if (uVar2 != 4) goto LAB_00253784;
    }
    else {
                    /* try { // try from 002536f0 to 002536f7 has its CatchHandler @ 00253c0c */
      puVar11 = (undefined1 *)thunk_FUN_0023abf0(__n);
      *puVar11 = 0;
      memset(puVar11 + 1,0,(ulong)uVar2 - 5);
      plVar20[4] = (long)puVar11;
                    /* try { // try from 00253710 to 0025371f has its CatchHandler @ 00253bf4 */
      FUN_00262880(&local_90,auStack_c8,__n);
      plVar6 = local_90;
      if (local_90 == (long *)0x0) {
        free(__dest);
        plVar5 = plStack_88;
      }
      else {
        memcpy((void *)plVar20[4],local_90,__n);
        plVar5 = plStack_88;
      }
      plStack_88 = plVar5;
      if ((plVar5 != (long *)0x0) &&
         (lVar15 = FUN_0023cb40(0xffffffffffffffff,plVar5 + 1), lVar15 == 0)) {
        (**(code **)(*plVar5 + 0x10))(plVar5);
        FUN_001f9ca4(plVar5);
      }
      if (plVar6 == (long *)0x0) goto LAB_0025378c;
    }
                    /* try { // try from 0025383c to 00253843 has its CatchHandler @ 00253c0c */
    puVar12 = (undefined8 *)thunk_FUN_0023abf0(0x20);
    *plVar18 = (long)puVar12;
    puVar12[1] = 0;
    *puVar12 = 0;
    puVar12[3] = 0;
    puVar12[2] = 0;
                    /* try { // try from 00253850 to 0025385f has its CatchHandler @ 00253bf8 */
    FUN_00262880(&local_a0,auStack_c8,0x20);
    puVar12 = (undefined8 *)CONCAT44(uStack_9c,local_a0);
    if (puVar12 != (undefined8 *)0x0) {
      uVar22 = *puVar12;
      uVar14 = puVar12[3];
      uVar13 = puVar12[2];
      puVar19 = (undefined8 *)*plVar18;
      puVar19[1] = puVar12[1];
      *puVar19 = uVar22;
      puVar19[3] = uVar14;
      puVar19[2] = uVar13;
                    /* try { // try from 00253874 to 002538c7 has its CatchHandler @ 00253bfc */
      iVar8 = FUN_002626c0(auStack_c8);
      if (iVar8 == *(int *)((long)plVar20 + 0xc)) {
        *(undefined1 *)((long)plVar20 + 0x2d) = 1;
        __android_log_print(3,"Thing-Network","[%s:%d]decrypt response callback ","ThingFrameV3_4",
                            0x40);
        if (*(int *)((long)plVar20 + 0x14) == 0x42) {
          local_d0 = (byte *)FUN_00247894(2);
          if ((*local_d0 & 1) != 0) {
            local_d0 = *(byte **)(local_d0 + 0x10);
            goto LAB_002538e4;
          }
          local_d0 = local_d0 + 1;
        }
        else {
LAB_002538e4:
          if (local_d0 == (byte *)0x0) {
                    /* try { // try from 00253b7c to 00253b9f has its CatchHandler @ 00253bfc */
            __android_log_print(3,"Thing-Network","[%s:%d]key is null","ThingFrameV3_4",0x45);
            goto LAB_00253ba0;
          }
        }
        sVar21 = (size_t)((int)plVar20[3] + -0x14);
                    /* try { // try from 002538f8 to 002538ff has its CatchHandler @ 00253be0 */
        pvVar10 = (void *)thunk_FUN_0023abf0(sVar21);
        memcpy(pvVar10,__dest,sVar21);
        plStack_88 = (long *)0x0;
        local_90 = (long *)0x0;
        local_78 = 0;
        local_80 = 0;
                    /* try { // try from 00253918 to 00253947 has its CatchHandler @ 00253be4 */
        uVar13 = mbedcrypto_md_info_from_type(6);
        uVar14 = __strlen_chk(local_d0,0xffffffffffffffff);
        mbedcrypto_md_hmac(uVar13,local_d0,uVar14,pvVar10,sVar21,&local_90);
        puts("iHmac: ");
        printf("%x ",(ulong)local_90 & 0xff);
        printf("%x ",(ulong)local_90 >> 8 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x10 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x18 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x20 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x28 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x30 & 0xff);
        printf("%x ",(ulong)local_90 >> 0x38);
        printf("%x ",(ulong)plStack_88 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 8 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x10 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x18 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x20 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x28 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x30 & 0xff);
        printf("%x ",(ulong)plStack_88 >> 0x38);
        printf("%x ",local_80 & 0xff);
        printf("%x ",local_80 >> 8 & 0xff);
        printf("%x ",local_80 >> 0x10 & 0xff);
        printf("%x ",local_80 >> 0x18 & 0xff);
        printf("%x ",local_80 >> 0x20 & 0xff);
        printf("%x ",local_80 >> 0x28 & 0xff);
        printf("%x ",local_80 >> 0x30 & 0xff);
        printf("%x ",local_80 >> 0x38);
        printf("%x ",local_78 & 0xff);
        printf("%x ",local_78 >> 8 & 0xff);
        printf("%x ",local_78 >> 0x10 & 0xff);
        printf("%x ",local_78 >> 0x18 & 0xff);
        printf("%x ",local_78 >> 0x20 & 0xff);
        printf("%x ",local_78 >> 0x28 & 0xff);
        printf("%x ",local_78 >> 0x30 & 0xff);
        printf("%x ",local_78 >> 0x38);
        puts("\nend");
        plVar18 = (long *)*plVar18;
        if (((local_90 == (long *)*plVar18 && plStack_88 == (long *)plVar18[1]) &&
            local_80 == plVar18[2]) && local_78 == plVar18[3]) {
          local_a4 = 0;
          *(undefined1 *)((long)plVar20 + 0x2c) = 1;
                    /* try { // try from 00253b20 to 00253b33 has its CatchHandler @ 00253bdc */
          aes128_ecb_decode(plVar20[4],__n & 0xffffffff,plVar20 + 6,&local_a4,local_d0);
          *(int *)(plVar20 + 3) = local_a4 + 0x28;
        }
        free(pvVar10);
        if ((local_98 != (long *)0x0) &&
           (lVar15 = FUN_0023cb40(0xffffffffffffffff,local_98 + 1), lVar15 == 0)) {
          (**(code **)(*local_98 + 0x10))(local_98);
          FUN_001f9ca4(local_98);
        }
        goto LAB_00253784;
      }
    }
LAB_00253ba0:
    free(__dest);
    if ((local_98 != (long *)0x0) &&
       (lVar15 = FUN_0023cb40(0xffffffffffffffff,local_98 + 1), lVar15 == 0)) {
      (**(code **)(*local_98 + 0x10))(local_98);
      FUN_001f9ca4(local_98);
    }
  }
  else {
LAB_00253784:
    free(__dest);
  }
LAB_0025378c:
  plVar18 = *(long **)(param_1 + 0x30);
  if (plVar18 != (long *)0x0) {
                    /* try { // try from 002537a4 to 002537af has its CatchHandler @ 00253c44 */
    local_a0 = uVar1;
    local_90 = plVar20;
    (**(code **)(*plVar18 + 0x30))(plVar18,&local_a0,&local_90);
  }
  if (plVar20 != (long *)0x0) {
    (**(code **)(*plVar20 + 8))(plVar20);
  }
  if (local_b0 != (void *)0x0) {
    free(local_b0);
  }
  if (*(long *)(lVar4 + 0x28) == local_68) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
