// Ghidra decompilation of jni_sendCMD  (entry=00292244)

ulong FUN_00292244(long *param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                  undefined4 param_5,undefined4 param_6,int param_7)

{
  undefined8 *puVar1;
  long *plVar2;
  size_t sVar3;
  long lVar4;
  char *pcVar5;
  undefined4 uVar6;
  byte bVar7;
  ulong uVar8;
  long lVar9;
  byte **ppbVar10;
  byte ***__ptr;
  int iVar11;
  char *__s;
  size_t sVar12;
  ulong uVar13;
  byte *pbVar14;
  byte *pbVar15;
  byte **ppbVar16;
  long lVar17;
  undefined1 *__dest;
  undefined8 uVar18;
  uint uVar19;
  long *plVar20;
  ulong uVar21;
  long lVar22;
  byte *pbVar23;
  long lVar24;
  uint uVar25;
  long *plVar26;
  char *pcVar27;
  char *pcVar28;
  ulong uVar29;
  ulong uVar30;
  ulong uVar31;
  undefined8 *puVar32;
  void *__dest_00;
  byte *pbVar33;
  long lVar34;
  undefined2 uVar35;
  ulong local_108;
  size_t local_100;
  void *local_f8;
  ulong local_f0;
  size_t sStack_e8;
  char *local_e0;
  byte *local_d0;
  byte **local_c8;
  byte **local_c0;
  long local_b8;
  byte ***local_b0;
  undefined1 local_a8;
  byte *local_a0;
  byte *pbStack_98;
  byte *local_90;
  byte **local_80;
  long local_70;

  lVar9 = tpidr_el0;
  local_70 = *(long *)(lVar9 + 0x28);
  __s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  lVar24 = DAT_002d19b0;
  if ((__s == (char *)0x0) || (*__s == '\0')) {
    plVar26 = (long *)0xffffffff;
    if (*(long *)(lVar9 + 0x28) != local_70) goto LAB_00292e44;
    goto LAB_002923c8;
  }
  sVar12 = strlen(__s);
  if (0xffffffffffffffef < sVar12) {
    if (*(long *)(lVar9 + 0x28) == local_70) {
                    /* WARNING: Subroutine does not return */
      FUN_00242b50(&local_108);
    }
    goto LAB_00292e44;
  }
  if (sVar12 < 0x17) {
    __dest_00 = (void *)((ulong)&local_108 | 1);
    local_108 = CONCAT71(local_108._1_7_,(char)((int)sVar12 << 1));
    if (sVar12 != 0) goto LAB_00292328;
  }
  else {
    __dest_00 = (void *)FUN_0023abf0((sVar12 | 0xf) + 1);
    local_108 = (sVar12 | 0xf) + 2;
    local_100 = sVar12;
    local_f8 = __dest_00;
LAB_00292328:
    memmove(__dest_00,__s,sVar12);
  }
  *(undefined1 *)((long)__dest_00 + sVar12) = 0;
                    /* try { // try from 0029233c to 00292343 has its CatchHandler @ 00292df0 */
  FUN_001fc980(lVar24 + 0x180);
  plVar26 = *(long **)(lVar24 + 0x170);
  if (plVar26 == (long *)0x0) {
LAB_00292384:
    FUN_001fc9ac(lVar24 + 0x180);
    plVar26 = (long *)0x1;
  }
  else {
    plVar20 = (long *)(lVar24 + 0x170);
    do {
      plVar2 = plVar26;
      if ((int)plVar26[4] < param_7) {
        plVar2 = plVar20;
        plVar26 = plVar26 + 1;
      }
      plVar26 = (long *)*plVar26;
      plVar20 = plVar2;
    } while (plVar26 != (long *)0x0);
    if ((plVar2 == (long *)(lVar24 + 0x170)) || (param_7 < (int)plVar2[4])) goto LAB_00292384;
    lVar4 = plVar2[5];
    plVar26 = (long *)plVar2[6];
    if (plVar26 != (long *)0x0) {
      FUN_0023cb10(1,plVar26 + 1);
    }
    FUN_001fc9ac(lVar24 + 0x180);
    if ((*(byte *)(lVar4 + 200) & 1) == 0) {
      sStack_e8 = *(size_t *)(lVar4 + 0xd0);
      local_f0 = *(ulong *)(lVar4 + 200);
      local_e0 = *(char **)(lVar4 + 0xd8);
    }
    else {
                    /* try { // try from 00292434 to 0029243b has its CatchHandler @ 00292c40 */
      FUN_00243654(&local_f0,*(undefined8 *)(lVar4 + 0xd8),*(undefined8 *)(lVar4 + 0xd0));
    }
    plVar20 = DAT_002d1840;
    sVar12 = local_f0 >> 1 & 0x7f;
    pcVar5 = (char *)((ulong)&local_f0 | 1);
    if ((local_f0 & 1) != 0) {
      sVar12 = sStack_e8;
      pcVar5 = local_e0;
    }
    uVar13 = FUN_002484c4(pcVar5,sVar12);
    uVar31 = plVar20[1];
    if (uVar31 != 0) {
      uVar18 = CONCAT17(POPCOUNT((char)(uVar31 >> 0x38)),
                        CONCAT16(POPCOUNT((char)(uVar31 >> 0x30)),
                                 CONCAT15(POPCOUNT((char)(uVar31 >> 0x28)),
                                          CONCAT14(POPCOUNT((char)(uVar31 >> 0x20)),
                                                   CONCAT13(POPCOUNT((char)(uVar31 >> 0x18)),
                                                            CONCAT12(POPCOUNT((char)(uVar31 >> 0x10)
                                                                             ),
                                                                     CONCAT11(POPCOUNT((char)(uVar31
                                                                                             >> 8)),
                                                                              POPCOUNT((char)uVar31)
                                                                             )))))));
      uVar35 = NEON_uaddlv(uVar18,1);
      uVar29 = CONCAT62((int6)((ulong)uVar18 >> 0x10),uVar35) & 0xffffffff;
      if (uVar29 < 2) {
        uVar30 = uVar31 - 1 & uVar13;
      }
      else {
        uVar30 = uVar13;
        if (uVar31 <= uVar13) {
          uVar30 = 0;
          if (uVar31 != 0) {
            uVar30 = uVar13 / uVar31;
          }
          uVar30 = uVar13 - uVar30 * uVar31;
        }
      }
      plVar20 = *(long **)(*plVar20 + uVar30 * 8);
      if ((plVar20 != (long *)0x0) && (plVar20 = (long *)*plVar20, plVar20 != (long *)0x0)) {
LAB_002924ec:
        uVar21 = plVar20[1];
        if (uVar21 == uVar13) {
          bVar7 = *(byte *)(plVar20 + 2);
          uVar21 = (ulong)(bVar7 >> 1);
          sVar3 = uVar21;
          if ((bVar7 & 1) != 0) {
            sVar3 = plVar20[3];
          }
          if (sVar3 != sVar12) goto LAB_002924e4;
          if ((bVar7 & 1) != 0) {
            iVar11 = memcmp((void *)plVar20[4],pcVar5,plVar20[3]);
            if (iVar11 == 0) goto LAB_0029259c;
            goto LAB_002924e4;
          }
          if (1 < bVar7) {
            pcVar27 = (char *)((long)plVar20 + 0x11);
            pcVar28 = pcVar5;
            while (*pcVar27 == *pcVar28) {
              uVar21 = uVar21 - 1;
              pcVar27 = pcVar27 + 1;
              pcVar28 = pcVar28 + 1;
              if (uVar21 == 0) goto LAB_0029259c;
            }
            goto LAB_002924e4;
          }
LAB_0029259c:
          pbStack_98 = (byte *)0x0;
          local_90 = (byte *)0x0;
          local_a0 = (byte *)0x0;
          lVar17 = *(long *)plVar20[5];
          puVar32 = (undefined8 *)((long *)plVar20[5])[1];
          local_c8 = &local_a0;
          local_c0 = (byte **)((ulong)local_c0 & 0xffffffffffffff00);
          lVar22 = (long)puVar32 - lVar17;
          if (lVar22 != 0) {
            if (-1 < lVar22) {
                    /* try { // try from 002925c4 to 002925cb has its CatchHandler @ 00292c30 */
              pbVar14 = (byte *)FUN_0023abf0(lVar22);
              lVar34 = 0;
              local_90 = pbVar14 + lVar22;
              local_a0 = pbVar14;
              pbStack_98 = pbVar14;
              do {
                puVar1 = (undefined8 *)(lVar17 + lVar34);
                *(undefined8 *)(pbVar14 + lVar34) = *puVar1;
                lVar22 = puVar1[1];
                *(long *)(pbVar14 + lVar34 + 8) = lVar22;
                if (lVar22 != 0) {
                  FUN_0023cb10(1,lVar22 + 8);
                }
                lVar34 = lVar34 + 0x10;
              } while (puVar1 + 2 != puVar32);
              pbStack_98 = pbVar14 + lVar34;
              goto LAB_00292630;
            }
            goto LAB_00292c14;
          }
          pbVar14 = (byte *)0x0;
          goto LAB_00292630;
        }
        if (uVar29 < 2) {
          uVar21 = uVar21 & uVar31 - 1;
        }
        else if (uVar31 <= uVar21) {
          uVar8 = 0;
          if (uVar31 != 0) {
            uVar8 = uVar21 / uVar31;
          }
          uVar21 = uVar21 - uVar8 * uVar31;
        }
        if (uVar21 == uVar30) goto LAB_002924e4;
      }
    }
LAB_00292620:
    pbVar14 = (byte *)0x0;
    local_a0 = (byte *)0x0;
    pbStack_98 = (byte *)0x0;
    local_90 = (byte *)0x0;
LAB_00292630:
                    /* try { // try from 00292630 to 00292637 has its CatchHandler @ 00292d94 */
    pbVar33 = pbStack_98;
    pbVar15 = (byte *)FUN_0023abf0(0xa0);
    local_b0 = &local_c8;
    lVar17 = (long)pbVar33 - (long)pbVar14;
    local_c8 = (byte **)0x0;
    local_c0 = (byte **)0x0;
    local_b8 = 0;
    local_a8 = 0;
    ppbVar16 = local_c0;
    if (lVar17 != 0) {
      if (lVar17 < 0) {
        if (*(long *)(lVar9 + 0x28) == local_70) {
                    /* try { // try from 00292c10 to 00292c13 has its CatchHandler @ 00292d60 */
          FUN_00248340();
LAB_00292c14:
          if (*(long *)(lVar9 + 0x28) == local_70) {
                    /* try { // try from 00292c28 to 00292c2b has its CatchHandler @ 00292c30 */
            uVar18 = FUN_00248340();
                    /* catch() { ... } // from try @ 002929b0 with catch @ 00292e0c */
            FUN_0024891c(&local_d0);
            FUN_00246434(plVar26);
                    /* catch() { ... } // from try @ 00292bc4 with catch @ 00292c2c */
            if ((local_108 & 1) == 0) {
              if (*(long *)(lVar9 + 0x28) == local_70) goto LAB_00292dcc;
            }
            else {
              free(local_f8);
              if (*(long *)(lVar9 + 0x28) == local_70) {
LAB_00292dcc:
                    /* WARNING: Subroutine does not return */
                FUN_0023cd9c(uVar18);
              }
            }
          }
        }
        goto LAB_00292e44;
      }
                    /* try { // try from 00292658 to 0029265f has its CatchHandler @ 00292d60 */
      ppbVar16 = (byte **)FUN_0023abf0(lVar17);
      local_b8 = (long)ppbVar16 + lVar17;
      local_c8 = ppbVar16;
      local_c0 = ppbVar16;
      do {
        *ppbVar16 = *(byte **)pbVar14;
        pbVar23 = *(byte **)(pbVar14 + 8);
        ppbVar16[1] = pbVar23;
        if (pbVar23 != (byte *)0x0) {
          FUN_0023cb10(1,pbVar23 + 8);
        }
        pbVar14 = pbVar14 + 0x10;
        ppbVar16 = ppbVar16 + 2;
      } while (pbVar14 != pbVar33);
    }
    local_c0 = ppbVar16;
    pbVar15[0] = 0;
    pbVar15[1] = 0;
    pbVar14 = pbVar15 + 0x20;
    pbVar14[0] = 0;
    pbVar14[1] = 0;
    pbVar15[0x38] = 0;
    pbVar15[0x39] = 0;
    pbVar15[0x50] = 0;
    pbVar15[0x51] = 0;
    pbVar15[0x68] = 0;
    pbVar15[0x69] = 0;
    pbVar33 = pbVar15 + 0x88;
    pbVar33[0] = 0;
    pbVar33[1] = 0;
    pbVar33[2] = 0;
    pbVar33[3] = 0;
    pbVar33[4] = 0;
    pbVar33[5] = 0;
    pbVar33[6] = 0;
    pbVar33[7] = 0;
    pbVar15[0x90] = 0;
    pbVar15[0x91] = 0;
    pbVar15[0x92] = 0;
    pbVar15[0x93] = 0;
    pbVar15[0x94] = 0;
    pbVar15[0x95] = 0;
    pbVar15[0x96] = 0;
    pbVar15[0x97] = 0;
    pbVar15[0x98] = 0;
    pbVar15[0x99] = 0;
    pbVar15[0x9a] = 0;
    pbVar15[0x9b] = 0;
    pbVar15[0x9c] = 0;
    pbVar15[0x9d] = 0;
    pbVar15[0x9e] = 0;
    pbVar15[0x9f] = 0;
    puts("LanProtocolBuilder");
                    /* try { // try from 002926e8 to 002926ef has its CatchHandler @ 00292cd4 */
    FUN_002683f0(pbVar33,local_c8,local_c0,(long)local_c0 - (long)local_c8 >> 4);
    ppbVar10 = local_c8;
    ppbVar16 = local_c0;
    if (local_c8 != (byte **)0x0) {
      for (; ppbVar16 != ppbVar10; ppbVar16 = ppbVar16 + -2) {
        pbVar33 = ppbVar16[-1];
        if ((pbVar33 != (byte *)0x0) &&
           (lVar17 = FUN_0023cb40(0xffffffffffffffff,pbVar33 + 8), lVar17 == 0)) {
          (**(code **)(*(long *)pbVar33 + 0x10))(pbVar33);
          FUN_001f9ca4(pbVar33);
        }
      }
      local_c0 = ppbVar10;
      free(local_c8);
    }
                    /* try { // try from 00292758 to 00292763 has its CatchHandler @ 00292d94 */
    FUN_001fa998(pbVar14,&local_f0);
    pbVar33 = local_a0;
    local_d0 = pbVar15;
    pbVar14 = pbStack_98;
    if (local_a0 != (byte *)0x0) {
      for (; pbVar14 != pbVar33; pbVar14 = pbVar14 + -0x10) {
        plVar20 = *(long **)(pbVar14 + -8);
        if ((plVar20 != (long *)0x0) &&
           (lVar17 = FUN_0023cb40(0xffffffffffffffff,plVar20 + 1), lVar17 == 0)) {
          (**(code **)(*plVar20 + 0x10))(plVar20);
          FUN_001f9ca4(plVar20);
        }
      }
      pbStack_98 = pbVar33;
      free(local_a0);
    }
    if ((local_f0 & 1) != 0) {
      free(local_e0);
    }
    pbVar14 = local_d0;
                    /* try { // try from 002927e4 to 002927ef has its CatchHandler @ 00292d90 */
    FUN_001fa998(local_d0,&local_108);
    *(undefined4 *)(pbVar14 + 0x84) = param_5;
    plVar20 = DAT_002d1840;
    bVar7 = *(byte *)(lVar4 + 0xe0);
    sVar12 = *(size_t *)(lVar4 + 0xe8);
    pcVar5 = *(char **)(lVar4 + 0xf0);
    if ((bVar7 & 1) == 0) {
      pcVar5 = (char *)(lVar4 + 0xe1);
      sVar12 = (ulong)(bVar7 >> 1);
    }
    uVar13 = FUN_002484c4(pcVar5,sVar12);
    uVar31 = plVar20[6];
    if (uVar31 != 0) {
      uVar18 = CONCAT17(POPCOUNT((char)(uVar31 >> 0x38)),
                        CONCAT16(POPCOUNT((char)(uVar31 >> 0x30)),
                                 CONCAT15(POPCOUNT((char)(uVar31 >> 0x28)),
                                          CONCAT14(POPCOUNT((char)(uVar31 >> 0x20)),
                                                   CONCAT13(POPCOUNT((char)(uVar31 >> 0x18)),
                                                            CONCAT12(POPCOUNT((char)(uVar31 >> 0x10)
                                                                             ),
                                                                     CONCAT11(POPCOUNT((char)(uVar31
                                                                                             >> 8)),
                                                                              POPCOUNT((char)uVar31)
                                                                             )))))));
      uVar35 = NEON_uaddlv(uVar18,1);
      uVar29 = CONCAT62((int6)((ulong)uVar18 >> 0x10),uVar35) & 0xffffffff;
      if (uVar29 < 2) {
        uVar30 = uVar31 - 1 & uVar13;
      }
      else {
        uVar30 = uVar13;
        if (uVar31 <= uVar13) {
          uVar30 = 0;
          if (uVar31 != 0) {
            uVar30 = uVar13 / uVar31;
          }
          uVar30 = uVar13 - uVar30 * uVar31;
        }
      }
      plVar20 = *(long **)(plVar20[5] + uVar30 * 8);
      if ((plVar20 != (long *)0x0) && (plVar20 = (long *)*plVar20, plVar20 != (long *)0x0)) {
        do {
          uVar21 = plVar20[1];
          if (uVar21 == uVar13) {
            bVar7 = *(byte *)(plVar20 + 2);
            uVar21 = (ulong)(bVar7 >> 1);
            sVar3 = uVar21;
            if ((bVar7 & 1) != 0) {
              sVar3 = plVar20[3];
            }
            if (sVar3 == sVar12) {
              if ((bVar7 & 1) == 0) {
                if (bVar7 < 2) {
LAB_00292940:
                  if ((*(byte *)(plVar20 + 5) & 1) == 0) {
                    pbStack_98 = (byte *)plVar20[6];
                    local_a0 = (byte *)plVar20[5];
                    local_90 = (byte *)plVar20[7];
                  }
                  else {
                    /* try { // try from 00292bc4 to 00292bcf has its CatchHandler @ 00292c2c */
                    FUN_00243654(&local_a0,plVar20[7],plVar20[6]);
                  }
                  goto LAB_00292968;
                }
                pcVar27 = (char *)((long)plVar20 + 0x11);
                pcVar28 = pcVar5;
                while (*pcVar27 == *pcVar28) {
                  uVar21 = uVar21 - 1;
                  pcVar27 = pcVar27 + 1;
                  pcVar28 = pcVar28 + 1;
                  if (uVar21 == 0) goto LAB_00292940;
                }
              }
              else {
                iVar11 = memcmp((void *)plVar20[4],pcVar5,plVar20[3]);
                if (iVar11 == 0) goto LAB_00292940;
              }
            }
          }
          else {
            if (uVar29 < 2) {
              uVar21 = uVar21 & uVar31 - 1;
            }
            else if (uVar31 <= uVar21) {
              uVar8 = 0;
              if (uVar31 != 0) {
                uVar8 = uVar21 / uVar31;
              }
              uVar21 = uVar21 - uVar8 * uVar31;
            }
            if (uVar21 != uVar30) break;
          }
          plVar20 = (long *)*plVar20;
        } while (plVar20 != (long *)0x0);
      }
    }
    local_a0 = (byte *)((ulong)local_a0 & 0xffffffffffff0000);
LAB_00292968:
                    /* try { // try from 00292968 to 00292973 has its CatchHandler @ 00292cbc */
    FUN_001fa998(pbVar14 + 0x38,&local_a0);
    if (((ulong)local_a0 & 1) != 0) {
      free(local_90);
    }
    *(undefined4 *)(pbVar14 + 0x80) = param_6;
                    /* try { // try from 0029298c to 00292997 has its CatchHandler @ 00292d90 */
    FUN_001fa998(pbVar14 + 0x68,(byte *)(lVar4 + 0xe0));
    puVar32 = *(undefined8 **)(pbVar14 + 0x88);
    if (puVar32 != *(undefined8 **)(pbVar14 + 0x90)) {
      do {
                    /* try { // try from 002929b0 to 002929b7 has its CatchHandler @ 00292e0c */
        (**(code **)(*(long *)*puVar32 + 0x10))((long *)*puVar32,pbVar14);
        puVar32 = puVar32 + 2;
      } while (puVar32 != *(undefined8 **)(pbVar14 + 0x90));
    }
                    /* try { // try from 002929c8 to 002929cf has its CatchHandler @ 00292cb8 */
    plVar20 = (long *)FUN_0023abf0(0x38);
    uVar6 = *(undefined4 *)(lVar4 + 0xc0);
    *plVar20 = (long)&PTR_FUN_002c5b20;
    lVar4 = DAT_00143a88;
    plVar20[3] = 0;
    plVar20[4] = 0;
    *(undefined1 *)((long)plVar20 + 0x2f) = 1;
    plVar20[1] = lVar4;
    *(undefined8 *)((long)plVar20 + 0x27) = 0;
    plVar20[6] = 0;
    *(undefined4 *)(plVar20 + 2) = uVar6;
    *(undefined4 *)((long)plVar20 + 0x14) = param_4;
    sVar12 = (ulong)(*pbVar14 >> 1);
    if ((*pbVar14 & 1) != 0) {
      sVar12 = *(size_t *)(pbVar14 + 8);
    }
    sVar3 = sVar12;
    if (sVar12 == 0) {
      sVar3 = 0xffffffffffffffff;
    }
    *(int *)(plVar20 + 3) = (int)sVar12 + 8;
                    /* try { // try from 00292a30 to 00292a37 has its CatchHandler @ 00292d78 */
    __dest = (undefined1 *)thunk_FUN_0023abf0(sVar3);
    *__dest = 0;
    memset(__dest + 1,0,sVar3 - 1);
    plVar20[4] = (long)__dest;
    pbVar33 = *(byte **)(pbVar14 + 0x10);
    if ((*pbVar14 & 1) == 0) {
      pbVar33 = pbVar14 + 1;
    }
    memcpy(__dest,pbVar33,sVar12);
                    /* try { // try from 00292a70 to 00292a7f has its CatchHandler @ 00292d78 */
    FUN_00263220(&local_a0,plVar20,0);
    uVar25 = (int)sVar12 + 0x10;
    uVar13 = (ulong)uVar25;
    if (uVar25 == 0) {
      uVar25 = 0;
      uVar19 = 0;
      if (local_a0 != (byte *)0x0) goto LAB_00292ac8;
    }
    else {
      uVar25 = 0xffffffff;
      pbVar33 = local_a0;
      do {
        uVar13 = uVar13 - 1;
        uVar25 = *(uint *)(&DAT_00154dc4 + ((ulong)(*pbVar33 ^ uVar25) & 0xff) * 4) ^ uVar25 >> 8;
        pbVar33 = pbVar33 + 1;
      } while (uVar13 != 0);
      uVar25 = ~uVar25;
LAB_00292ac8:
      free(local_a0);
      uVar19 = uVar25;
    }
    *(uint *)(plVar20 + 5) = uVar19;
                    /* try { // try from 00292adc to 00292aef has its CatchHandler @ 00292ca0 */
    (**(code **)(*plVar20 + 0x18))(&local_b0,plVar20,&local_c8,0);
    local_80 = (byte **)0x0;
                    /* try { // try from 00292b0c to 00292b1b has its CatchHandler @ 00292c58 */
    (**(code **)(**(long **)(lVar24 + 0x80) + 0x38))
              (*(long **)(lVar24 + 0x80),param_7,local_b0,local_c8,&local_a0);
    if (local_80 == &local_a0) {
      lVar24 = 4;
      ppbVar16 = &local_a0;
LAB_00292b44:
      (**(code **)(*ppbVar16 + lVar24 * 8))();
    }
    else if (local_80 != (byte **)0x0) {
      lVar24 = 5;
      ppbVar16 = local_80;
      goto LAB_00292b44;
    }
    __ptr = local_b0;
    local_b0 = (byte ***)0x0;
    if (__ptr != (byte ***)0x0) {
      free(__ptr);
    }
    (**(code **)(*plVar20 + 8))(plVar20);
    FUN_00248958(pbVar14);
    free(pbVar14);
    if (plVar26 != (long *)0x0) {
      lVar24 = FUN_0023cb40(0xffffffffffffffff,plVar26 + 1);
      if (lVar24 == 0) {
        (**(code **)(*plVar26 + 0x10))(plVar26);
        FUN_001f9ca4(plVar26);
      }
      plVar26 = (long *)0x0;
    }
  }
  if ((local_108 & 1) != 0) {
    free(local_f8);
  }
  (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
  if (*(long *)(lVar9 + 0x28) == local_70) {
LAB_002923c8:
    return (ulong)plVar26 & 0xffffffff;
  }
LAB_00292e44:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
LAB_002924e4:
  plVar20 = (long *)*plVar20;
  if (plVar20 == (long *)0x0) goto LAB_00292620;
  goto LAB_002924ec;
}
