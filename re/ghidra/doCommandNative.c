// Ghidra decompilation of doCommandNative  (entry=00113ed8)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void * FUN_00113ed8(long *param_1,undefined8 param_2,undefined8 param_3,int param_4,
                   undefined8 param_5,undefined8 param_6,char param_7)

{
  ulong uVar1;
  long *plVar2;
  undefined *puVar3;
  undefined1 *puVar4;
  byte bVar5;
  byte bVar6;
  long lVar7;
  ulong uVar8;
  bool bVar9;
  int iVar10;
  uint uVar11;
  ulong uVar12;
  long *plVar13;
  long lVar14;
  void *pvVar15;
  void *pvVar16;
  void *__dest;
  size_t sVar17;
  void *pvVar18;
  byte *pbVar19;
  undefined8 uVar20;
  undefined8 uVar21;
  ulong *puVar22;
  ulong *puVar23;
  char *pcVar24;
  long lVar25;
  int iVar26;
  ulong *puVar27;
  int iVar28;
  ulong local_1c0;
  ulong uStack_1b8;
  void *local_1b0;
  ulong local_1a0;
  ulong uStack_198;
  void *local_190;
  ulong local_180;
  ulong uStack_178;
  undefined *local_170;
  ulong *local_160;
  ulong *puStack_158;
  ulong *local_150;
  ulong *local_140;
  ulong *puStack_138;
  ulong *local_130;
  long *local_128;
  long *local_120;
  void *local_118;
  ulong *local_110;
  ulong *puStack_108;
  ulong *local_100;
  int local_f4;
  ulong local_f0;
  ulong uStack_e8;
  undefined *local_e0;
  undefined8 uStack_d8;
  undefined8 local_d0;
  undefined8 uStack_c8;
  undefined8 uStack_c0;
  undefined8 uStack_b8;
  ulong local_b0;
  ulong uStack_a8;
  void *local_a0;
  undefined6 local_88;
  undefined2 uStack_82;
  undefined6 uStack_80;
  long local_78;
  
  lVar7 = tpidr_el0;
  local_78 = *(long *)(lVar7 + 0x28);
  uVar12 = FUN_00129de0(1,&DAT_001390b8);
  if ((uVar12 & 1) == 0) {
    local_110 = (ulong *)0x0;
    puStack_108 = (ulong *)0x0;
    local_100 = (ulong *)0x0;
                    /* try { // try from 00113f3c to 00113f43 has its CatchHandler @ 00115180 */
    plVar13 = (long *)operator_new(0xa0);
    plVar2 = plVar13 + 3;
    plVar13[1] = 0;
    plVar13[2] = 0;
    *plVar13 = (long)&PTR_FUN_00132f48;
                    /* try { // try from 00113f68 to 00113f77 has its CatchHandler @ 0011516c */
    FUN_001199ac(plVar2,param_1,param_3,param_7 != '\0');
    local_f0 = 0;
    uStack_e8 = 0;
    local_e0 = (undefined *)0x0;
                    /* try { // try from 00113f84 to 00113f8f has its CatchHandler @ 00115188 */
    local_128 = plVar2;
    local_120 = plVar13;
    iVar10 = FUN_0011a030(plVar2,&local_f0);
    if (iVar10 == 0) {
      uVar12 = local_f0 >> 1 & 0x7f;
      if ((local_f0 & 1) != 0) {
        uVar12 = uStack_e8;
      }
      if (uVar12 == 0) {
        lVar25 = 0;
        iVar26 = -5;
      }
      else {
        puVar3 = (undefined *)((ulong)&local_f0 | 1);
        if ((local_f0 & 1) != 0) {
          puVar3 = local_e0;
        }
                    /* try { // try from 0011410c to 0011410f has its CatchHandler @ 00115188 */
        lVar25 = FUN_001126d8(puVar3);
        if (lVar25 == 0) {
          iVar26 = -1;
        }
        else {
                    /* try { // try from 00114118 to 0011412b has its CatchHandler @ 00115018 */
          FUN_00112760(lVar25,"securityOpen");
          iVar10 = FUN_00112814();
          if (iVar10 == 0) {
            iVar26 = 2;
          }
          else {
                    /* try { // try from 0011413c to 0011414b has its CatchHandler @ 00114f50 */
            uVar20 = FUN_00112760(lVar25,&DAT_00108f3e);
                    /* try { // try from 0011414c to 00114153 has its CatchHandler @ 00114f4c */
            iVar10 = FUN_00112714();
            if (iVar10 < 1) {
              iVar26 = 1;
            }
            else {
              iVar28 = 0;
              do {
                    /* try { // try from 00114180 to 0011418b has its CatchHandler @ 00115164 */
                FUN_00112730(uVar20,iVar28);
                    /* try { // try from 0011418c to 0011418f has its CatchHandler @ 00115168 */
                pcVar24 = (char *)FUN_00111fc0();
                iVar26 = 1;
                if (pcVar24 == (char *)0x0) break;
                sVar17 = strlen(pcVar24);
                if (0xffffffffffffffef < sVar17) {
                  if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* try { // try from 00114e6c to 00114e73 has its CatchHandler @ 00115120 */
                    /* WARNING: Subroutine does not return */
                    FUN_001171f4(&local_b0);
                  }
                  goto LAB_001151f4;
                }
                if (sVar17 < 0x17) {
                  local_b0 = CONCAT71(local_b0._1_7_,(char)((int)sVar17 << 1));
                  pvVar15 = (void *)((ulong)&local_b0 | 1);
                  if (sVar17 != 0) goto LAB_00114220;
                }
                else {
                  uVar12 = (sVar17 | 0xf) + 1;
                    /* try { // try from 001141ec to 001141f3 has its CatchHandler @ 001150bc */
                  pvVar15 = operator_new(uVar12);
                  local_b0 = uVar12 | 1;
                  uStack_a8 = sVar17;
                  local_a0 = pvVar15;
LAB_00114220:
                  memmove(pvVar15,pcVar24,sVar17);
                }
                puVar22 = puStack_108;
                *(undefined1 *)((long)pvVar15 + sVar17) = 0;
                if (puStack_108 < local_100) {
                  if ((local_b0 & 1) == 0) {
                    puVar22 = puStack_108 + 3;
                    puStack_108[2] = (ulong)local_a0;
                    puStack_108[1] = uStack_a8;
                    *puStack_108 = local_b0;
                  }
                  else {
                    /* try { // try from 0011427c to 00114283 has its CatchHandler @ 00114fd0 */
                    FUN_001172b0(puStack_108,local_a0,uStack_a8);
                    puVar22 = puVar22 + 3;
                  }
                }
                else {
                    /* try { // try from 00114264 to 0011426f has its CatchHandler @ 001150c0 */
                  puVar22 = (ulong *)FUN_00116c58(&local_110,&local_b0);
                }
                puStack_108 = puVar22;
                if ((local_b0 & 1) != 0) {
                  operator_delete(local_a0);
                }
                iVar28 = iVar28 + 1;
              } while (iVar10 != iVar28);
            }
          }
        }
      }
    }
    else {
      lVar25 = 0;
      iVar26 = 2;
      if (iVar10 != -2) {
        iVar26 = iVar10;
      }
    }
    if ((local_f0 & 1) != 0) {
      operator_delete(local_e0);
    }
    plVar2 = local_120;
    if ((local_120 != (long *)0x0) &&
       (lVar14 = FUN_0012a4d0(0xffffffffffffffff,local_120 + 1), lVar14 == 0)) {
      (**(code **)(*plVar2 + 0x10))(plVar2);
      std::__ndk1::__shared_weak_count::__release_weak();
    }
    if (lVar25 != 0) {
                    /* try { // try from 00113fd0 to 00113fd7 has its CatchHandler @ 00115118 */
      FUN_00111fe0(lVar25);
    }
    if (iVar26 == 2) {
      bVar9 = true;
    }
    else {
                    /* try { // try from 00113fe8 to 00113ff7 has its CatchHandler @ 00115108 */
      FUN_00116528(&local_f0,param_1,param_3);
      uVar12 = local_f0 >> 1 & 0x7f;
      if ((local_f0 & 1) != 0) {
        uVar12 = uStack_e8;
      }
      if (uVar12 != 0) {
        std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
        ::operator=((basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                     *)&DAT_00139088,(basic_string *)&local_f0);
      }
      puVar22 = puStack_108;
      if (local_110 == puStack_108) {
        bVar9 = false;
      }
      else {
        puVar23 = local_110;
        do {
          puVar27 = puVar23 + 3;
          if ((*puVar23 & 1) == 0) {
            local_a0 = (void *)puVar23[2];
            uStack_a8 = puVar23[1];
            local_b0 = *puVar23;
          }
          else {
                    /* try { // try from 0011407c to 00114083 has its CatchHandler @ 001151a8 */
            FUN_001172b0(&local_b0,puVar23[2],puVar23[1]);
          }
          pvVar16 = local_a0;
          uVar1 = local_b0;
          uVar12 = local_b0 >> 1 & 0x7f;
          pvVar15 = (void *)((ulong)&local_b0 | 1);
          if ((local_b0 & 1) != 0) {
            uVar12 = uStack_a8;
            pvVar15 = local_a0;
          }
          puVar3 = (undefined *)((ulong)&local_f0 | 1);
          uVar8 = local_f0 >> 1 & 0x7f;
          if ((local_f0 & 1) != 0) {
            puVar3 = local_e0;
            uVar8 = uStack_e8;
          }
          sVar17 = uVar12;
          if (uVar8 <= uVar12) {
            sVar17 = uVar8;
          }
          iVar10 = memcmp(puVar3,pvVar15,sVar17);
          bVar9 = uVar12 == uVar8 && iVar10 == 0;
          if ((uVar1 & 1) != 0) {
            operator_delete(pvVar16);
          }
          puVar23 = puVar27;
        } while (puVar27 != puVar22 && (uVar12 != uVar8 || iVar10 != 0));
      }
      if ((local_f0 & 1) != 0) {
        operator_delete(local_e0);
      }
    }
    puVar22 = local_110;
    puVar23 = puStack_108;
    if (local_110 != (ulong *)0x0) {
      while (puVar27 = puVar23, puVar27 != puVar22) {
        puVar23 = puVar27 + -3;
        if ((*puVar23 & 1) != 0) {
          operator_delete((void *)puVar27[-1]);
        }
      }
      puStack_108 = puVar22;
      operator_delete(local_110);
    }
    if (iVar26 == 1) {
      if (!bVar9) {
LAB_00114344:
        lVar25 = (**(code **)(*param_1 + 0x30))
                           (param_1,"com/thingclips/smart/security/jni/JNICLibrary");
        if ((lVar25 != 0) &&
           (lVar14 = (**(code **)(*param_1 + 0x388))(param_1,lVar25,"checkStatus",&DAT_00108c97),
           lVar14 != 0)) {
          FUN_00116f70(param_1,lVar25,lVar14,0xffffffff);
        }
        pthread_create((pthread_t *)&DAT_001390c0,(pthread_attr_t *)0x0,FUN_00113d34,(void *)0x0);
      }
      bVar9 = (bool)(bVar9 ^ 1);
      if (iVar26 != 1) {
        bVar9 = true;
      }
      if (((!bVar9) &&
          (lVar25 = (**(code **)(*param_1 + 0x30))
                              (param_1,"com/thingclips/smart/security/jni/JNICLibrary"), lVar25 != 0
          )) && (lVar14 = (**(code **)(*param_1 + 0x388))
                                    (param_1,lVar25,"checkStatus",&DAT_00108c97), lVar14 != 0)) {
        FUN_00116f70(param_1,lVar25,lVar14,0);
      }
    }
    else if (iVar26 < 0) goto LAB_00114344;
  }
  if (param_4 == 2) {
    local_f0 = 0;
    uStack_e8 = 0;
    local_e0 = (undefined *)0x0;
                    /* try { // try from 00114510 to 00114523 has its CatchHandler @ 00115110 */
    pvVar15 = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_5,0);
    if (pvVar15 == (void *)0x0) goto LAB_00114dfc;
                    /* try { // try from 00114534 to 0011453f has its CatchHandler @ 00115078 */
    uVar11 = (**(code **)(*param_1 + 0x558))(param_1,param_5);
    if (0xffffffef < uVar11) {
      if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* try { // try from 00114ea4 to 00114eab has its CatchHandler @ 001150f4 */
                    /* WARNING: Subroutine does not return */
        FUN_001171f4(&local_b0);
      }
      goto LAB_001151f4;
    }
    uVar12 = (ulong)(int)uVar11;
    if (uVar11 < 0x17) {
      pvVar16 = (void *)((ulong)&local_b0 | 1);
      local_b0 = CONCAT71(local_b0._1_7_,(char)(uVar11 << 1));
      if (uVar11 != 0) goto LAB_0011480c;
    }
    else {
      uVar1 = (uVar12 | 0xf) + 1;
                    /* try { // try from 001147f4 to 001147fb has its CatchHandler @ 001150f4 */
      pvVar16 = operator_new(uVar1);
      local_b0 = uVar1 | 1;
      uStack_a8 = uVar12;
      local_a0 = pvVar16;
LAB_0011480c:
      memmove(pvVar16,pvVar15,uVar12);
    }
    uVar1 = local_b0;
    *(undefined1 *)((long)pvVar16 + uVar12) = 0;
    if ((local_b0 & 1) == 0) {
      uStack_1b8 = uStack_a8;
      local_1c0 = local_b0;
      local_1b0 = local_a0;
    }
    else {
                    /* try { // try from 00114844 to 0011484b has its CatchHandler @ 00114fbc */
      FUN_001172b0(&local_1c0,local_a0,uStack_a8);
    }
                    /* try { // try from 00114850 to 0011485b has its CatchHandler @ 00115038 */
    FUN_00113474(&local_1c0,&local_f0);
    if ((local_1c0 & 1) != 0) {
      operator_delete(local_1b0);
    }
    puVar3 = (undefined *)((ulong)&local_f0 | 1);
    if ((local_f0 & 1) != 0) {
      puVar3 = local_e0;
    }
                    /* try { // try from 0011488c to 00114893 has its CatchHandler @ 0011501c */
    pvVar15 = (void *)(**(code **)(*param_1 + 0x538))(param_1,puVar3);
    if ((uVar1 & 1) != 0) {
      operator_delete(local_a0);
    }
    if ((local_f0 & 1) != 0) {
      operator_delete(local_e0);
    }
  }
  else if (param_4 == 1) {
    pvVar16 = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_5,0);
    pvVar15 = pvVar16;
    if (pvVar16 != (void *)0x0) {
      uVar11 = (**(code **)(*param_1 + 0x558))(param_1,param_5);
      if (0xffffffef < uVar11) {
LAB_00114e74:
        if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* WARNING: Subroutine does not return */
          FUN_001171f4(&local_110);
        }
        goto LAB_001151f4;
      }
      puVar22 = (ulong *)(long)(int)uVar11;
      if (uVar11 < 0x17) {
        puVar23 = (ulong *)((ulong)&local_110 | 1);
        local_110 = (ulong *)CONCAT71(local_110._1_7_,(char)(uVar11 << 1));
        if (uVar11 != 0) goto LAB_00114588;
      }
      else {
        puVar23 = (ulong *)operator_new(((ulong)puVar22 | 0xf) + 1);
        local_110 = (ulong *)(((ulong)puVar22 | 0xf) + 2);
        puStack_108 = puVar22;
        local_100 = puVar23;
LAB_00114588:
        memmove(puVar23,pvVar16,(size_t)puVar22);
      }
      puVar27 = local_110;
      *(byte *)((long)puVar23 + (long)puVar22) = 0;
      if (DAT_00139040 == DAT_00139048) {
        pvVar15 = (void *)0x0;
      }
      else {
        if (((ulong)local_110 & 1) == 0) {
          puStack_158 = puStack_108;
          local_160 = local_110;
          local_150 = local_100;
        }
        else {
                    /* try { // try from 001148e4 to 001148eb has its CatchHandler @ 00114f64 */
          FUN_001172b0(&local_160,local_100,puStack_108);
        }
        if ((_DAT_00139058 & 1) == 0) {
          uStack_178 = DAT_00139060;
          local_180 = _DAT_00139058;
          local_170 = DAT_00139068;
        }
        else {
                    /* try { // try from 00114920 to 00114927 has its CatchHandler @ 00114f54 */
          FUN_001172b0(&local_180,DAT_00139068,DAT_00139060);
        }
        if (DAT_00139048 == DAT_00139040) {
          if (*(long *)(lVar7 + 0x28) != local_78) goto LAB_001151f4;
          FUN_00117208(&DAT_00139040);
LAB_00114ecc:
          if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* try { // try from 00114ee0 to 00114ee7 has its CatchHandler @ 00114f6c */
                    /* WARNING: Subroutine does not return */
            FUN_001171f4(&local_140);
          }
          goto LAB_001151f4;
        }
        if ((*DAT_00139040 & 1) == 0) {
          local_190 = (void *)DAT_00139040[2];
          uStack_198 = DAT_00139040[1];
          local_1a0 = *DAT_00139040;
        }
        else {
                    /* try { // try from 00114954 to 0011495b has its CatchHandler @ 00114ff8 */
          FUN_001172b0(&local_1a0,DAT_00139040[2],DAT_00139040[1]);
        }
                    /* try { // try from 0011495c to 001149ab has its CatchHandler @ 0011507c */
        uVar20 = FUN_0011775c(6);
        uVar12 = CONCAT62(uRam000000000013907a,DAT_00139072._6_2_);
        puVar4 = DAT_00139080;
        if ((DAT_00139070 & 1) == 0) {
          uVar12 = (ulong)(DAT_00139070 >> 1);
          puVar4 = &DAT_00139071;
        }
        puVar22 = (ulong *)((ulong)local_160 >> 1 & 0x7f);
        puVar23 = (ulong *)((ulong)&local_160 | 1);
        if (((ulong)local_160 & 1) != 0) {
          puVar22 = puStack_158;
          puVar23 = local_150;
        }
        FUN_001179f8(uVar20,puVar4,uVar12,puVar23,puVar22,&local_b0);
        if ((local_1a0 & 1) != 0) {
          operator_delete(local_190);
        }
        if ((local_180 & 1) != 0) {
          operator_delete(local_170);
        }
        if (((ulong)local_160 & 1) != 0) {
          operator_delete(local_150);
        }
        lVar25 = 0;
        uStack_e8 = 0;
        local_f0 = 0;
        uStack_d8 = 0;
        local_e0 = (undefined *)0x0;
        uStack_c8 = 0;
        local_d0 = 0;
        uStack_b8 = 0;
        uStack_c0 = 0;
        puVar22 = &local_b0;
        do {
                    /* try { // try from 001149f0 to 001149ff has its CatchHandler @ 001151c8 */
          FUN_00116ae4((long)&local_f0 + lVar25,0xffffffffffffffff,&DAT_001090ea,(char)*puVar22);
          lVar25 = lVar25 + 2;
          puVar22 = (ulong *)((long)puVar22 + 1);
        } while (lVar25 != 0x40);
                    /* try { // try from 00114a18 to 00114a1f has its CatchHandler @ 00114fc4 */
        pvVar15 = (void *)(**(code **)(*param_1 + 0x538))(param_1,&local_f0);
      }
      if (((ulong)puVar27 & 1) != 0) {
        operator_delete(local_100);
      }
      (**(code **)(*param_1 + 0x600))(param_1,param_5,pvVar16,1);
    }
  }
  else {
    if (param_4 != 0) goto LAB_00114dfc;
    pvVar15 = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_5,0);
    if (pvVar15 == (void *)0x0) goto LAB_00114e00;
    uVar11 = (**(code **)(*param_1 + 0x558))(param_1,param_5);
    if (0xffffffef < uVar11) goto LAB_00114e74;
    puVar22 = (ulong *)(long)(int)uVar11;
    if (uVar11 < 0x17) {
      puVar23 = (ulong *)((ulong)&local_110 | 1);
      local_110 = (ulong *)CONCAT71(local_110._1_7_,(char)(uVar11 << 1));
      if (uVar11 != 0) goto LAB_001145e8;
    }
    else {
      puVar23 = (ulong *)operator_new(((ulong)puVar22 | 0xf) + 1);
      local_110 = (ulong *)(((ulong)puVar22 | 0xf) + 2);
      puStack_108 = puVar22;
      local_100 = puVar23;
LAB_001145e8:
      memmove(puVar23,pvVar15,(size_t)puVar22);
    }
    *(byte *)((long)puVar23 + (long)puVar22) = 0;
                    /* try { // try from 00114604 to 00114613 has its CatchHandler @ 00115068 */
    pvVar16 = (void *)(**(code **)(*param_1 + 0x5c0))(param_1,param_6,0);
    if (pvVar16 != (void *)0x0) {
                    /* try { // try from 00114624 to 0011462f has its CatchHandler @ 00114fcc */
      iVar10 = (**(code **)(*param_1 + 0x558))(param_1,param_6);
      __dest = calloc((long)(iVar10 + 1),1);
      memcpy(__dest,pvVar16,(long)iVar10);
                    /* try { // try from 00114660 to 0011466f has its CatchHandler @ 00114fc8 */
      FUN_00113b5c(&local_128,param_1,param_3,param_7 != '\0');
      plVar2 = (long *)(ulong)((byte)local_128 >> 1);
      if (((ulong)local_128 & 1) != 0) {
        plVar2 = local_120;
      }
      if (plVar2 != (long *)0x0) {
        puStack_138 = (ulong *)0x0;
        local_130 = (ulong *)0x0;
        local_140 = (ulong *)0x0;
        pvVar18 = (void *)((ulong)&local_128 | 1);
        if (((ulong)local_128 & 1) != 0) {
          pvVar18 = local_118;
        }
                    /* try { // try from 001146a4 to 001146b3 has its CatchHandler @ 00114f70 */
        iVar10 = read_keys_from_content(__dest,&local_88,&local_f4,pvVar18);
        if (iVar10 == 0) {
          if (0 < local_f4) {
            lVar25 = 0;
            do {
              pcVar24 = *(char **)(CONCAT26(uStack_82,local_88) + lVar25 * 8);
              sVar17 = strlen(pcVar24);
              if (0xffffffffffffffef < sVar17) {
                if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* try { // try from 00114e50 to 00114e57 has its CatchHandler @ 00115124 */
                    /* WARNING: Subroutine does not return */
                  FUN_001171f4(&local_b0);
                }
                goto LAB_001151f4;
              }
              if (sVar17 < 0x17) {
                local_b0 = CONCAT71(local_b0._1_7_,(char)((int)sVar17 << 1));
                pvVar18 = (void *)((ulong)&local_b0 | 1);
                if (sVar17 != 0) goto LAB_00114748;
              }
              else {
                uVar12 = (sVar17 | 0xf) + 1;
                    /* try { // try from 0011472c to 00114733 has its CatchHandler @ 001150ec */
                pvVar18 = operator_new(uVar12);
                local_b0 = uVar12 | 1;
                uStack_a8 = sVar17;
                local_a0 = pvVar18;
LAB_00114748:
                memmove(pvVar18,pcVar24,sVar17);
              }
              *(undefined1 *)((long)pvVar18 + sVar17) = 0;
                    /* try { // try from 0011475c to 00114767 has its CatchHandler @ 0011512c */
              FUN_00113150(&local_f0,&local_b0);
              if ((local_b0 & 1) != 0) {
                operator_delete(local_a0);
              }
              puVar22 = puStack_138;
              if (puStack_138 < local_130) {
                if ((local_f0 & 1) == 0) {
                  puVar22 = puStack_138 + 3;
                  puStack_138[2] = (ulong)local_e0;
                  puStack_138[1] = uStack_e8;
                  *puStack_138 = local_f0;
                }
                else {
                    /* try { // try from 001147bc to 001147c3 has its CatchHandler @ 00114fdc */
                  FUN_001172b0(puStack_138,local_e0,uStack_e8);
                  puVar22 = puVar22 + 3;
                }
              }
              else {
                    /* try { // try from 001147a8 to 001147b3 has its CatchHandler @ 001150d8 */
                puVar22 = (ulong *)FUN_00116c58(&local_140,&local_f0);
              }
              puStack_138 = puVar22;
              free(*(void **)(CONCAT26(uStack_82,local_88) + lVar25 * 8));
              if ((local_f0 & 1) != 0) {
                operator_delete(local_e0);
              }
              lVar25 = lVar25 + 1;
            } while (lVar25 < local_f4);
          }
          free((void *)CONCAT26(uStack_82,local_88));
        }
        puVar22 = DAT_00139040;
        puVar23 = DAT_00139048;
        if (DAT_00139040 != (ulong *)0x0) {
          while (puVar27 = puVar23, puVar27 != puVar22) {
            puVar23 = puVar27 + -3;
            if ((*puVar23 & 1) != 0) {
              operator_delete((void *)puVar27[-1]);
            }
          }
          DAT_00139048 = puVar22;
          operator_delete(DAT_00139040);
        }
        DAT_00139048 = puStack_138;
        DAT_00139040 = local_140;
        DAT_00139050 = local_130;
        uVar12 = (ulong)(DAT_00139088 >> 1);
        if ((DAT_00139088 & 1) != 0) {
          uVar12 = DAT_00139090;
        }
        if (uVar12 == 0) {
                    /* try { // try from 00114b50 to 00114b5f has its CatchHandler @ 00114f08 */
          FUN_00116528(&local_f0,param_1,param_3);
          if ((_DAT_00139058 & 1) != 0) {
            operator_delete(DAT_00139068);
          }
          DAT_00139060 = uStack_e8;
          _DAT_00139058 = local_f0;
          DAT_00139068 = local_e0;
        }
        else {
          std::__ndk1::
          basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::operator=
                    ((basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                      *)&DAT_00139058,(basic_string *)&DAT_00139088);
        }
        bVar5 = DAT_001390a0;
        if (DAT_00139040 != DAT_00139048) {
          sVar17 = (ulong)(DAT_001390a0 >> 1);
          if ((DAT_001390a0 & 1) != 0) {
            sVar17 = DAT_001390a8;
          }
          puVar22 = (ulong *)(sVar17 + 1);
          if ((ulong *)0xffffffffffffffef < puVar22) goto LAB_00114ecc;
          if (puVar22 < (ulong *)0x17) {
            puStack_138 = (ulong *)0x0;
            puVar23 = (ulong *)((ulong)&local_140 | 1);
            local_130 = (ulong *)0x0;
            local_140 = (ulong *)(ulong)(byte)((int)puVar22 << 1);
            if (sVar17 != 0) goto LAB_00114c08;
          }
          else {
            uVar12 = ((ulong)puVar22 | 0xf) + 1;
                    /* try { // try from 00114bf0 to 00114bf7 has its CatchHandler @ 00114f6c */
            puVar23 = (ulong *)operator_new(uVar12);
            local_140 = (ulong *)(uVar12 | 1);
            puStack_138 = puVar22;
            local_130 = puVar23;
LAB_00114c08:
            puVar3 = &DAT_001390a1;
            if ((bVar5 & 1) != 0) {
              puVar3 = DAT_001390b0;
            }
            memmove(puVar23,puVar3,sVar17);
          }
          puVar3 = DAT_00139068;
          uVar12 = _DAT_00139058;
          ((byte *)((long)puVar23 + sVar17))[0] = 0x5f;
          ((byte *)((long)puVar23 + sVar17))[1] = 0;
          if ((uVar12 & 1) == 0) {
            puVar3 = &DAT_00139059;
          }
                    /* try { // try from 00114c48 to 00114c4f has its CatchHandler @ 00114f3c */
          puVar22 = (ulong *)std::__ndk1::
                             basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                             ::append((char *)&local_140,(ulong)puVar3);
          local_a0 = (void *)puVar22[2];
          uStack_a8 = puVar22[1];
          local_b0 = *puVar22;
          puVar22[1] = 0;
          puVar22[2] = 0;
          *puVar22 = 0;
                    /* try { // try from 00114c6c to 00114c7b has its CatchHandler @ 00114f0c */
          puVar22 = (ulong *)std::__ndk1::
                             basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                             ::append((char *)&local_b0);
          local_e0 = (undefined *)puVar22[2];
          uStack_e8 = puVar22[1];
          local_f0 = *puVar22;
          puVar22[1] = 0;
          puVar22[2] = 0;
          *puVar22 = 0;
          if (DAT_00139048 == DAT_00139040) {
            if (*(long *)(lVar7 + 0x28) == local_78) {
              uVar20 = FUN_00117208(&DAT_00139040);
                    /* catch() { ... } // from try @ 00114b38 with catch @ 00114fe8
                       catch() { ... } // from try @ 00114d54 with catch @ 00114fe8 */
                    /* catch() { ... } // from try @ 00114b50 with catch @ 00114f08 */
              if (((ulong)local_128 & 1) != 0) {
                operator_delete(local_118);
              }
              if (((ulong)local_110 & 1) != 0) {
                operator_delete(local_100);
              }
              if (*(long *)(lVar7 + 0x28) == local_78) {
                    /* WARNING: Subroutine does not return */
                FUN_0012a634(uVar20);
              }
            }
            goto LAB_001151f4;
          }
          pbVar19 = (byte *)DAT_00139040[2];
          if ((*DAT_00139040 & 1) == 0) {
            pbVar19 = (byte *)((long)DAT_00139040 + 1);
          }
                    /* try { // try from 00114cbc to 00114cc3 has its CatchHandler @ 00114f78 */
          pbVar19 = (byte *)std::__ndk1::
                            basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                            ::append((char *)&local_f0,(ulong)pbVar19);
          bVar5 = *pbVar19;
          uVar20 = *(undefined8 *)(pbVar19 + 8);
          puVar4 = *(undefined1 **)(pbVar19 + 0x10);
          bVar6 = pbVar19[1];
          uVar21 = *(undefined8 *)(pbVar19 + 2);
          pbVar19[8] = 0;
          pbVar19[9] = 0;
          pbVar19[10] = 0;
          pbVar19[0xb] = 0;
          pbVar19[0xc] = 0;
          pbVar19[0xd] = 0;
          pbVar19[0xe] = 0;
          pbVar19[0xf] = 0;
          pbVar19[0x10] = 0;
          pbVar19[0x11] = 0;
          pbVar19[0x12] = 0;
          pbVar19[0x13] = 0;
          pbVar19[0x14] = 0;
          pbVar19[0x15] = 0;
          pbVar19[0x16] = 0;
          pbVar19[0x17] = 0;
          pbVar19[0] = 0;
          pbVar19[1] = 0;
          pbVar19[2] = 0;
          pbVar19[3] = 0;
          pbVar19[4] = 0;
          pbVar19[5] = 0;
          pbVar19[6] = 0;
          pbVar19[7] = 0;
          local_88 = (undefined6)uVar21;
          uStack_82 = (undefined2)uVar20;
          uStack_80 = (undefined6)((ulong)uVar20 >> 0x10);
          if ((DAT_00139070 & 1) != 0) {
            operator_delete(DAT_00139080);
          }
          DAT_00139072._0_6_ = local_88;
          DAT_00139072._6_2_ = uStack_82;
          uRam000000000013907a = uStack_80;
          DAT_00139070 = bVar5;
          DAT_00139071 = bVar6;
          DAT_00139080 = puVar4;
          if ((local_f0 & 1) != 0) {
            operator_delete(local_e0);
          }
          if ((local_b0 & 1) != 0) {
            operator_delete(local_a0);
          }
          if (((ulong)local_140 & 1) != 0) {
            operator_delete(local_130);
          }
          std::__ndk1::
          basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::append
                    ((char *)&DAT_00139070);
          puVar22 = (ulong *)((ulong)&local_110 | 1);
          if (((ulong)local_110 & 1) != 0) {
            puVar22 = local_100;
          }
          std::__ndk1::
          basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::append
                    ((char *)&DAT_00139070,(ulong)puVar22);
        }
        free(__dest);
      }
      if (((byte)local_128 & 1) != 0) {
        operator_delete(local_118);
      }
    }
    if (((ulong)local_110 & 1) != 0) {
      operator_delete(local_100);
    }
    (**(code **)(*param_1 + 0x600))(param_1,param_5,pvVar15,1);
    if (pvVar16 != (void *)0x0) {
      (**(code **)(*param_1 + 0x600))(param_1,param_6,pvVar16,1);
    }
LAB_00114dfc:
    pvVar15 = (void *)0x0;
  }
LAB_00114e00:
  if (*(long *)(lVar7 + 0x28) == local_78) {
    return pvVar15;
  }
LAB_001151f4:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

