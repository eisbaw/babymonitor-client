// Ghidra decompilation of imm_p2p_rtc_sdp_encode  (entry=00173ed8)

uint imm_p2p_rtc_sdp_encode(long param_1,char *param_2,long param_3,int param_4)

{
  bool bVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  long *plVar9;
  long *plVar10;
  char *pcVar11;
  char *pcVar12;
  undefined4 uVar13;
  int iVar14;
  long lVar15;
  bool bVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  uint uVar20;
  uint uVar21;
  int iVar22;
  int iVar23;
  time_t tVar24;
  undefined *puVar25;
  long *plVar26;
  long *plVar27;
  long *plVar28;
  undefined8 local_110;
  undefined8 uStack_108;
  undefined8 uStack_100;
  undefined8 uStack_f8;
  undefined8 local_f0;
  undefined8 uStack_e8;
  undefined8 uStack_e0;
  undefined8 uStack_d8;
  undefined8 local_d0;
  undefined8 uStack_c8;
  undefined8 uStack_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  long local_70;
  
  lVar15 = tpidr_el0;
  local_70 = *(long *)(lVar15 + 0x28);
  plVar4 = (long *)(param_1 + 0x3d0);
  iVar19 = 0;
  uStack_c8 = 0;
  local_d0 = 0;
  uStack_b8 = 0;
  uStack_c0 = 0;
  uStack_e8 = 0;
  local_f0 = 0;
  uStack_d8 = 0;
  uStack_e0 = 0;
  plVar26 = plVar4;
  do {
    plVar26 = (long *)*plVar26;
    if (plVar26 == plVar4) {
      tVar24 = time((time_t *)0x0);
      lVar5 = param_1 + 4;
      uVar18 = FUN_001735c0(param_3,0xffffffffffffffff,(long)param_4,
                            "v=0\r\no=- %lu 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE%s\r\na=msid-semantic: WMS %s\r\n"
                            ,tVar24,&local_f0,lVar5);
      uVar21 = uVar18;
      if (param_4 <= (int)uVar18 || 0x7fffffff < uVar18) {
        uVar21 = 0xffffffff;
      }
      uVar20 = 0xffffffff;
      if (((int)uVar21 < 0) || (param_4 <= (int)uVar21)) goto LAB_00174df4;
      param_4 = param_4 - uVar21;
      plVar26 = (long *)(param_1 + 0x688);
      lVar6 = param_1 + 0x1b6;
      lVar7 = param_1 + 0x236;
      lVar8 = param_1 + 0x45;
      plVar9 = (long *)(param_1 + 0x568);
      plVar10 = (long *)(param_1 + 0x488);
      plVar28 = plVar4;
      goto LAB_001740a4;
    }
    iVar17 = FUN_001735c0((long)&local_f0 + (long)iVar19,0xffffffffffffffff,0x40 - (long)iVar19,
                          " %s",plVar26 + 3);
    bVar16 = -1 < iVar17;
    bVar1 = iVar17 < 0x40 - iVar19;
    if (!bVar16 || !bVar1) {
      iVar17 = 0;
    }
    iVar19 = iVar17 + iVar19;
  } while (bVar16 && bVar1);
  uVar20 = 0xffffffff;
  goto LAB_00174df4;
LAB_001740a4:
  do {
    plVar28 = (long *)*plVar28;
    uVar20 = uVar18;
    if (plVar28 == plVar4) goto LAB_00174df4;
    plVar27 = plVar28 + 2;
    iVar19 = strcmp((char *)plVar27,"audio");
    lVar2 = param_3 + (int)uVar18;
    if (iVar19 == 0) {
      uStack_88 = 0;
      local_90 = 0;
      uStack_78 = 0;
      uStack_80 = 0;
      uStack_a8 = 0;
      local_b0 = 0;
      uStack_98 = 0;
      uStack_a0 = 0;
      uStack_c8 = 0;
      local_d0 = 0;
      uStack_b8 = 0;
      uStack_c0 = 0;
      uStack_e8 = 0;
      local_f0 = 0;
      uStack_d8 = 0;
      uStack_e0 = 0;
      iVar19 = strcmp(param_2,"offer");
      if (iVar19 == 0) {
        iVar19 = 0;
        plVar27 = plVar10;
        do {
          plVar27 = (long *)*plVar27;
          if (plVar27 == plVar10) goto LAB_0017427c;
          iVar17 = FUN_001735c0((long)&local_f0 + (long)iVar19,0xffffffffffffffff,
                                0x80 - (long)iVar19," %d",(int)plVar27[6]);
          uVar21 = 0xffffffff;
        } while ((-1 < iVar17) &&
                (iVar23 = 0x80 - iVar19, iVar19 = iVar17 + iVar19, iVar17 < iVar23));
      }
      else {
        uVar21 = FUN_001735c0(&local_f0,0x80,0x80," %d",*(undefined4 *)(param_1 + 0x4c8));
        if (uVar21 < 0x80) {
LAB_0017427c:
          iVar19 = FUN_001735c0(lVar2,0xffffffffffffffff,(long)param_4,"m=%s 9 %s%s\r\n","audio",
                                &DAT_0021aa01,&local_f0);
          uVar21 = 0xffffffff;
          if ((-1 < iVar19) && (iVar17 = param_4 - iVar19, iVar17 != 0 && iVar19 <= param_4)) {
            iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                  "c=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:%s\r\na=ice-pwd:%s\r\na=ice-options:trickle\r\n"
                                  ,lVar6,lVar7);
            uVar21 = 0xffffffff;
            if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
              uStack_108 = 0;
              local_110 = 0;
              uStack_f8 = 0;
              uStack_100 = 0;
              pcVar11 = "passive";
              if (*(int *)(param_1 + 0x430) != 2) {
                pcVar11 = "actpass";
              }
              lVar3 = (long)iVar19 + (long)iVar23;
              pcVar12 = "active";
              if (*(int *)(param_1 + 0x430) != 1) {
                pcVar12 = pcVar11;
              }
              FUN_001735c0(&local_110,0x20,0x20,"%s",pcVar12);
              iVar19 = FUN_001735c0(lVar2 + lVar3,0xffffffffffffffff,(long)iVar22,
                                    "a=fingerprint:%s\r\na=setup:%s\r\n",param_1 + 0xb6,&local_110);
              uVar21 = 0xffffffff;
              if ((-1 < iVar19) && (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)) {
                iVar19 = iVar19 + (int)lVar3;
                iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,"a=mid:%s\r\n",
                                      plVar28 + 3);
                uVar21 = 0xffffffff;
                if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
                  iVar23 = iVar23 + iVar19;
                  puVar25 = &DAT_0023571f;
                  if (*(uint *)(param_1 + 0x480) < 4) {
                    puVar25 = (&PTR_DAT_00257f08)[(int)*(uint *)(param_1 + 0x480)];
                  }
                  iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,"a=%s\r\n",
                                        puVar25);
                  uVar21 = 0xffffffff;
                  if ((-1 < iVar19) && (iVar19 < iVar22)) {
                    iVar23 = iVar19 + iVar23;
                    iVar22 = iVar22 - iVar19;
                    iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                          "a=msid:%s %s\r\n",lVar5,param_1 + 0x438);
                    uVar21 = 0xffffffff;
                    if ((-1 < iVar19) && (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)
                       ) {
                      iVar19 = iVar19 + iVar23;
                      iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                            "a=rtcp-mux\r\n");
                      uVar21 = 0xffffffff;
                      if ((-1 < iVar23) &&
                         (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
                        iVar23 = iVar23 + iVar19;
                        iVar17 = strcmp(param_2,"offer");
                        plVar27 = plVar10;
                        iVar19 = iVar22;
                        if (iVar17 == 0) {
                          do {
                            plVar27 = (long *)*plVar27;
                            if (plVar27 == plVar10) goto LAB_00174b4c;
                            iVar17 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                                  "a=rtpmap:%d %s/%d\r\n",
                                                  *(undefined4 *)(plVar27 + 6),plVar27 + 2,
                                                  *(undefined4 *)(plVar27 + 7));
                            uVar21 = 0xffffffff;
                            if (iVar17 < 0) break;
                            iVar23 = iVar17 + iVar23;
                            bVar1 = iVar17 < iVar19;
                            iVar19 = iVar19 - iVar17;
                          } while (bVar1);
                        }
                        else {
                          iVar17 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                                "a=rtpmap:%d %s/%d\r\n",
                                                *(undefined4 *)(param_1 + 0x4c8),param_1 + 0x4a8,
                                                *(undefined4 *)(param_1 + 0x4d0));
                          uVar21 = 0xffffffff;
                          if ((-1 < iVar17) &&
                             (iVar19 = iVar22 - iVar17, iVar19 != 0 && iVar17 <= iVar22)) {
                            iVar23 = iVar17 + iVar23;
LAB_00174b4c:
                            uVar20 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                                  "a=ssrc:%u cname:%s\r\n",
                                                  *(undefined4 *)(param_1 + 0x4cc),lVar8);
                            uVar21 = uVar20 + iVar23;
                            if (iVar19 <= (int)uVar20 || 0x7fffffff < uVar20) {
                              uVar21 = 0xffffffff;
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        else {
LAB_00174078:
          uVar21 = 0xffffffff;
        }
      }
    }
    else {
      iVar19 = strcmp((char *)plVar27,"video");
      if (iVar19 == 0) {
        uStack_88 = 0;
        local_90 = 0;
        uStack_78 = 0;
        uStack_80 = 0;
        uStack_a8 = 0;
        local_b0 = 0;
        uStack_98 = 0;
        uStack_a0 = 0;
        uStack_c8 = 0;
        local_d0 = 0;
        uStack_b8 = 0;
        uStack_c0 = 0;
        uStack_e8 = 0;
        local_f0 = 0;
        uStack_d8 = 0;
        uStack_e0 = 0;
        iVar19 = strcmp(param_2,"offer");
        if (iVar19 == 0) {
          iVar19 = 0;
          plVar27 = plVar9;
          do {
            plVar27 = (long *)*plVar27;
            if (plVar27 == plVar9) goto LAB_00174520;
            iVar17 = FUN_001735c0((long)&local_f0 + (long)iVar19,0xffffffffffffffff,
                                  0x80 - (long)iVar19," %d",(int)plVar27[6]);
            uVar21 = 0xffffffff;
          } while ((-1 < iVar17) &&
                  (iVar23 = 0x80 - iVar19, iVar19 = iVar17 + iVar19, iVar17 < iVar23));
        }
        else {
          uVar20 = FUN_001735c0(&local_f0,0x80,0x80," %d",*(undefined4 *)(param_1 + 0x5a8));
          if (0x7f < uVar20) goto LAB_00174078;
          if (*(int *)(param_1 + 0x630) != -1) {
            iVar19 = FUN_001735c0((long)&local_f0 + (long)(int)uVar20,0xffffffffffffffff,
                                  0x80 - (long)(int)uVar20," %d");
            uVar21 = 0xffffffff;
            if ((iVar19 < 0) || ((int)(0x80 - uVar20) <= iVar19)) goto LAB_0017407c;
          }
LAB_00174520:
          iVar19 = FUN_001735c0(lVar2,0xffffffffffffffff,(long)param_4,"m=%s 9 %s%s\r\n","video",
                                &DAT_0021aa01,&local_f0);
          uVar21 = 0xffffffff;
          if ((-1 < iVar19) && (iVar17 = param_4 - iVar19, iVar17 != 0 && iVar19 <= param_4)) {
            iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                  "c=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:%s\r\na=ice-pwd:%s\r\na=ice-options:trickle\r\n"
                                  ,lVar6,lVar7);
            uVar21 = 0xffffffff;
            if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
              uStack_108 = 0;
              local_110 = 0;
              uStack_f8 = 0;
              uStack_100 = 0;
              pcVar11 = "passive";
              if (*(int *)(param_1 + 0x430) != 2) {
                pcVar11 = "actpass";
              }
              lVar3 = (long)iVar19 + (long)iVar23;
              pcVar12 = "active";
              if (*(int *)(param_1 + 0x430) != 1) {
                pcVar12 = pcVar11;
              }
              FUN_001735c0(&local_110,0x20,0x20,"%s",pcVar12);
              iVar19 = FUN_001735c0(lVar2 + lVar3,0xffffffffffffffff,(long)iVar22,
                                    "a=fingerprint:%s\r\na=setup:%s\r\n",param_1 + 0xb6,&local_110);
              uVar21 = 0xffffffff;
              if ((-1 < iVar19) && (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)) {
                iVar19 = iVar19 + (int)lVar3;
                iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,"a=mid:%s\r\n",
                                      plVar28 + 3);
                uVar21 = 0xffffffff;
                if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
                  iVar23 = iVar23 + iVar19;
                  puVar25 = &DAT_0023571f;
                  if (*(uint *)(param_1 + 0x560) < 4) {
                    puVar25 = (&PTR_DAT_00257f08)[(int)*(uint *)(param_1 + 0x560)];
                  }
                  iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,"a=%s\r\n",
                                        puVar25);
                  uVar21 = 0xffffffff;
                  if ((-1 < iVar19) && (iVar19 < iVar22)) {
                    iVar23 = iVar19 + iVar23;
                    iVar22 = iVar22 - iVar19;
                    iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                          "a=msid:%s %s\r\n",lVar5,param_1 + 0x518);
                    uVar21 = 0xffffffff;
                    if ((-1 < iVar19) && (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)
                       ) {
                      iVar19 = iVar19 + iVar23;
                      iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                            "a=rtcp-mux\r\n");
                      uVar21 = 0xffffffff;
                      if ((-1 < iVar23) &&
                         (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
                        iVar23 = iVar23 + iVar19;
                        iVar19 = strcmp(param_2,"offer");
                        if (iVar19 == 0) {
                          for (plVar27 = (long *)*plVar9; plVar27 != plVar9;
                              plVar27 = (long *)*plVar27) {
                            iVar19 = strcmp((char *)(plVar27 + 2),"rtx");
                            uVar13 = *(undefined4 *)(plVar27 + 6);
                            lVar3 = lVar2 + iVar23;
                            if (iVar19 == 0) {
                              iVar19 = FUN_001735c0(lVar3,0xffffffffffffffff,(long)iVar22,
                                                    "a=rtpmap:%d rtx/%d\r\na=fmtp:%d apt=%d\r\n",
                                                    uVar13,*(undefined4 *)((long)plVar27 + 0x3c),
                                                    uVar13,*(undefined4 *)((long)plVar27 + 0x34));
                              uVar21 = 0xffffffff;
                              if ((iVar19 < 0) || (iVar22 <= iVar19)) goto LAB_0017407c;
                              iVar23 = iVar19 + iVar23;
                              iVar22 = iVar22 - iVar19;
                            }
                            else {
                              iVar19 = FUN_001735c0(lVar3,0xffffffffffffffff,(long)iVar22,
                                                    "a=rtpmap:%d %s/%d\r\n",uVar13,plVar27 + 2);
                              uVar21 = 0xffffffff;
                              if ((iVar19 < 0) || (iVar22 <= iVar19)) goto LAB_0017407c;
                              lVar3 = (long)iVar23 + (long)iVar19;
                              iVar22 = iVar22 - iVar19;
                              iVar19 = FUN_001735c0(lVar2 + lVar3,0xffffffffffffffff,(long)iVar22,
                                                    "a=rtcp-fb:%d ccm fir\r\n",
                                                    *(undefined4 *)(plVar27 + 6));
                              uVar21 = 0xffffffff;
                              if ((iVar19 < 0) ||
                                 (iVar17 = iVar22 - iVar19, iVar17 == 0 || iVar22 < iVar19))
                              goto LAB_0017407c;
                              iVar19 = iVar19 + (int)lVar3;
                              iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                                    "a=rtcp-fb:%d nack\r\n",
                                                    *(undefined4 *)(plVar27 + 6));
                              uVar21 = 0xffffffff;
                              if ((iVar23 < 0) ||
                                 (iVar22 = iVar17 - iVar23, iVar22 == 0 || iVar17 < iVar23))
                              goto LAB_0017407c;
                              iVar23 = iVar23 + iVar19;
                              iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                                    "a=rtcp-fb:%d nack pli\r\n",
                                                    *(undefined4 *)(plVar27 + 6));
                              uVar21 = 0xffffffff;
                              if ((iVar19 < 0) ||
                                 (iVar17 = iVar22 - iVar19, iVar17 == 0 || iVar22 < iVar19))
                              goto LAB_0017407c;
                              iVar19 = iVar19 + iVar23;
                              iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                                                                                        
                                                  "a=fmtp:%d level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%s\r\n"
                                                  ,*(undefined4 *)(plVar27 + 6),plVar27 + 8);
                              uVar21 = 0xffffffff;
                              if ((iVar23 < 0) ||
                                 (iVar22 = iVar17 - iVar23, iVar22 == 0 || iVar17 < iVar23))
                              goto LAB_0017407c;
                              iVar23 = iVar23 + iVar19;
                            }
                          }
LAB_00174d58:
                          iVar17 = *(int *)(param_1 + 0x55c);
                          iVar19 = iVar22;
LAB_00174d60:
                          uVar13 = *(undefined4 *)(param_1 + 0x5b0);
                          if (iVar17 == 2) {
                            uVar20 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                                  "a=ssrc-group:FID %u %u\r\na=ssrc:%u cname:%s\r\na=ssrc:%u cname:%s\r\n"
                                                  ,uVar13,*(undefined4 *)(param_1 + 0x638),uVar13,
                                                  lVar8,*(undefined4 *)(param_1 + 0x638),lVar8);
                          }
                          else {
                            uVar20 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                                  "a=ssrc:%u cname:%s\r\n",uVar13,lVar8);
                          }
                          uVar21 = 0xffffffff;
                          if ((-1 < (int)uVar20) && (uVar21 = 0xffffffff, (int)uVar20 < iVar19)) {
                            uVar21 = uVar20;
                          }
                        }
                        else {
                          iVar19 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                                "a=rtpmap:%d %s/%d\r\n",
                                                *(undefined4 *)(param_1 + 0x5a8),param_1 + 0x588,
                                                *(undefined4 *)(param_1 + 0x5b4));
                          uVar21 = 0xffffffff;
                          if ((-1 < iVar19) &&
                             (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)) {
                            iVar22 = FUN_001735c0(lVar2 + (iVar19 + iVar23),0xffffffffffffffff,
                                                  (long)iVar17,"a=rtcp-fb:%d ccm fir\r\n",
                                                  *(undefined4 *)(param_1 + 0x5a8));
                            uVar21 = 0xffffffff;
                            if ((-1 < iVar22) &&
                               (iVar14 = iVar17 - iVar22, iVar14 != 0 && iVar22 <= iVar17)) {
                              iVar22 = iVar22 + iVar19 + iVar23;
                              iVar19 = FUN_001735c0(lVar2 + iVar22,0xffffffffffffffff,(long)iVar14,
                                                    "a=rtcp-fb:%d nack\r\n",
                                                    *(undefined4 *)(param_1 + 0x5a8));
                              uVar21 = 0xffffffff;
                              if ((-1 < iVar19) &&
                                 (iVar17 = iVar14 - iVar19, iVar17 != 0 && iVar19 <= iVar14)) {
                                iVar19 = iVar19 + iVar22;
                                iVar22 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17
                                                      ,"a=rtcp-fb:%d nack pli\r\n",
                                                      *(undefined4 *)(param_1 + 0x5a8));
                                uVar21 = 0xffffffff;
                                if ((-1 < iVar22) &&
                                   (iVar14 = iVar17 - iVar22, iVar14 != 0 && iVar22 <= iVar17)) {
                                  iVar22 = iVar22 + iVar19;
                                  iVar23 = FUN_001735c0(lVar2 + iVar22,0xffffffffffffffff,
                                                        (long)iVar14,
                                                                                                                
                                                  "a=fmtp:%d level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=%s\r\n"
                                                  ,*(undefined4 *)(param_1 + 0x5a8),param_1 + 0x5b8)
                                  ;
                                  uVar21 = 0xffffffff;
                                  if ((-1 < iVar23) &&
                                     (iVar19 = iVar14 - iVar23, iVar19 != 0 && iVar23 <= iVar14)) {
                                    iVar23 = iVar23 + iVar22;
                                    iVar17 = *(int *)(param_1 + 0x55c);
                                    if (iVar17 != 2) goto LAB_00174d60;
                                    iVar17 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,
                                                          (long)iVar19,
                                                                                                                    
                                                  "a=rtpmap:%d rtx/%d\r\na=fmtp:%d apt=%d\r\n",
                                                  *(undefined4 *)(param_1 + 0x630),
                                                  *(undefined4 *)(param_1 + 0x63c),
                                                  *(undefined4 *)(param_1 + 0x630),
                                                  *(undefined4 *)(param_1 + 0x5a8));
                                    uVar21 = 0xffffffff;
                                    if ((-1 < iVar17) &&
                                       (iVar22 = iVar19 - iVar17, uVar21 = 0xffffffff,
                                       iVar22 != 0 && iVar17 <= iVar19)) {
                                      iVar23 = iVar17 + iVar23;
                                      goto LAB_00174d58;
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      else {
        iVar19 = strcmp((char *)plVar27,"imm");
        if (iVar19 == 0) {
          uStack_88 = 0;
          local_90 = 0;
          uStack_78 = 0;
          uStack_80 = 0;
          uStack_a8 = 0;
          local_b0 = 0;
          uStack_98 = 0;
          uStack_a0 = 0;
          uStack_c8 = 0;
          local_d0 = 0;
          uStack_b8 = 0;
          uStack_c0 = 0;
          uStack_e8 = 0;
          local_f0 = 0;
          uStack_d8 = 0;
          uStack_e0 = 0;
          iVar19 = strcmp(param_2,"offer");
          if (iVar19 == 0) {
            iVar19 = 0;
            plVar27 = plVar26;
            do {
              plVar27 = (long *)*plVar27;
              if (plVar27 == plVar26) goto LAB_00174908;
              iVar17 = FUN_001735c0((long)&local_f0 + (long)iVar19,0xffffffffffffffff,
                                    0x80 - (long)iVar19," %d",*(undefined4 *)(plVar27 + 6));
              uVar21 = 0xffffffff;
            } while ((-1 < iVar17) &&
                    (iVar23 = 0x80 - iVar19, iVar19 = iVar17 + iVar19, iVar17 < iVar23));
          }
          else {
            uVar21 = FUN_001735c0(&local_f0,0x80,0x80," %d",*(undefined4 *)(param_1 + 0x6c8));
            if (0x7f < uVar21) goto LAB_00174078;
LAB_00174908:
            iVar19 = FUN_001735c0(lVar2,0xffffffffffffffff,(long)param_4,"m=%s 9 %s%s\r\n",
                                  "application",&DAT_00218955,&local_f0);
            uVar21 = 0xffffffff;
            if ((-1 < iVar19) && (iVar17 = param_4 - iVar19, iVar17 != 0 && iVar19 <= param_4)) {
              iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                    "c=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:%s\r\na=ice-pwd:%s\r\na=ice-options:trickle\r\n"
                                    ,lVar6,lVar7);
              uVar21 = 0xffffffff;
              if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17)) {
                lVar3 = (long)iVar19 + (long)iVar23;
                iVar19 = FUN_001735c0(lVar2 + lVar3,0xffffffffffffffff,(long)iVar22,
                                      "a=aes-key:%s\r\n",param_1 + 0x86);
                uVar21 = 0xffffffff;
                if ((-1 < iVar19) && (iVar17 = iVar22 - iVar19, iVar17 != 0 && iVar19 <= iVar22)) {
                  iVar19 = iVar19 + (int)lVar3;
                  iVar23 = FUN_001735c0(lVar2 + iVar19,0xffffffffffffffff,(long)iVar17,
                                        "a=mid:%s\r\n",plVar28 + 3);
                  uVar21 = 0xffffffff;
                  if ((-1 < iVar23) && (iVar22 = iVar17 - iVar23, iVar22 != 0 && iVar23 <= iVar17))
                  {
                    iVar23 = iVar23 + iVar19;
                    iVar17 = strcmp(param_2,"offer");
                    plVar27 = plVar26;
                    iVar19 = iVar22;
                    if (iVar17 == 0) {
                      do {
                        plVar27 = (long *)*plVar27;
                        if (plVar27 == plVar26) goto LAB_00174aa8;
                        iVar17 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                              "a=rtpmap:%d %s %d\r\n",(int)plVar27[6],plVar27 + 2,
                                              *(undefined4 *)((long)plVar27 + 0x34));
                        uVar21 = 0xffffffff;
                        if (iVar17 < 0) break;
                        iVar23 = iVar17 + iVar23;
                        bVar1 = iVar17 < iVar19;
                        uVar21 = 0xffffffff;
                        iVar19 = iVar19 - iVar17;
                      } while (bVar1);
                    }
                    else {
                      iVar17 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar22,
                                            "a=rtpmap:%d %s %d\r\n",*(undefined4 *)(param_1 + 0x6c8)
                                            ,param_1 + 0x6a8,*(undefined4 *)(param_1 + 0x6cc));
                      uVar21 = 0xffffffff;
                      if ((-1 < iVar17) &&
                         (iVar19 = iVar22 - iVar17, iVar19 != 0 && iVar17 <= iVar22)) {
                        iVar23 = iVar17 + iVar23;
LAB_00174aa8:
                        uVar21 = FUN_001735c0(lVar2 + iVar23,0xffffffffffffffff,(long)iVar19,
                                              "a=ssrc:%u cname:%s\r\n",
                                              *(undefined4 *)(param_1 + 0x5b0),lVar8);
                        if (iVar19 <= (int)uVar21 || 0x7fffffff < uVar21) {
                          uVar21 = 0xffffffff;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        else {
          uVar21 = 0;
        }
      }
    }
LAB_0017407c:
    bVar16 = (int)uVar21 < 0;
    bVar1 = param_4 <= (int)uVar21;
    if (bVar16 || bVar1) {
      uVar21 = 0;
    }
    uVar18 = uVar21 + uVar18;
    param_4 = param_4 - uVar21;
  } while (!bVar16 && !bVar1);
  uVar20 = 0xffffffff;
LAB_00174df4:
  if (*(long *)(lVar15 + 0x28) == local_70) {
    return uVar20;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

