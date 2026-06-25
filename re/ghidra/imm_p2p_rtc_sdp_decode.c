// Ghidra decompilation of imm_p2p_rtc_sdp_decode  (entry=00174e2c)

undefined8 imm_p2p_rtc_sdp_decode(long param_1,char *param_2)

{
  long *plVar1;
  long *plVar2;
  long *plVar3;
  long lVar4;
  undefined *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  size_t sVar10;
  char *pcVar11;
  char *pcVar12;
  char *pcVar13;
  ulong uVar14;
  long lVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  char **ppcVar18;
  long *plVar19;
  undefined8 *puVar20;
  long *plVar21;
  char *local_228;
  undefined8 local_220;
  undefined8 uStack_218;
  undefined8 uStack_210;
  undefined8 uStack_208;
  undefined8 local_200;
  undefined8 uStack_1f8;
  undefined8 uStack_1f0;
  undefined8 uStack_1e8;
  ulong local_1e0;
  undefined8 uStack_1d8;
  undefined8 uStack_1d0;
  undefined8 uStack_1c8;
  undefined8 local_1c0;
  undefined8 uStack_1b8;
  undefined8 uStack_1b0;
  undefined8 uStack_1a8;
  undefined8 local_1a0;
  undefined8 uStack_198;
  undefined8 uStack_190;
  undefined8 uStack_188;
  undefined8 local_180;
  undefined8 uStack_178;
  undefined8 uStack_170;
  undefined8 uStack_168;
  undefined8 local_160;
  undefined8 uStack_158;
  undefined8 uStack_150;
  undefined8 uStack_148;
  undefined8 local_140;
  undefined8 uStack_138;
  undefined8 uStack_130;
  undefined8 uStack_128;
  undefined8 local_120;
  undefined8 uStack_118;
  undefined8 uStack_110;
  undefined8 uStack_108;
  undefined8 local_100;
  undefined8 uStack_f8;
  undefined8 uStack_f0;
  undefined8 uStack_e8;
  undefined1 local_e0;
  char *local_d0;
  undefined8 uStack_c8;
  undefined8 uStack_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined1 local_90;
  long local_88;
  
  lVar4 = tpidr_el0;
  local_88 = *(long *)(lVar4 + 0x28);
  local_228 = (char *)0x0;
  pcVar9 = strtok_r(param_2,"\r\n",&local_228);
  if (pcVar9 != (char *)0x0) {
    pcVar9 = strtok_r((char *)0x0,"\r\n",&local_228);
    if (pcVar9 != (char *)0x0) {
      plVar1 = (long *)(param_1 + 0x2b8);
      plVar19 = (long *)(param_1 + 0x3d0);
      plVar2 = (long *)(param_1 + 0x488);
      plVar3 = (long *)(param_1 + 0x568);
      iVar7 = 0x30;
      do {
        sVar10 = __strlen_chk("a=msid-semantic:",0x11);
        iVar6 = strncmp(pcVar9,"a=msid-semantic:",sVar10);
        if (iVar6 == 0) {
          lVar15 = __strlen_chk("a=msid-semantic:",0x11);
          local_1e0 = local_1e0 & 0xffffffffffffff00;
          uStack_1f8 = 0;
          local_200 = 0;
          uStack_1e8 = 0;
          uStack_1f0 = 0;
          uStack_218 = 0;
          local_220 = 0;
          uStack_208 = 0;
          uStack_210 = 0;
          local_90 = 0;
          uStack_a8 = 0;
          local_b0 = 0;
          uStack_98 = 0;
          uStack_a0 = 0;
          uStack_c8 = 0;
          local_d0 = (char *)0x0;
          uStack_b8 = 0;
          uStack_c0 = 0;
          iVar6 = sscanf(pcVar9 + lVar15,"%s %s",&local_220,&local_d0);
          if ((iVar6 == 2) && (pcVar13 = (char *)(param_1 + 4), (int)local_220 == 0x534d57)) {
LAB_0017511c:
            ppcVar18 = &local_d0;
            uVar16 = 0x41;
            uVar17 = 0x41;
LAB_00175128:
            FUN_001735c0(pcVar13,uVar16,uVar17,"%s",ppcVar18);
          }
        }
        else {
          sVar10 = __strlen_chk("a=msid:",8);
          iVar6 = strncmp(pcVar9,"a=msid:",sVar10);
          if (iVar6 == 0) {
            lVar15 = __strlen_chk("a=msid:",8);
            local_1e0 = local_1e0 & 0xffffffffffffff00;
            uStack_1f8 = 0;
            local_200 = 0;
            uStack_1e8 = 0;
            uStack_1f0 = 0;
            uStack_218 = 0;
            local_220 = 0;
            uStack_208 = 0;
            uStack_210 = 0;
            local_90 = 0;
            uStack_a8 = 0;
            local_b0 = 0;
            uStack_98 = 0;
            uStack_a0 = 0;
            uStack_c8 = 0;
            local_d0 = (char *)0x0;
            uStack_b8 = 0;
            uStack_c0 = 0;
            iVar6 = sscanf(pcVar9 + lVar15,"%s %s",&local_220,&local_d0);
            if (((iVar6 == 2) &&
                (iVar6 = strcmp((char *)&local_220,(char *)(param_1 + 4)), iVar6 == 0)) &&
               ((pcVar13 = (char *)(param_1 + 0x518), iVar7 == 0x76 ||
                (pcVar13 = (char *)(param_1 + 0x438), iVar7 == 0x61)))) goto LAB_0017511c;
          }
          else {
            sVar10 = __strlen_chk("a=group:BUNDLE",0xf);
            iVar6 = strncmp(pcVar9,"a=group:BUNDLE",sVar10);
            if (iVar6 == 0) {
              lVar15 = __strlen_chk("a=group:BUNDLE",0xf);
              local_1e0 = local_1e0 & 0xffffffffffffff00;
              uStack_1f8 = 0;
              local_200 = 0;
              uStack_1e8 = 0;
              uStack_1f0 = 0;
              uStack_218 = 0;
              local_220 = 0;
              uStack_208 = 0;
              uStack_210 = 0;
              local_90 = 0;
              uStack_a8 = 0;
              local_b0 = 0;
              uStack_98 = 0;
              uStack_a0 = 0;
              uStack_c8 = 0;
              local_d0 = (char *)0x0;
              uStack_b8 = 0;
              uStack_c0 = 0;
              local_e0 = 0;
              uStack_f8 = 0;
              local_100 = 0;
              uStack_e8 = 0;
              uStack_f0 = 0;
              uStack_118 = 0;
              local_120 = 0;
              uStack_108 = 0;
              uStack_110 = 0;
              iVar6 = sscanf(pcVar9 + lVar15,"%s %s %s",&local_220,&local_d0,&local_120);
              if (0 < iVar6) {
                plVar21 = (long *)imm_p2p_pool_zmalloc(0x60);
                if (plVar21 != (long *)0x0) {
                  FUN_001735c0(plVar21 + 3,0xffffffffffffffff,0x41,"%s",&local_220);
                  FUN_001735c0(plVar21 + 2,8,8,"%s",&DAT_0023571f);
                  *plVar21 = (long)plVar19;
                  puVar20 = *(undefined8 **)(param_1 + 0x3d8);
                  plVar21[1] = (long)puVar20;
                  *puVar20 = plVar21;
                  *(long **)(param_1 + 0x3d8) = plVar21;
                }
                if (1 < iVar6) {
                  plVar21 = (long *)imm_p2p_pool_zmalloc(0x60);
                  if (plVar21 != (long *)0x0) {
                    FUN_001735c0(plVar21 + 3,0xffffffffffffffff,0x41,"%s",&local_d0);
                    FUN_001735c0(plVar21 + 2,8,8,"%s",&DAT_0023571f);
                    *plVar21 = (long)plVar19;
                    puVar20 = *(undefined8 **)(param_1 + 0x3d8);
                    plVar21[1] = (long)puVar20;
                    *puVar20 = plVar21;
                    *(long **)(param_1 + 0x3d8) = plVar21;
                  }
                  if ((2 < iVar6) &&
                     (plVar21 = (long *)imm_p2p_pool_zmalloc(0x60), plVar21 != (long *)0x0)) {
                    FUN_001735c0(plVar21 + 3,0xffffffffffffffff,0x41,"%s",&local_120);
                    FUN_001735c0(plVar21 + 2,8,8,"%s",&DAT_0023571f);
                    *plVar21 = (long)plVar19;
                    puVar20 = *(undefined8 **)(param_1 + 0x3d8);
                    plVar21[1] = (long)puVar20;
                    *puVar20 = plVar21;
                    *(long **)(param_1 + 0x3d8) = plVar21;
                  }
                }
              }
            }
            else {
              sVar10 = __strlen_chk(&DAT_0021a8f0,8);
              iVar6 = strncmp(pcVar9,"m=audio",sVar10);
              if (iVar6 == 0) {
                uStack_1b8 = 0;
                local_1c0 = 0;
                uStack_1a8 = 0;
                uStack_1b0 = 0;
                uStack_1d8 = 0;
                local_1e0 = 0;
                uStack_1c8 = 0;
                uStack_1d0 = 0;
                uStack_1f8 = 0;
                local_200 = 0;
                uStack_1e8 = 0;
                uStack_1f0 = 0;
                uStack_218 = 0;
                local_220 = 0;
                uStack_208 = 0;
                uStack_210 = 0;
                pcVar9 = strstr(pcVar9,"SAVPF");
                if (pcVar9 != (char *)0x0) {
                  lVar15 = __strlen_chk("SAVPF",6);
                  FUN_001735c0(&local_220,0x80,0x80,"%s",pcVar9 + lVar15 + 1);
                }
                local_d0 = (char *)0x0;
                pcVar9 = strtok_r((char *)&local_220," ",&local_d0);
                if (pcVar9 != (char *)0x0) {
                  iVar7 = atoi(pcVar9);
                  while( true ) {
                    if ((iVar7 == 0) &&
                       (plVar21 = (long *)imm_p2p_pool_zmalloc(0x40),
                       puVar5 = PTR_default_audio_rtpmaps_00263e30, plVar21 != (long *)0x0)) {
                      if (*(int *)(PTR_default_audio_rtpmaps_00263e30 + 0x30) == 0) {
                        FUN_001735c0(plVar21 + 2,0x20,0x20,"%s",
                                     PTR_default_audio_rtpmaps_00263e30 + 0x10);
                        lVar15 = *(long *)(puVar5 + 0x30);
                        plVar21[7] = *(long *)(puVar5 + 0x38);
                        plVar21[6] = lVar15;
                        *plVar21 = (long)plVar2;
                        puVar20 = *(undefined8 **)(param_1 + 0x490);
                        plVar21[1] = (long)puVar20;
                        *puVar20 = plVar21;
                        *(long **)(param_1 + 0x490) = plVar21;
                      }
                      else {
                        free(plVar21);
                      }
                    }
                    pcVar9 = strtok_r((char *)0x0," ",&local_d0);
                    if (pcVar9 == (char *)0x0) break;
                    iVar7 = atoi(pcVar9);
                  }
                }
                iVar7 = 0x61;
              }
              else {
                sVar10 = __strlen_chk(&DAT_0021a8f8,8);
                iVar6 = strncmp(pcVar9,"m=video",sVar10);
                if (iVar6 == 0) {
                  uStack_1b8 = 0;
                  local_1c0 = 0;
                  uStack_1a8 = 0;
                  uStack_1b0 = 0;
                  uStack_1d8 = 0;
                  local_1e0 = 0;
                  uStack_1c8 = 0;
                  uStack_1d0 = 0;
                  uStack_1f8 = 0;
                  local_200 = 0;
                  uStack_1e8 = 0;
                  uStack_1f0 = 0;
                  uStack_218 = 0;
                  local_220 = 0;
                  uStack_208 = 0;
                  uStack_210 = 0;
                  pcVar9 = strstr(pcVar9,"SAVPF");
                  if (pcVar9 != (char *)0x0) {
                    lVar15 = __strlen_chk("SAVPF",6);
                    FUN_001735c0(&local_220,0x80,0x80,"%s",pcVar9 + lVar15 + 1);
                  }
                  local_d0 = (char *)0x0;
                  pcVar9 = strtok_r((char *)&local_220," ",&local_d0);
                  while (pcVar9 != (char *)0x0) {
                    iVar7 = atoi(pcVar9);
                    plVar21 = (long *)imm_p2p_pool_zmalloc(0x88);
                    if (plVar21 != (long *)0x0) {
                      FUN_001735c0(plVar21 + 2,0x20,0x20,"%s",&DAT_0023571f);
                      *(int *)(plVar21 + 6) = iVar7;
                      *(undefined8 *)((long)plVar21 + 0x34) = 0xffffffff;
                      *(undefined4 *)((long)plVar21 + 0x3c) = 0;
                      FUN_001735c0(plVar21 + 8,0xffffffffffffffff,0x41,"%s",&DAT_0023571f);
                      *plVar21 = (long)plVar3;
                      puVar20 = *(undefined8 **)(param_1 + 0x570);
                      plVar21[1] = (long)puVar20;
                      *puVar20 = plVar21;
                      *(long **)(param_1 + 0x570) = plVar21;
                    }
                    pcVar9 = strtok_r((char *)0x0," ",&local_d0);
                  }
                  iVar7 = 0x76;
                }
                else {
                  sVar10 = __strlen_chk("m=application",0xe);
                  iVar6 = strncmp(pcVar9,"m=application",sVar10);
                  if (iVar6 == 0) {
                    uStack_1b8 = 0;
                    local_1c0 = 0;
                    uStack_1a8 = 0;
                    uStack_1b0 = 0;
                    uStack_1d8 = 0;
                    local_1e0 = 0;
                    uStack_1c8 = 0;
                    uStack_1d0 = 0;
                    uStack_1f8 = 0;
                    local_200 = 0;
                    uStack_1e8 = 0;
                    uStack_1f0 = 0;
                    uStack_218 = 0;
                    local_220 = 0;
                    uStack_208 = 0;
                    uStack_210 = 0;
                    pcVar9 = strstr(pcVar9,"imm");
                    if (pcVar9 != (char *)0x0) {
                      lVar15 = __strlen_chk(&DAT_00218955,4);
                      FUN_001735c0(&local_220,0x80,0x80,"%s",pcVar9 + lVar15 + 1);
                    }
                    local_d0 = (char *)0x0;
                    pcVar9 = strtok_r((char *)&local_220," ",&local_d0);
                    while (pcVar9 != (char *)0x0) {
                      iVar7 = atoi(pcVar9);
                      plVar21 = (long *)imm_p2p_pool_zmalloc(0x38);
                      if (plVar21 != (long *)0x0) {
                        FUN_001735c0(plVar21 + 2,0x20,0x20,"%s",&DAT_0023571f);
                        *(int *)(plVar21 + 6) = iVar7;
                        *(undefined4 *)((long)plVar21 + 0x34) = 0;
                        *plVar21 = param_1 + 0x688;
                        puVar20 = *(undefined8 **)(param_1 + 0x690);
                        plVar21[1] = (long)puVar20;
                        *puVar20 = plVar21;
                        *(long **)(param_1 + 0x690) = plVar21;
                      }
                      pcVar9 = strtok_r((char *)0x0," ",&local_d0);
                    }
                    iVar7 = 0x74;
                  }
                  else {
                    sVar10 = __strlen_chk("a=rtpmap:",10);
                    iVar6 = strncmp(pcVar9,"a=rtpmap:",sVar10);
                    if (iVar6 == 0) {
                      lVar15 = __strlen_chk("a=rtpmap:",10);
                      iVar6 = atoi(pcVar9 + lVar15);
                      pcVar9 = strchr(pcVar9 + lVar15,0x20);
                      if (pcVar9 == (char *)0x0) {
                        pcVar9 = (char *)0x0;
                        pcVar13 = (char *)0x0;
                        pcVar11 = (char *)0x0;
                      }
                      else {
                        pcVar9 = pcVar9 + 1;
                        pcVar11 = strchr(pcVar9,0x2f);
                        if (pcVar11 == (char *)0x0) {
                          pcVar11 = (char *)0x0;
                          pcVar13 = (char *)0x0;
                        }
                        else {
                          pcVar13 = pcVar11 + 1;
                          *pcVar11 = '\0';
                          pcVar12 = strchr(pcVar13,0x2f);
                          pcVar11 = pcVar12;
                          if (pcVar12 != (char *)0x0) {
                            pcVar11 = pcVar12 + 1;
                            *pcVar12 = '\0';
                          }
                        }
                      }
                      if (iVar7 == 0x76) {
                        imm_p2p_log_log(1,&DAT_0023571f,0x350,
                                        "update video codec: pt = %d, codec = %s, %s\n",iVar6,pcVar9
                                        ,pcVar13);
                        plVar21 = plVar3;
                        do {
                          plVar21 = (long *)*plVar21;
                          if (plVar21 == plVar3) goto LAB_00174f4c;
                        } while ((int)plVar21[6] != iVar6);
                        if (pcVar9 != (char *)0x0) {
                          FUN_001735c0(plVar21 + 2,0x20,0x20,"%s");
                        }
                        if (pcVar13 != (char *)0x0) {
                          iVar6 = atoi(pcVar13);
                          *(int *)((long)plVar21 + 0x3c) = iVar6;
                        }
                      }
                      else if (iVar7 != 0x74) {
                        if (iVar7 == 0x61) {
                          imm_p2p_log_log(1,&DAT_0023571f,0x338,
                                          "update audio codec: pt = %d, codec = %s, %s, %s\n",iVar6,
                                          pcVar9,pcVar13,pcVar11);
                          plVar21 = plVar2;
                          do {
                            plVar21 = (long *)*plVar21;
                            if (plVar21 == plVar2) goto LAB_00174f4c;
                          } while (*(int *)(plVar21 + 6) != iVar6);
                          if (pcVar9 != (char *)0x0) {
                            FUN_001735c0(plVar21 + 2,0x20,0x20,"%s");
                          }
                          if (pcVar13 != (char *)0x0) {
                            iVar6 = atoi(pcVar13);
                            *(int *)(plVar21 + 7) = iVar6;
                          }
                          if (pcVar11 == (char *)0x0) {
                            *(undefined4 *)((long)plVar21 + 0x3c) = 1;
                          }
                          else {
                            iVar6 = atoi(pcVar11);
                            *(int *)((long)plVar21 + 0x3c) = iVar6;
                          }
                        }
                        else {
                          imm_p2p_log_log(3,&DAT_0023571f,0x404,"got invalid rtpmap, m = %c\n",iVar7
                                         );
                        }
                      }
                    }
                    else {
                      sVar10 = __strlen_chk("a=fmtp:",8);
                      iVar6 = strncmp(pcVar9,"a=fmtp:",sVar10);
                      if (iVar6 == 0) {
                        lVar15 = __strlen_chk("a=fmtp:",8);
                        pcVar9 = pcVar9 + lVar15;
                        uStack_c8 = 0;
                        local_d0 = (char *)0x0;
                        uStack_b8 = 0;
                        uStack_c0 = 0;
                        uStack_138 = 0;
                        local_140 = 0;
                        uStack_128 = 0;
                        uStack_130 = 0;
                        uStack_158 = 0;
                        local_160 = 0;
                        uStack_148 = 0;
                        uStack_150 = 0;
                        uStack_178 = 0;
                        local_180 = 0;
                        uStack_168 = 0;
                        uStack_170 = 0;
                        uStack_198 = 0;
                        local_1a0 = 0;
                        uStack_188 = 0;
                        uStack_190 = 0;
                        uStack_1b8 = 0;
                        local_1c0 = 0;
                        uStack_1a8 = 0;
                        uStack_1b0 = 0;
                        uStack_1d8 = 0;
                        local_1e0 = 0;
                        uStack_1c8 = 0;
                        uStack_1d0 = 0;
                        uStack_1f8 = 0;
                        local_200 = 0;
                        uStack_1e8 = 0;
                        uStack_1f0 = 0;
                        uStack_218 = 0;
                        local_220 = 0;
                        uStack_208 = 0;
                        uStack_210 = 0;
                        iVar6 = sscanf(pcVar9,"%s %s",&local_d0,&local_220);
                        if (iVar6 == 2) {
                          sVar10 = __strlen_chk(&DAT_0021a93c,5);
                          iVar6 = strncmp((char *)&local_220,"apt=",sVar10);
                          if (iVar6 == 0) {
                            iVar6 = atoi((char *)&local_d0);
                            lVar15 = __strlen_chk(&DAT_0021a93c,5);
                            iVar8 = atoi((char *)((long)&local_220 + lVar15));
                            for (plVar21 = (long *)*plVar3; plVar21 != plVar3;
                                plVar21 = (long *)*plVar21) {
                              if (*(int *)(plVar21 + 6) == iVar6) {
                                *(int *)((long)plVar21 + 0x34) = iVar8;
                              }
                            }
                          }
                        }
                      }
                      sVar10 = __strlen_chk("a=ssrc-group:FID",0x11);
                      iVar6 = strncmp(pcVar9,"a=ssrc-group:FID",sVar10);
                      if (iVar6 == 0) {
                        lVar15 = __strlen_chk("a=ssrc-group:FID",0x11);
                        local_1e0 = local_1e0 & 0xffffffffffffff00;
                        uStack_1f8 = 0;
                        local_200 = 0;
                        uStack_1e8 = 0;
                        uStack_1f0 = 0;
                        uStack_218 = 0;
                        local_220 = 0;
                        uStack_208 = 0;
                        uStack_210 = 0;
                        local_90 = 0;
                        uStack_a8 = 0;
                        local_b0 = 0;
                        uStack_98 = 0;
                        uStack_a0 = 0;
                        uStack_c8 = 0;
                        local_d0 = (char *)0x0;
                        uStack_b8 = 0;
                        uStack_c0 = 0;
                        iVar6 = sscanf(pcVar9 + lVar15,"%s %s",&local_220,&local_d0);
                        if (iVar6 == 2) {
                          if (iVar7 == 0x76) {
                            uVar14 = strtoul((char *)&local_220,(char **)0x0,10);
                            *(int *)(param_1 + 0x5b0) = (int)uVar14;
                            uVar14 = strtoul((char *)&local_d0,(char **)0x0,10);
                            *(int *)(param_1 + 0x638) = (int)uVar14;
                          }
                          else if (iVar7 == 0x61) {
                            uVar14 = strtoul((char *)&local_220,(char **)0x0,10);
                            *(int *)(param_1 + 0x4cc) = (int)uVar14;
                            uVar14 = strtoul((char *)&local_d0,(char **)0x0,10);
                            *(int *)(param_1 + 0x50c) = (int)uVar14;
                          }
                        }
                      }
                      else {
                        sVar10 = __strlen_chk("a=ssrc:",8);
                        iVar6 = strncmp(pcVar9,"a=ssrc:",sVar10);
                        if (iVar6 == 0) {
                          lVar15 = __strlen_chk("a=ssrc:",8);
                          pcVar9 = pcVar9 + lVar15;
                          pcVar13 = strchr(pcVar9,0x20);
                          if (pcVar13 != (char *)0x0) {
                            *pcVar13 = '\0';
                            sVar10 = __strlen_chk("cname:",7);
                            iVar6 = strncmp(pcVar13 + 1,"cname:",sVar10);
                            if (iVar6 == 0) {
                              lVar15 = __strlen_chk("cname:",7);
                              pcVar13 = pcVar13 + 1 + lVar15;
                            }
                            else {
                              pcVar13 = (char *)0x0;
                            }
                          }
                          if (pcVar9 != (char *)0x0) {
                            if (iVar7 == 0x76) {
                              if (*(int *)(param_1 + 0x5b0) == 0) {
                                uVar14 = strtoul(pcVar9,(char **)0x0,10);
                                *(int *)(param_1 + 0x5b0) = (int)uVar14;
                              }
                              else if (*(int *)(param_1 + 0x638) == 0) {
                                uVar14 = strtoul(pcVar9,(char **)0x0,10);
                                *(int *)(param_1 + 0x638) = (int)uVar14;
                              }
                            }
                            else if (iVar7 == 0x61) {
                              if (*(int *)(param_1 + 0x4cc) == 0) {
                                uVar14 = strtoul(pcVar9,(char **)0x0,10);
                                *(int *)(param_1 + 0x4cc) = (int)uVar14;
                              }
                              else if (*(int *)(param_1 + 0x50c) == 0) {
                                uVar14 = strtoul(pcVar9,(char **)0x0,10);
                                *(int *)(param_1 + 0x50c) = (int)uVar14;
                              }
                            }
                          }
                          if (pcVar13 != (char *)0x0) {
                            FUN_001735c0(param_1 + 0x45,0x41,0x41,"%s",pcVar13);
                          }
                        }
                        else {
                          sVar10 = __strlen_chk("a=mid:",7);
                          iVar6 = strncmp(pcVar9,"a=mid:",sVar10);
                          if (iVar6 != 0) {
                            sVar10 = __strlen_chk("a=ice-ufrag:",0xd);
                            iVar6 = strncmp(pcVar9,"a=ice-ufrag:",sVar10);
                            if (iVar6 == 0) {
                              lVar15 = __strlen_chk("a=ice-ufrag:",0xd);
                              pcVar13 = (char *)(param_1 + 0x1b6);
                            }
                            else {
                              sVar10 = __strlen_chk("a=ice-pwd:",0xb);
                              iVar6 = strncmp(pcVar9,"a=ice-pwd:",sVar10);
                              if (iVar6 != 0) {
                                sVar10 = __strlen_chk("a=fingerprint:",0xf);
                                iVar6 = strncmp(pcVar9,"a=fingerprint:",sVar10);
                                if (iVar6 == 0) {
                                  lVar15 = __strlen_chk("a=fingerprint:",0xf);
                                  ppcVar18 = (char **)(pcVar9 + lVar15);
                                  uVar16 = 0x100;
                                  uVar17 = 0x100;
                                  pcVar13 = (char *)(param_1 + 0xb6);
                                }
                                else {
                                  sVar10 = __strlen_chk("a=aes-key:",0xb);
                                  iVar6 = strncmp(pcVar9,"a=aes-key:",sVar10);
                                  if (iVar6 != 0) {
                                    sVar10 = __strlen_chk("a=candidate:",0xd);
                                    iVar6 = strncmp(pcVar9,"a=candidate:",sVar10);
                                    plVar21 = plVar1;
                                    if (iVar6 == 0) {
                                      do {
                                        plVar21 = (long *)*plVar21;
                                        if (plVar21 == plVar1) {
                                          plVar21 = (long *)imm_p2p_pool_zmalloc(0x118);
                                          if (plVar21 != (long *)0x0) {
                                            FUN_001735c0(plVar21 + 2,0x100,0x100,"%s",pcVar9);
                                            lVar15 = imm_p2p_misc_get_timestamp_ms();
                                            plVar21[0x22] = lVar15;
                                            *plVar21 = (long)plVar1;
                                            puVar20 = *(undefined8 **)(param_1 + 0x2c0);
                                            plVar21[1] = (long)puVar20;
                                            *puVar20 = plVar21;
                                            *(long **)(param_1 + 0x2c0) = plVar21;
                                          }
                                          break;
                                        }
                                        iVar6 = strcmp((char *)(plVar21 + 2),pcVar9);
                                      } while (iVar6 != 0);
                                    }
                                    goto LAB_00174f4c;
                                  }
                                  lVar15 = __strlen_chk("a=aes-key:",0xb);
                                  ppcVar18 = (char **)(pcVar9 + lVar15);
                                  uVar16 = 0x30;
                                  uVar17 = 0x30;
                                  pcVar13 = (char *)(param_1 + 0x86);
                                }
                                goto LAB_00175128;
                              }
                              lVar15 = __strlen_chk("a=ice-pwd:",0xb);
                              pcVar13 = (char *)(param_1 + 0x236);
                            }
                            ppcVar18 = (char **)(pcVar9 + lVar15);
                            uVar16 = 0x80;
                            uVar17 = 0x80;
                            goto LAB_00175128;
                          }
                          lVar15 = __strlen_chk("a=mid:",7);
                          pcVar9 = pcVar9 + lVar15;
                          if (pcVar9 != (char *)0x0) {
                            if (iVar7 == 0x76) {
                              for (plVar21 = (long *)*plVar19; plVar21 != plVar19;
                                  plVar21 = (long *)*plVar21) {
                                iVar6 = strcmp((char *)(plVar21 + 3),pcVar9);
                                if (iVar6 == 0) {
                                  FUN_001735c0(plVar21 + 2,8,8,"%s","video");
                                }
                              }
                            }
                            else if (iVar7 == 0x61) {
                              for (plVar21 = (long *)*plVar19; plVar21 != plVar19;
                                  plVar21 = (long *)*plVar21) {
                                iVar6 = strcmp((char *)(plVar21 + 3),pcVar9);
                                if (iVar6 == 0) {
                                  FUN_001735c0(plVar21 + 2,8,8,"%s","audio");
                                }
                              }
                            }
                            else {
                              for (plVar21 = (long *)*plVar19; plVar21 != plVar19;
                                  plVar21 = (long *)*plVar21) {
                                iVar6 = strcmp((char *)(plVar21 + 3),pcVar9);
                                if (iVar6 == 0) {
                                  FUN_001735c0(plVar21 + 2,8,8,"%s",&DAT_00218955);
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
LAB_00174f4c:
        pcVar9 = strtok_r((char *)0x0,"\r\n",&local_228);
      } while (pcVar9 != (char *)0x0);
    }
    plVar19 = *(long **)(param_1 + 0x2b8);
    plVar1 = (long *)(param_1 + 0x2b8);
    if (plVar1 != plVar19) {
      do {
        if ((char)plVar19[2] == '\0') goto LAB_00175f64;
        plVar19 = (long *)*plVar19;
      } while (plVar19 != plVar1);
      plVar19 = (long *)imm_p2p_pool_zmalloc(0x118);
      if (plVar19 != (long *)0x0) {
        FUN_001735c0(plVar19 + 2,0x100,0x100,"%s",&DAT_0023571f);
        lVar15 = imm_p2p_misc_get_timestamp_ms();
        plVar19[0x22] = lVar15;
        *plVar19 = (long)plVar1;
        puVar20 = *(undefined8 **)(param_1 + 0x2c0);
        plVar19[1] = (long)puVar20;
        *puVar20 = plVar19;
        *(long **)(param_1 + 0x2c0) = plVar19;
      }
    }
  }
LAB_00175f64:
  if (*(long *)(lVar4 + 0x28) == local_88) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

