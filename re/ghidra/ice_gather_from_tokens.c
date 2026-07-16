// Ghidra decompilation of ice_gather_from_tokens  (entry=00152108)

void FUN_00152108(undefined8 *param_1)

{
  short *psVar1;
  undefined4 uVar2;
  ushort uVar3;
  long lVar4;
  bool bVar5;
  int iVar6;
  undefined8 uVar7;
  long lVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  char *pcVar12;
  size_t sVar13;
  long lVar14;
  long *plVar15;
  uint uVar16;
  undefined8 *puVar17;
  long *plVar18;
  char *pcVar19;
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  undefined1 auStack_990 [36];
  int local_96c;
  short local_968 [192];
  undefined1 auStack_7e8 [36];
  ushort local_7c4 [2];
  ulong local_7c0;
  undefined8 local_7b8;
  undefined1 local_7b0 [16];
  undefined1 auStack_798 [32];
  code *local_778;
  code *local_770;
  undefined1 auStack_768 [64];
  undefined1 auStack_728 [64];
  undefined1 local_6e8;
  undefined1 auStack_6e7 [67];
  undefined4 local_6a4;
  undefined8 local_3b0;
  undefined1 auStack_3a8 [64];
  undefined1 auStack_368 [64];
  undefined1 auStack_328 [64];
  undefined4 local_2e8;
  int local_2e4;
  undefined1 auStack_2e0 [64];
  undefined4 local_2a0;
  undefined1 local_29c;
  undefined1 auStack_298 [32];
  code *local_278;
  code *local_270;
  code *local_268;
  undefined8 local_260;
  undefined8 uStack_258;
  undefined8 local_250;
  undefined8 uStack_248;
  undefined8 local_240;
  undefined8 uStack_238;
  undefined8 local_230;
  undefined8 uStack_228;
  undefined8 local_220;
  undefined8 uStack_218;
  undefined8 local_210;
  undefined8 uStack_208;
  undefined8 local_200;
  undefined8 uStack_1f8;
  undefined8 local_1f0;
  undefined8 uStack_1e8;
  undefined8 local_1e0;
  undefined8 uStack_1d8;
  undefined8 local_1d0;
  undefined8 uStack_1c8;
  undefined8 local_1c0;
  undefined8 uStack_1b8;
  undefined8 local_1b0;
  undefined8 uStack_1a8;
  undefined8 local_1a0;
  undefined8 uStack_198;
  undefined8 local_190;
  undefined8 uStack_188;
  undefined8 local_180;
  undefined8 uStack_178;
  undefined8 local_170;
  undefined8 uStack_168;
  undefined8 local_160;
  undefined8 uStack_158;
  undefined8 local_150;
  undefined8 uStack_148;
  undefined8 local_140;
  ulong uStack_138;
  undefined8 local_130;
  undefined8 uStack_128;
  undefined8 local_120;
  undefined8 uStack_118;
  undefined8 local_110;
  undefined8 uStack_108;
  undefined8 local_100;
  undefined8 uStack_f8;
  undefined8 local_f0;
  undefined8 uStack_e8;
  undefined8 local_e0;
  undefined8 uStack_d8;
  undefined8 local_d0;
  undefined8 uStack_c8;
  undefined8 local_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 local_a0;
  undefined8 uStack_98;
  undefined *local_90;
  long local_80;

  lVar4 = tpidr_el0;
  local_80 = *(long *)(lVar4 + 0x28);
  if (*(int *)((long)param_1 + 0x9d4) != 0) {
LAB_00152140:
    uVar7 = 0;
    goto LAB_00152144;
  }
  *(undefined4 *)((long)param_1 + 0x9d4) = 1;
  uVar7 = imm_p2p_misc_get_timestamp_ms();
  param_1[0x13b] = uVar7;
  *(undefined4 *)(param_1 + 0x13c) = 10000;
  if ((code *)param_1[1] != (code *)0x0) {
    (*(code *)param_1[1])(param_1,*(undefined4 *)(param_1 + 0x13a));
  }
  local_7b8 = 0;
  local_7c0 = 0;
  local_7c4[0] = 0;
  local_90 = (undefined *)0x0;
  uStack_98 = 0;
  local_a0 = 0;
  uStack_a8 = 0;
  local_b0 = 0;
  uStack_b8 = 0;
  local_c0 = 0;
  uStack_c8 = 0;
  local_d0 = 0;
  uStack_d8 = 0;
  local_e0 = 0;
  uStack_e8 = 0;
  local_f0 = 0;
  uStack_f8 = 0;
  local_100 = 0;
  uStack_108 = 0;
  local_110 = 0;
  uStack_118 = 0;
  local_120 = 0;
  uStack_128 = 0;
  local_130 = 0;
  uStack_138 = 0;
  local_140 = 0;
  uStack_148 = 0;
  local_150 = 0;
  uStack_158 = 0;
  local_160 = 0;
  uStack_168 = 0;
  local_170 = 0;
  uStack_178 = 0;
  local_180 = 0;
  uStack_188 = 0;
  local_190 = 0;
  uStack_198 = 0;
  local_1a0 = 0;
  uStack_1a8 = 0;
  local_1b0 = 0;
  uStack_1b8 = 0;
  local_1c0 = 0;
  uStack_1c8 = 0;
  local_1d0 = 0;
  uStack_1d8 = 0;
  local_1e0 = 0;
  uStack_1e8 = 0;
  local_1f0 = 0;
  uStack_1f8 = 0;
  local_200 = 0;
  uStack_208 = 0;
  local_210 = 0;
  uStack_218 = 0;
  local_220 = 0;
  uStack_228 = 0;
  local_230 = 0;
  uStack_238 = 0;
  local_240 = 0;
  uStack_248 = 0;
  local_250 = 0;
  uStack_258 = 0;
  local_260 = 0;
  lVar8 = cJSON_Parse(param_1 + 0xc);
  iVar6 = cJSON_IsArray();
  lVar14 = DAT_00215678;
  if (iVar6 == 0) {
    uVar7 = 1;
    goto LAB_00152144;
  }
  if (lVar8 != 0) {
    plVar18 = *(long **)(lVar8 + 0x10);
    if (plVar18 != (long *)0x0) {
      do {
        while( true ) {
          iVar6 = cJSON_IsObject(plVar18);
          if (iVar6 != 0) break;
LAB_001522a8:
          plVar18 = (long *)*plVar18;
joined_r0x00152730:
          if (plVar18 == (long *)0x0) goto LAB_00152804;
        }
        lVar9 = cJSON_GetObjectItemCaseSensitive(plVar18,"username");
        lVar10 = cJSON_GetObjectItemCaseSensitive(plVar18,"credential");
        uVar7 = cJSON_GetObjectItemCaseSensitive(plVar18,"sha256");
        if (*(char *)(param_1 + 0xb) == '\0') {
LAB_0015231c:
          bVar5 = false;
        }
        else {
          iVar6 = cJSON_IsBool();
          if (iVar6 == 0) goto LAB_0015231c;
          iVar6 = cJSON_IsTrue(uVar7);
          bVar5 = iVar6 != 0;
        }
        lVar11 = cJSON_GetObjectItemCaseSensitive(plVar18,&DAT_00215773);
        iVar6 = cJSON_IsString();
        if (iVar6 == 0) goto LAB_001522a8;
        pcVar19 = *(char **)(lVar11 + 0x20);
        pcVar12 = strstr(pcVar19,"?transport=");
        if (pcVar12 != (char *)0x0) {
          lVar11 = __strlen_chk("?transport=",0xc);
          sVar13 = __strlen_chk(&DAT_00215784,4);
          iVar6 = strncmp(pcVar12 + lVar11,"tcp",sVar13);
          if (iVar6 != 0) {
            sVar13 = __strlen_chk("TCP",4);
            iVar6 = strncmp(pcVar12 + lVar11,"TCP",sVar13);
            if (iVar6 != 0) goto LAB_001523c0;
          }
          goto LAB_001522a8;
        }
LAB_001523c0:
        sVar13 = __strlen_chk("turn:",6);
        iVar6 = strncmp(pcVar19,"turn:",sVar13);
        if (iVar6 == 0) {
          iVar6 = cJSON_IsString(lVar9);
          if (iVar6 != 0) {
            iVar6 = cJSON_IsString(lVar10);
            if (iVar6 != 0) {
              pcVar12 = *(char **)(lVar9 + 0x20);
              sVar13 = strlen(pcVar12);
              auVar22 = uv_buf_init(pcVar12,sVar13);
              pcVar12 = *(char **)(lVar10 + 0x20);
              sVar13 = strlen(pcVar12);
              auVar20 = uv_buf_init(pcVar12,sVar13);
              iVar6 = FUN_001536bc(pcVar19,"turn:",&local_7b8,&local_7c0,local_7c4);
              if (iVar6 == 0) {
                auVar21 = uv_buf_init(local_7b8,local_7c0 & 0xffffffff);
                local_7b0 = auVar21;
                imm_p2p_log_log(1,&DAT_0023571f,0x587,"+ turn server: %.*s port:%d\n",auVar21._8_8_,
                                auVar21._0_8_,local_7c4[0]);
                if (*(int *)((long)param_1 + 0x884) == 0) {
                  iVar6 = imm_p2p_misc_is_ipv6(local_7b0);
                  if (iVar6 != 0) {
                    imm_p2p_log_log(3,&DAT_0023571f,0x58a,
                                    "turn server is ipv6, but ice has no ipv6\n");
                    plVar18 = (long *)*plVar18;
                    goto joined_r0x00152730;
                  }
                }
                if (*(int *)(param_1 + 0x110) == 0) {
                  iVar6 = imm_p2p_misc_is_ipv4(local_7b0);
                  if (iVar6 != 0) {
                    imm_p2p_log_log(3,&DAT_0023571f,0x58f,
                                    "turn server is ipv4, but ice has no ipv4\n");
                    plVar18 = (long *)*plVar18;
                    goto joined_r0x00152730;
                  }
                }
                iVar6 = imm_p2p_misc_is_ipv4(local_7b0);
                if (iVar6 == 0) {
                  iVar6 = imm_p2p_misc_is_ipv6(local_7b0);
                  if (iVar6 != 0) goto LAB_0015258c;
                  uVar7 = 0x594;
LAB_001527e8:
                  imm_p2p_log_log(3,&DAT_0023571f,uVar7,"skip domian\n");
                  plVar18 = (long *)*plVar18;
                  goto joined_r0x00152730;
                }
LAB_0015258c:
                uVar16 = (uint)local_7c4[0];
                plVar15 = (long *)imm_p2p_pool_zmalloc(0x78);
                if (plVar15 != (long *)0x0) {
                  plVar15[2] = lVar14;
                  auVar22 = uv_buf_clone(auVar22._0_8_,auVar22._8_8_);
                  *(undefined1 (*) [16])(plVar15 + 3) = auVar22;
                  auVar22 = uv_buf_clone(auVar20._0_8_,auVar20._8_8_);
                  *(undefined1 (*) [16])(plVar15 + 5) = auVar22;
                  *(bool *)(plVar15 + 7) = bVar5;
                  auVar22 = uv_buf_clone(local_7b0._0_8_,local_7b0._8_8_);
                  *(undefined1 (*) [16])(plVar15 + 8) = auVar22;
                  plVar15[0xb] = 0;
                  plVar15[0xc] = (long)param_1;
                  plVar15[0xd] = 0;
                  *(uint *)(plVar15 + 10) = uVar16;
                  *plVar15 = (long)(param_1 + 0x10e);
                  puVar17 = (undefined8 *)param_1[0x10f];
                  plVar15[1] = (long)puVar17;
                  *puVar17 = plVar15;
                  param_1[0x10f] = plVar15;
                  plVar18 = (long *)*plVar18;
                  goto joined_r0x00152730;
                }
              }
            }
          }
          goto LAB_001522a8;
        }
        sVar13 = __strlen_chk("stun:",6);
        iVar6 = strncmp(pcVar19,"stun:",sVar13);
        if (iVar6 == 0) {
          iVar6 = FUN_001536bc(pcVar19,"stun:",&local_7b8,&local_7c0,local_7c4);
          if (iVar6 != 0) goto LAB_001522a8;
          auVar22 = uv_buf_init(local_7b8,local_7c0 & 0xffffffff);
          local_7b0 = auVar22;
          imm_p2p_log_log(1,&DAT_0023571f,0x5a2,"+ stun server: %.*s port:%d\n",auVar22._8_8_,
                          auVar22._0_8_,local_7c4[0]);
          if (*(int *)((long)param_1 + 0x884) == 0) {
            iVar6 = imm_p2p_misc_is_ipv6(local_7b0);
            if (iVar6 == 0) goto LAB_00152654;
            imm_p2p_log_log(3,&DAT_0023571f,0x5a5,"stun server is ipv6, but ice has no ipv6\n");
            plVar18 = (long *)*plVar18;
          }
          else {
LAB_00152654:
            if (*(int *)(param_1 + 0x110) == 0) {
              iVar6 = imm_p2p_misc_is_ipv4(local_7b0);
              if (iVar6 != 0) {
                imm_p2p_log_log(3,&DAT_0023571f,0x5aa,"stun server is ipv4, but ice has no ipv4\n");
                plVar18 = (long *)*plVar18;
                goto joined_r0x00152730;
              }
            }
            iVar6 = imm_p2p_misc_is_ipv4(local_7b0);
            if (iVar6 == 0) {
              iVar6 = imm_p2p_misc_is_ipv6(local_7b0);
              if (iVar6 == 0) {
                uVar7 = 0x5af;
                goto LAB_001527e8;
              }
            }
            uVar3 = local_7c4[0];
            plVar15 = (long *)imm_p2p_pool_zmalloc(0x78);
            if (plVar15 == (long *)0x0) goto LAB_001522a8;
            plVar15[2] = 0;
            *(bool *)(plVar15 + 7) = bVar5;
            auVar22 = uv_buf_clone(local_7b0._0_8_,local_7b0._8_8_);
            *(undefined1 (*) [16])(plVar15 + 8) = auVar22;
            plVar15[0xb] = 0;
            plVar15[0xc] = (long)param_1;
            *(uint *)(plVar15 + 10) = (uint)uVar3;
            plVar15[0xd] = 0;
            *plVar15 = (long)(param_1 + 0x10e);
            puVar17 = (undefined8 *)param_1[0x10f];
            plVar15[1] = (long)puVar17;
            *puVar17 = plVar15;
            param_1[0x10f] = plVar15;
            plVar18 = (long *)*plVar18;
          }
          goto joined_r0x00152730;
        }
        sVar13 = __strlen_chk(&DAT_00215883,5);
        iVar6 = strncmp(pcVar19,"nat:",sVar13);
        if (iVar6 != 0) goto LAB_001522a8;
        iVar6 = FUN_001536bc(pcVar19,&DAT_00215883,&local_7b8,&local_7c0,local_7c4);
        if (iVar6 != 0) goto LAB_001522a8;
        lVar9 = __strlen_chk(&uStack_238,0x1b0);
        if (lVar9 == 0) {
          FUN_00151c5c(&uStack_238,0x80,0x80,"%.*s",local_7c0 & 0xffffffff,local_7b8);
          uStack_138 = CONCAT44(uStack_138._4_4_,(uint)local_7c4[0]);
          plVar18 = (long *)*plVar18;
        }
        else {
          lVar9 = __strlen_chk(&uStack_1b8,0x130);
          if (lVar9 != 0) goto LAB_001522a8;
          FUN_00151c5c(&uStack_1b8,0x80,0x80,"%.*s",local_7c0 & 0xffffffff,local_7b8);
          uStack_138 = (ulong)CONCAT24(local_7c4[0],(undefined4)uStack_138);
          plVar18 = (long *)*plVar18;
        }
      } while (plVar18 != (long *)0x0);
LAB_00152804:
      if (lVar8 == 0) goto LAB_00152818;
    }
    cJSON_Delete(lVar8);
  }
LAB_00152818:
  lVar14 = __strlen_chk(&uStack_238,0x1b0);
  if (lVar14 != 0) {
    lVar14 = __strlen_chk(&uStack_1b8,0x130);
    if (lVar14 != 0) {
      local_260 = param_1[5];
      local_90 = PTR_on_nat_detected_00263f78;
      imm_p2p_convert_sockaddr3(&local_b0,"0.0.0.0",0);
      imm_p2p_nat_detector_create(&local_260,param_1 + 0x13e);
      imm_p2p_nat_detector_set_user_data(param_1[0x13e],param_1);
      if (*(int *)((long)param_1 + 0x884) == 0) {
        if ((code *)param_1[3] != (code *)0x0) {
          (*(code *)param_1[3])(param_1,10,0xfffffffc);
        }
      }
      else {
        imm_p2p_convert_sockaddr3(&local_b0,&DAT_00215890,0);
        imm_p2p_nat_detector_create(&local_260,param_1 + 0x13f);
        imm_p2p_nat_detector_set_user_data(param_1[0x13f],param_1);
      }
    }
  }
  plVar18 = (long *)param_1[0x10e];
  uVar7 = 0;
  if ((plVar18 != param_1 + 0x10e) && (plVar18 != (long *)0x0)) {
    do {
      pcVar12 = "::";
      if ((*plVar18 == 0) || (plVar18[1] == 0)) goto LAB_00152140;
      iVar6 = imm_p2p_misc_is_ipv6(plVar18 + 8);
      if (iVar6 == 0) {
        iVar6 = imm_p2p_misc_is_ipv4(plVar18 + 8,&DAT_00215890);
        pcVar12 = "0.0.0.0";
        if (iVar6 != 0) goto LAB_00152980;
        imm_p2p_log_log(1,&DAT_0023571f,0x5ef,"addr is domain skip.\n");
      }
      else {
LAB_00152980:
        imm_p2p_convert_sockaddr3(auStack_7e8,pcVar12,0);
        if ((int)plVar18[2] == 1) {
          imm_p2p_turn_sock_cfg_default(local_7b0);
          local_7b0._0_8_ = param_1[5];
          sockaddr_cp(auStack_798,auStack_7e8);
          FUN_00151c5c(auStack_6e7,0x40,0x40,"%.*s",(int)plVar18[9],plVar18[8]);
          local_6a4 = (undefined4)plVar18[10];
          local_770 = FUN_00153ca8;
          local_778 = FUN_00153b54;
          FUN_00151c5c(auStack_768,0x40,0x40,"%.*s",(int)plVar18[4],plVar18[3]);
          FUN_00151c5c(auStack_728,0x40,0x40,"%.*s",(int)plVar18[6],plVar18[5]);
          local_6e8 = (undefined1)plVar18[7];
          iVar6 = imm_p2p_turn_sock_create(local_7b0,plVar18 + 0xb);
          if ((iVar6 == 0) && (lVar14 = plVar18[0xb], lVar14 != 0)) {
            imm_p2p_turn_sock_set_user_data(lVar14,plVar18);
          }
          else {
            lVar14 = imm_p2p_pool_zmalloc(0x88);
            if (lVar14 != 0) {
              uVar7 = 3;
LAB_00152b44:
              FUN_001519b8(lVar14,2,uVar7,plVar18,0,0);
            }
LAB_00152b58:
            plVar18[0xd] = lVar14;
          }
        }
        else if ((int)plVar18[2] == 0) {
          imm_p2p_stun_sock_cfg_default(&local_3b0);
          local_3b0 = param_1[5];
          sockaddr_cp(auStack_298,auStack_7e8);
          FUN_00151c5c(auStack_328,0x40,0x40,"%.*s",(int)plVar18[9],plVar18[8]);
          local_2e8 = (undefined4)plVar18[10];
          local_278 = FUN_001537c0;
          local_268 = FUN_00153af0;
          local_270 = FUN_001538e8;
          FUN_00151c5c(auStack_3a8,0x40,0x40,"%.*s",(int)plVar18[4],plVar18[3]);
          FUN_00151c5c(auStack_368,0x40,0x40,"%.*s",(int)plVar18[6],plVar18[5]);
          local_29c = (undefined1)plVar18[7];
          iVar6 = imm_p2p_stun_sock_create(&local_3b0,plVar18 + 0xb);
          if ((iVar6 != 0) || (lVar14 = plVar18[0xb], lVar14 == 0)) {
            lVar14 = imm_p2p_pool_zmalloc(0x88);
            if (lVar14 != 0) {
              uVar7 = 1;
              goto LAB_00152b44;
            }
            goto LAB_00152b58;
          }
          imm_p2p_stun_sock_set_user_data(lVar14,plVar18);
          local_96c = 0xc;
          imm_p2p_stun_sock_get_alias_address(plVar18[0xb],local_968,&local_96c);
          if (local_96c < 0xd) {
            if (0 < local_96c) goto LAB_00152bdc;
          }
          else {
            local_96c = 0xc;
LAB_00152bdc:
            lVar14 = 0;
            psVar1 = local_968;
            iVar6 = *(int *)((long)param_1 + 0x884);
            while( true ) {
              if (((iVar6 == 0) && (*psVar1 == 10)) ||
                 ((*(int *)(param_1 + 0x110) == 0 && (*psVar1 == 2)))) {
                imm_p2p_log_log(1,&DAT_0023571f,0x618,"skip ipv6 candidate\n");
              }
              else {
                plVar15 = (long *)imm_p2p_pool_zmalloc(0x88);
                if (plVar15 != (long *)0x0) {
                  FUN_001519b8(plVar15,1,0,plVar18,psVar1,psVar1);
                  lVar8 = param_1[0x112];
                  if (lVar8 != 0) {
                    *plVar15 = lVar8 + 0x90;
                    puVar17 = *(undefined8 **)(lVar8 + 0x98);
                    plVar15[1] = (long)puVar17;
                    *puVar17 = plVar15;
                    *(long **)(lVar8 + 0x98) = plVar15;
                    *(int *)(lVar8 + 0x88) = *(int *)(lVar8 + 0x88) + 1;
                  }
                  FUN_00151dc8(param_1,0,plVar15);
                  if ((*(ushort *)(plVar15 + 9) | 8) == 10) {
                    uVar3 = *(ushort *)((long)plVar15 + 0x4e);
                    iVar6 = rand();
                    uVar2 = *(undefined4 *)((long)plVar15 + 0x44);
                    uVar7 = get_ip_from_sockaddr((long)plVar15 + 0x4c);
                    pcVar12 = "srflx";
                    if ((int)plVar15[2] != 1) {
                      pcVar12 = "host";
                    }
                    pcVar19 = "relay";
                    if ((int)plVar15[2] != 3) {
                      pcVar19 = pcVar12;
                    }
                    FUN_00151c5c(local_7b0,0x400,0x400,"a=candidate:%d 1 UDP %u %s %d typ %s\r\n",
                                 iVar6,uVar2,uVar7,uVar3 >> 8 | uVar3 << 8,pcVar19);
                  }
                  if ((code *)*param_1 != (code *)0x0) {
                    (*(code *)*param_1)(param_1,0,local_7b0);
                  }
                }
              }
              lVar14 = lVar14 + 1;
              psVar1 = psVar1 + 0x10;
              if (local_96c <= lVar14) break;
              iVar6 = *(int *)((long)param_1 + 0x884);
            }
          }
          if (local_2e4 != 0) {
            imm_p2p_convert_sockaddr3(auStack_990,auStack_2e0,local_2a0);
            plVar15 = (long *)imm_p2p_pool_zmalloc(0x88);
            if (plVar15 != (long *)0x0) {
              FUN_001519b8(plVar15,1,0,plVar18,auStack_990,auStack_990);
              lVar14 = param_1[0x112];
              if (lVar14 != 0) {
                *plVar15 = lVar14 + 0x90;
                puVar17 = *(undefined8 **)(lVar14 + 0x98);
                plVar15[1] = (long)puVar17;
                *puVar17 = plVar15;
                *(long **)(lVar14 + 0x98) = plVar15;
                *(int *)(lVar14 + 0x88) = *(int *)(lVar14 + 0x88) + 1;
              }
              FUN_00151dc8(param_1,0,plVar15);
              if ((*(ushort *)(plVar15 + 9) | 8) == 10) {
                uVar3 = *(ushort *)((long)plVar15 + 0x4e);
                iVar6 = rand();
                uVar2 = *(undefined4 *)((long)plVar15 + 0x44);
                uVar7 = get_ip_from_sockaddr((long)plVar15 + 0x4c);
                pcVar12 = "srflx";
                if ((int)plVar15[2] != 1) {
                  pcVar12 = "host";
                }
                pcVar19 = "relay";
                if ((int)plVar15[2] != 3) {
                  pcVar19 = pcVar12;
                }
                FUN_00151c5c(local_7b0,0x400,0x400,"a=candidate:%d 1 UDP %u %s %d typ %s\r\n",iVar6,
                             uVar2,uVar7,uVar3 >> 8 | uVar3 << 8,pcVar19);
              }
              if ((code *)*param_1 != (code *)0x0) {
                (*(code *)*param_1)(param_1,0,local_7b0);
              }
            }
          }
        }
      }
      plVar18 = (long *)*plVar18;
      uVar7 = 0;
    } while ((plVar18 != param_1 + 0x10e) && (plVar18 != (long *)0x0));
  }
LAB_00152144:
  if (*(long *)(lVar4 + 0x28) == local_80) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar7);
}
