// Ghidra decompilation of imm_p2p_rtc_init  (entry=0015e520)

void imm_p2p_rtc_init(void *param_1)

{
  uint uVar1;
  long lVar2;
  undefined *puVar3;
  undefined *puVar4;
  int iVar5;
  uint uVar6;
  undefined8 uVar7;
  time_t tVar8;
  long lVar9;
  char *pcVar10;
  long *plVar11;
  char *pcVar12;
  undefined4 uVar13;
  long lVar14;
  ulong uVar15;
  long lVar16;
  uint uVar17;
  void *__arg;
  ulong local_10f0;
  undefined8 local_10e8;
  undefined8 local_10e0;
  undefined8 uStack_10d8;
  undefined8 uStack_10d0;
  undefined8 uStack_10c8;
  undefined8 local_10c0;
  undefined8 uStack_10b8;
  undefined8 uStack_10b0;
  undefined8 uStack_10a8;
  undefined8 local_10a0;
  undefined8 uStack_1098;
  undefined8 uStack_1090;
  undefined8 uStack_1088;
  undefined8 local_1080;
  undefined8 uStack_1078;
  undefined8 uStack_1070;
  undefined8 uStack_1068;
  pthread_attr_t apStack_1058 [73];
  long local_58;
  
  lVar2 = tpidr_el0;
  local_58 = *(long *)(lVar2 + 0x28);
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  puVar4 = PTR_g_p2p_skill_00263ff0;
  puVar3 = PTR_g_ctx_00263e48;
  if (*(long *)PTR_g_ctx_00263e48 == 0) {
    *(undefined4 *)PTR_g_ctx_inited_00263ee8 = 1;
    imm_p2p_log_set_level(2);
    uVar13 = 0x643;
    if (*(int *)((long)param_1 + 0xb28) != 0) {
      uVar13 = 0x663;
    }
    *(undefined4 *)puVar4 = uVar13;
    imm_p2p_log_log(2,&DAT_0023571f,0x1b0d,"imm p2p rtc sdk version: 0x%x, %s %s\n",0xf4030504,
                    "Jun 26 2025","09:02:39");
    uVar7 = imm_p2p_pool_zmalloc(0xb420);
    *(undefined8 *)puVar3 = uVar7;
    uStack_1078 = 0;
    local_1080 = 0;
    uStack_1068 = 0;
    uStack_1070 = 0;
    uStack_1098 = 0;
    local_10a0 = 0;
    uStack_1088 = 0;
    uStack_1090 = 0;
    uStack_10b8 = 0;
    local_10c0 = 0;
    uStack_10a8 = 0;
    uStack_10b0 = 0;
    uStack_10d8 = 0;
    local_10e0 = 0;
    uStack_10c8 = 0;
    uStack_10d0 = 0;
    imm_p2p_misc_rand_string(&local_10e0,0x80);
    lVar14 = *(long *)puVar3;
    tVar8 = time((time_t *)0x0);
    FUN_0015e3d0(lVar14 + 0xf89,0x50,0x29,"%s%ld%s",param_1,tVar8,&local_10e0);
    uVar6 = imm_p2p_misc_get_timestamp_ms();
    srand(uVar6);
    iVar5 = uv_loop_init(*(undefined8 *)puVar3);
    if (iVar5 == 0) {
      lVar14 = *(long *)puVar3;
      memcpy((void *)(lVar14 + 0x350),param_1,0xbd0);
      uVar6 = *(uint *)(lVar14 + 0x418);
      uVar17 = *(uint *)(lVar14 + 0x41c);
      if (0x149 < uVar6) {
        uVar6 = 0x14a;
      }
      if (0x3ff < uVar17) {
        uVar17 = 0x400;
      }
      uVar15 = 0;
      *(uint *)(lVar14 + 0x41c) = uVar17;
      *(uint *)(lVar14 + 0x418) = uVar6;
      if ((ulong)uVar6 != 0) goto LAB_0015e760;
LAB_0015e740:
      lVar9 = lVar14 + uVar15 * 4;
      *(undefined4 *)(lVar9 + 0x424) = 0;
      *(undefined4 *)(lVar9 + 0x94c) = 0;
LAB_0015e74c:
      uVar15 = uVar15 + 1;
      if (uVar15 == 0x14a) {
        if (*(uint *)(lVar14 + 0xe74) < 600) {
          uVar13 = 600;
LAB_0015e7d0:
          *(undefined4 *)(lVar14 + 0xe74) = uVar13;
        }
        else if (4000 < *(uint *)(lVar14 + 0xe74)) {
          uVar13 = 4000;
          goto LAB_0015e7d0;
        }
        lVar14 = *(long *)puVar3;
        *(undefined4 *)(lVar14 + 0xa6d0) = 0xffffffff;
        *(undefined8 *)(lVar14 + 0xa6c8) = 0;
        iVar5 = pthread_mutex_init((pthread_mutex_t *)(lVar14 + 0xaf58),(pthread_mutexattr_t *)0x0);
        if (iVar5 != 0) goto LAB_0015ea24;
        lVar14 = *(long *)puVar3;
        if (*(long *)(lVar14 + 0xf28) == 0) {
          uVar7 = bc_msg_queue_create();
          *(undefined8 *)(lVar14 + 0xf28) = uVar7;
          if (*(long *)(lVar14 + 0xf30) == 0) goto LAB_0015e978;
LAB_0015e810:
          if (*(long *)(lVar14 + 0xf38) != 0) goto LAB_0015e818;
LAB_0015e988:
          uVar7 = bc_msg_queue_create();
          *(undefined8 *)(lVar14 + 0xf38) = uVar7;
          if (*(long *)(lVar14 + 0xf40) == 0) goto LAB_0015e998;
LAB_0015e820:
          lVar9 = *(long *)(lVar14 + 0xf48);
          if (lVar9 != 0) goto LAB_0015e828;
LAB_0015e9a8:
          lVar9 = bc_msg_queue_create();
          *(long *)(lVar14 + 0xf48) = lVar9;
          lVar16 = *(long *)(lVar14 + 0xf28);
        }
        else {
          if (*(long *)(lVar14 + 0xf30) != 0) goto LAB_0015e810;
LAB_0015e978:
          uVar7 = bc_msg_queue_create();
          *(undefined8 *)(lVar14 + 0xf30) = uVar7;
          if (*(long *)(lVar14 + 0xf38) == 0) goto LAB_0015e988;
LAB_0015e818:
          if (*(long *)(lVar14 + 0xf40) != 0) goto LAB_0015e820;
LAB_0015e998:
          uVar7 = bc_msg_queue_create();
          *(undefined8 *)(lVar14 + 0xf40) = uVar7;
          lVar9 = *(long *)(lVar14 + 0xf48);
          if (lVar9 == 0) goto LAB_0015e9a8;
LAB_0015e828:
          lVar16 = *(long *)(lVar14 + 0xf28);
        }
        if ((((lVar16 == 0) || (*(long *)(lVar14 + 0xf30) == 0)) || (*(long *)(lVar14 + 0xf38) == 0)
            ) || ((lVar9 == 0 || (*(long *)(lVar14 + 0xf40) == 0)))) goto LAB_0015e9bc;
        lVar14 = *(long *)puVar3;
        pthread_mutex_init((pthread_mutex_t *)(lVar14 + 0x1040),(pthread_mutexattr_t *)0x0);
        pthread_cond_init((pthread_cond_t *)(lVar14 + 0x1068),(pthread_condattr_t *)0x0);
        *(long *)(lVar14 + 0x1030) = lVar14 + 0x1030;
        *(long *)(lVar14 + 0x1038) = lVar14 + 0x1030;
        pthread_mutex_init((pthread_mutex_t *)(lVar14 + 0xa628),(pthread_mutexattr_t *)0x0);
        pthread_cond_init((pthread_cond_t *)(lVar14 + 0xa650),(pthread_condattr_t *)0x0);
        *(long *)(lVar14 + 0x43e0) = lVar14 + 0x43e0;
        *(long *)(lVar14 + 0x43e8) = lVar14 + 0x43e0;
        *(undefined4 *)(lVar14 + 0xa680) = 0;
        pthread_mutex_init((pthread_mutex_t *)(lVar14 + 0xa698),(pthread_mutexattr_t *)0x0);
        *(long *)(lVar14 + 0xa688) = lVar14 + 0xa688;
        *(long *)(lVar14 + 0xa690) = lVar14 + 0xa688;
        *(undefined4 *)(lVar14 + 0xa6c0) = 0;
        lVar9 = *(long *)puVar3;
        lVar14 = lVar9 + 0xaf88;
        mbedtls_entropy_init(lVar14);
        lVar9 = lVar9 + 0xb2c8;
        mbedtls_ctr_drbg_init(lVar9);
        iVar5 = mbedtls_ctr_drbg_seed(lVar9,PTR_mbedtls_entropy_func_00263f20,lVar14,0,0);
        if (iVar5 == 0) {
          iVar5 = srtp_init();
          if (iVar5 != 0) {
            imm_p2p_log_log(4,&DAT_0023571f,0x1a5e,"imm p2p rtc init: srtp_init\n");
            iVar5 = 0;
            goto LAB_0015eb50;
          }
          local_10f0 = 0x2000;
          local_10e8 = 0x2000;
          iVar5 = imm_p2p_misc_generate_pkey(&DAT_00270bf8,&local_10e8);
          if (iVar5 < 0) {
LAB_0015eb48:
            srtp_shutdown();
            goto LAB_0015eb50;
          }
          DAT_00272ffc = (int)local_10e8;
          iVar5 = imm_p2p_misc_generate_cert
                            (&DAT_00270bf8,(long)DAT_00272ffc,&DAT_0026ebf8,&local_10f0);
          if (iVar5 < 0) goto LAB_0015eb48;
          DAT_00272ff8 = (undefined4)local_10f0;
          iVar5 = imm_p2p_misc_calculate_cert_fingerprint
                            ("sha-256",&DAT_0026ebf8,local_10f0 & 0xffffffff,&DAT_00272bf8,0x400);
          if (iVar5 < 0) goto LAB_0015eb48;
LAB_0015eb64:
          __arg = *(void **)puVar3;
          iVar5 = pthread_attr_init(apStack_1058);
          if (iVar5 == 0) {
            iVar5 = pthread_attr_setstacksize(apStack_1058,0x20000);
            if (iVar5 != 0) {
              pcVar10 = strerror(iVar5);
              pcVar12 = "pthread_attr_setstacksize failed, errno = %d, errstr = %s\n";
              uVar7 = 0x1a9d;
              goto LAB_0015ebd0;
            }
            *(undefined4 *)((long)__arg + 0xf50) = 0;
            iVar5 = pthread_create((pthread_t *)((long)__arg + 0xf58),apStack_1058,FUN_00165350,
                                   __arg);
            if (iVar5 == 0) {
              iVar5 = pthread_create((pthread_t *)((long)__arg + 0xf60),apStack_1058,FUN_00167210,
                                     __arg);
              if (iVar5 == 0) {
                iVar5 = pthread_create((pthread_t *)((long)__arg + 0xf68),apStack_1058,FUN_0016769c,
                                       __arg);
                if (iVar5 == 0) {
                  iVar5 = pthread_create((pthread_t *)((long)__arg + 0xf70),apStack_1058,
                                         FUN_00167794,__arg);
                  if (iVar5 == 0) {
                    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
                    FUN_0015ee40(*(undefined8 *)puVar3);
                    uVar7 = 0;
                    goto LAB_0015ea7c;
                  }
                  pcVar12 = strerror(iVar5);
                  imm_p2p_log_log(4,&DAT_0023571f,0x1ab3,
                                  "create signaling lan thread failed, errno = %d, errstr = %s\n",
                                  iVar5,pcVar12);
                  bc_msg_queue_close(*(undefined8 *)((long)__arg + 0xf40));
                  pthread_join(*(pthread_t *)((long)__arg + 0xf68),(void **)0x0);
                }
                else {
                  pcVar12 = strerror(iVar5);
                  imm_p2p_log_log(4,&DAT_0023571f,0x1aae,
                                  "create signaling mqtt worker thread failed, errno = %d, errstr = %s\n"
                                  ,iVar5,pcVar12);
                }
                bc_msg_queue_close(*(undefined8 *)((long)__arg + 0xf30));
                pthread_join(*(pthread_t *)((long)__arg + 0xf60),(void **)0x0);
              }
              else {
                pcVar12 = strerror(iVar5);
                imm_p2p_log_log(4,&DAT_0023571f,0x1aa9,
                                "create async worker thread failed, errno = %d, errstr = %s\n",iVar5
                                ,pcVar12);
              }
              bc_msg_queue_close(*(undefined8 *)((long)__arg + 0xf28));
              uVar6 = pthread_join(*(pthread_t *)((long)__arg + 0xf58),(void **)0x0);
              uVar15 = (ulong)uVar6;
            }
            else {
              pcVar12 = strerror(iVar5);
              uVar15 = imm_p2p_log_log(4,&DAT_0023571f,0x1aa4,
                                       "create worker thread failed, errno = %d, errstr = %s\n",
                                       iVar5,pcVar12);
            }
            *(undefined4 *)((long)__arg + 0xf50) = 1;
          }
          else {
            pcVar10 = strerror(iVar5);
            pcVar12 = "pthread_attr_init failed, errno = %d, errstr = %s\n";
            uVar7 = 0x1a98;
LAB_0015ebd0:
            uVar15 = imm_p2p_log_log(4,&DAT_0023571f,uVar7,pcVar12,iVar5,pcVar10);
          }
          lVar14 = *(long *)puVar3;
          srtp_shutdown(uVar15);
          mbedtls_ctr_drbg_free(lVar14 + 0xb2c8);
          mbedtls_entropy_free(lVar14 + 0xaf88);
        }
        else {
          memset(apStack_1058,0,0x800);
          mbedtls_strerror(iVar5,apStack_1058,0x800);
          imm_p2p_log_log(4,&DAT_0023571f,0x1a57,
                          "drbg seed failed! mbedtls_ctr_drbg_seed returned %d:%s\n",iVar5,
                          apStack_1058);
LAB_0015eb50:
          mbedtls_ctr_drbg_free(lVar9);
          mbedtls_entropy_free(lVar14);
          if (iVar5 == 0) goto LAB_0015eb64;
        }
        lVar14 = *(long *)puVar3;
        while (plVar11 = *(long **)(lVar14 + 0xa688), (long *)(lVar14 + 0xa688) != plVar11) {
          *(long *)plVar11[1] = *plVar11;
          *(long *)(*plVar11 + 8) = plVar11[1];
          free(plVar11);
        }
        plVar11 = *(long **)(lVar14 + 0x1030);
        while ((long *)(lVar14 + 0x1030) != plVar11) {
          *(long *)plVar11[1] = *plVar11;
          *(long *)(*plVar11 + 8) = plVar11[1];
          free(plVar11 + -0x12);
          plVar11 = *(long **)(lVar14 + 0x1030);
        }
        plVar11 = *(long **)(lVar14 + 0x43e0);
        while ((long *)(lVar14 + 0x43e0) != plVar11) {
          *(long *)plVar11[1] = *plVar11;
          *(long *)(*plVar11 + 8) = plVar11[1];
          FUN_0016913c(plVar11 + -0x669);
          plVar11 = *(long **)(lVar14 + 0x43e0);
        }
        lVar14 = *(long *)puVar3;
LAB_0015e9bc:
        FUN_0015f044(lVar14);
        lVar14 = *(long *)puVar3;
        plVar11 = (long *)(lVar14 + 0xa6c8);
        if (*(int *)(lVar14 + 0xa6d0) != -1) {
          close(*(int *)(lVar14 + 0xa6d0));
          *(undefined4 *)(lVar14 + 0xa6d0) = 0xffffffff;
        }
        if (*plVar11 != 0) {
          uv_handle_set_data(*plVar11,0);
          iVar5 = uv_is_closing(*plVar11);
          if (iVar5 == 0) {
            uv_close(*plVar11,PTR_imm_p2p_misc_release_uv_handle_00263df0);
          }
          *plVar11 = 0;
        }
        pthread_mutex_destroy((pthread_mutex_t *)(lVar14 + 0xaf58));
LAB_0015ea24:
        uVar7 = *(undefined8 *)puVar3;
        uv_timer_init(uVar7,apStack_1058);
        uv_timer_start(apStack_1058,FUN_0016788c,0,200);
        uv_run(uVar7,1);
        uv_loop_close(uVar7);
        goto LAB_0015ea60;
      }
      if (uVar15 < uVar6) goto LAB_0015e760;
      goto LAB_0015e740;
    }
LAB_0015ea60:
    free(*(void **)puVar3);
    *(undefined8 *)puVar3 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
    uVar7 = 0xffffffff;
  }
  else {
    if (*(int *)PTR_g_ctx_inited_00263ee8 == 0) {
      *(undefined4 *)PTR_g_ctx_inited_00263ee8 = 1;
      uVar13 = 0x643;
      if (*(int *)((long)param_1 + 0xb28) != 0) {
        uVar13 = 0x663;
      }
      *(undefined4 *)puVar4 = uVar13;
      memset(apStack_1058,0,0x1000);
      FUN_0015e3d0(apStack_1058,0x1000,0x1000,"{\"cmd\":\"reset\",\"args\":{\"local_id\":\"%s\"}}",
                   param_1);
      iVar5 = __strlen_chk(apStack_1058,0x1000);
      bc_msg_queue_push_back(*(undefined8 *)(*(long *)puVar3 + 0xf28),1,apStack_1058,iVar5 + 1);
      FUN_00162444(*(undefined8 *)puVar3);
      FUN_0015ee40(*(undefined8 *)puVar3);
    }
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
    uVar7 = 0;
  }
LAB_0015ea7c:
  if (*(long *)(lVar2 + 0x28) == local_58) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar7);
LAB_0015e760:
  uVar17 = 0x7d000;
  if (((uint)uVar15 | 2) != 3) {
    uVar17 = 0xc800;
  }
  lVar9 = lVar14 + uVar15 * 4;
  uVar1 = uVar17;
  if (uVar17 <= *(uint *)(lVar9 + 0x424)) {
    uVar1 = *(uint *)(lVar9 + 0x424);
  }
  if (uVar17 <= *(uint *)(lVar9 + 0x94c)) {
    uVar17 = *(uint *)(lVar9 + 0x94c);
  }
  if (0xc7fff < uVar1) {
    uVar1 = 0xc8000;
  }
  if (0xc7fff < uVar17) {
    uVar17 = 0xc8000;
  }
  *(uint *)(lVar9 + 0x424) = uVar1;
  *(uint *)(lVar9 + 0x94c) = uVar17;
  goto LAB_0015e74c;
}

