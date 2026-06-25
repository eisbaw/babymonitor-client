// Ghidra decompilation of imm_p2p_rtc_connect_v2  (entry=00160c10)

int imm_p2p_rtc_connect_v2
              (char *param_1,char *param_2,char *param_3,int param_4,char *param_5,int param_6,
              char *param_7,undefined4 param_8,int param_9)

{
  long lVar1;
  undefined *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  ulong uVar6;
  size_t sVar7;
  int local_1150;
  int local_114c;
  undefined1 auStack_10b0 [4096];
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  long local_70;
  
  lVar1 = tpidr_el0;
  local_70 = *(long *)(lVar1 + 0x28);
  if (param_9 < 0x3e9) {
    param_9 = 1000;
  }
  if (29999 < param_9) {
    param_9 = 30000;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar4 = *(int *)PTR_g_ctx_inited_00263ee8;
  uVar3 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  uVar6 = (ulong)uVar3;
  if (iVar4 == 0) {
    uVar6 = imm_p2p_log_log(4,&DAT_0023571f,0x1c67,"connect_v2: sdk not inited\n");
    local_1150 = -1;
  }
  else if ((param_1 == (char *)0x0) || (uVar6 = strlen(param_1), uVar6 == 0)) {
    local_1150 = -5;
  }
  else {
    if (((param_3 == (char *)0x0) || (sVar7 = strlen(param_3), param_4 == 0)) || (sVar7 == 0)) {
      param_3 = "{}";
      param_4 = __strlen_chk(&DAT_002171e6,3);
    }
    if (((param_5 == (char *)0x0) || (sVar7 = strlen(param_5), param_6 == 0)) || (sVar7 == 0)) {
      param_5 = "{}";
      param_6 = __strlen_chk(&DAT_002171e6,3);
    }
    if ((param_7 == (char *)0x0) || (sVar7 = strlen(param_7), sVar7 == 0)) {
      param_7 = "";
    }
    if ((param_2 == (char *)0x0) || (sVar7 = strlen(param_2), sVar7 == 0)) {
      param_2 = param_1;
    }
    iVar4 = imm_p2p_misc_get_timestamp_ms();
    imm_p2p_log_log(2,&DAT_0023571f,0x1c7e,"try connect to %s, token: %.*s\n",param_1,param_6,
                    param_5);
    uStack_88 = 0;
    local_90 = 0;
    uStack_78 = 0;
    uStack_80 = 0;
    uStack_a8 = 0;
    local_b0 = 0;
    uStack_98 = 0;
    uStack_a0 = 0;
    imm_p2p_misc_rand_string(&local_b0,0x21);
    memset(auStack_10b0,0,0x1000);
    FUN_0015e3d0(auStack_10b0,0x1000,0x1000,
                 "{\"cmd\":\"connect_v2\",\"args\":{\"remote_id\":\"%s\",\"dev_id\":\"%s\",\"skill\":%.*s,\"token\":%.*s,\"trace_id\":\"%s\",\"timeout_ms\":%d,\"lan_mode\":%d,\"preconnect_enable\":1,\"connect_session\":\"%s\"}}"
                 ,param_1,param_2,param_4,param_3,param_6,param_5,param_7,param_9,param_8,&local_b0)
    ;
    iVar5 = __strlen_chk(auStack_10b0,0x1000);
    puVar2 = PTR_g_ctx_00263e48;
    bc_msg_queue_push_back
              (*(undefined8 *)(*(long *)PTR_g_ctx_00263e48 + 0xf28),1,auStack_10b0,iVar5 + 1);
    FUN_00162444(*(undefined8 *)puVar2);
    FUN_0016011c(*(undefined8 *)puVar2,&local_b0,&local_1150);
    iVar5 = imm_p2p_misc_get_timestamp_ms();
    FUN_00160208(*(undefined8 *)puVar2,"connect_v2",param_1,param_2,param_7,iVar5 - iVar4,local_114c
                );
    iVar4 = local_114c;
    if (local_114c == 0) {
      uVar6 = imm_p2p_log_log(2,&DAT_0023571f,0x1c95,"connect to %s result %08x\n",param_1,
                              local_1150);
    }
    else {
      imm_p2p_rtc_close(local_1150,0);
      uVar6 = imm_p2p_log_log(3,&DAT_0023571f,0x1c92,"connect to %s error %d\n",param_1,local_114c);
      local_1150 = iVar4;
    }
  }
  if (*(long *)(lVar1 + 0x28) == local_70) {
    return local_1150;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar6);
}

