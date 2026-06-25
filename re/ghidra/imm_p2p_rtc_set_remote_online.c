// Ghidra decompilation of imm_p2p_rtc_set_remote_online  (entry=00163c48)

void imm_p2p_rtc_set_remote_online(undefined8 param_1)

{
  int iVar1;
  long lVar2;
  undefined *puVar3;
  undefined8 uVar4;
  undefined1 auStack_448 [1024];
  long local_48;
  
  lVar2 = tpidr_el0;
  local_48 = *(long *)(lVar2 + 0x28);
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar1 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar1 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1fbc,"set remote online: sdk not inited\n");
    uVar4 = 0xffffffff;
  }
  else {
    imm_p2p_log_log(2,&DAT_0023571f,0x1fc0,"set remote online: %s\n",param_1);
    memset(auStack_448,0,0x400);
    FUN_0015e3d0(auStack_448,0x400,0x400,
                 "{\"cmd\":\"set_remote_online\",\"args\":{\"remote_id\":\"%s\"}}",param_1);
    uVar4 = __strlen_chk(auStack_448,0x400);
    puVar3 = PTR_g_ctx_00263e48;
    bc_msg_queue_push_back(*(undefined8 *)(*(long *)PTR_g_ctx_00263e48 + 0xf28),1,auStack_448,uVar4)
    ;
    FUN_00162444(*(undefined8 *)puVar3);
    uVar4 = 0;
  }
  if (*(long *)(lVar2 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar4);
}

