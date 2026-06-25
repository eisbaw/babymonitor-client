// Ghidra decompilation of imm_p2p_rtc_set_signaling  (entry=00161f8c)

undefined8 imm_p2p_rtc_set_signaling(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar1 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar1 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1d88,"set signaling: sdk not inited\n");
    uVar2 = 0xffffffff;
  }
  else {
    FUN_00162020(param_2,param_3);
    FUN_00162444(*(undefined8 *)PTR_g_ctx_00263e48);
    uVar2 = 0;
  }
  return uVar2;
}

