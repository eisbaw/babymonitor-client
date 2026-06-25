// Ghidra decompilation of imm_p2p_rtc_frame_list_get_current_frame  (entry=0014fc54)

long imm_p2p_rtc_frame_list_get_current_frame(long param_1)

{
  long lVar1;
  
  if (param_1 != 0) {
    lVar1 = param_1 + 0x18;
    uv_mutex_lock(lVar1);
    param_1 = *(long *)(param_1 + 0x10);
    uv_mutex_unlock(lVar1);
  }
  return param_1;
}

