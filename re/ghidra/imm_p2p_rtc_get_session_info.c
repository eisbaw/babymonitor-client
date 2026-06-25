// Ghidra decompilation of imm_p2p_rtc_get_session_info  (entry=00161754)

int imm_p2p_rtc_get_session_info(int param_1,int *param_2)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  pthread_mutex_t *__mutex_00;
  bool bVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar3 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar3 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1d15,"rtc session %08x get session info: sdk not inited\n",
                    param_1);
    return -1;
  }
  lVar4 = *(long *)PTR_g_ctx_00263e48;
  __mutex = (pthread_mutex_t *)(lVar4 + 0xa628);
  pthread_mutex_lock(__mutex);
  plVar1 = (long *)(lVar4 + 0x43e0);
  plVar5 = plVar1;
  do {
    plVar5 = (long *)*plVar5;
    if (plVar5 == plVar1) {
      pthread_mutex_unlock(__mutex);
      imm_p2p_log_log(4,&DAT_0023571f,0x1d1a,"rtc session %08x get session info: invalid session\n",
                      param_1);
      return -0xb;
    }
  } while (*(int *)(plVar5 + -0x669) != param_1);
  __mutex_00 = (pthread_mutex_t *)(plVar5 + -0x668);
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar5 + -0x3344) = *(int *)((long)plVar5 + -0x3344) + 1;
  pthread_mutex_unlock(__mutex_00);
  pthread_mutex_unlock(__mutex);
  iVar3 = -0x13;
  switch(*(undefined4 *)(plVar5 + 0x1a)) {
  case 0:
    if (*(int *)((long)plVar5 + 0xd4) == 0) {
      iVar3 = *(int *)(plVar5 + 0x1b);
      if (iVar3 == 0) goto LAB_00161910;
      goto LAB_001618a8;
    }
  case 4:
    iVar3 = -0xe;
    break;
  default:
    iVar3 = -3;
    break;
  case 3:
    break;
  case 5:
    iVar3 = *(int *)(plVar5 + 0x1b);
LAB_001618a8:
    iVar3 = -100 - iVar3;
    if (iVar3 == 0) {
LAB_00161910:
      param_2[0x78] = 0;
      param_2[0x79] = 0;
      param_2[0x72] = 0;
      param_2[0x73] = 0;
      param_2[0x70] = 0;
      param_2[0x71] = 0;
      param_2[0x76] = 0;
      param_2[0x77] = 0;
      param_2[0x74] = 0;
      param_2[0x75] = 0;
      param_2[0x6a] = 0;
      param_2[0x6b] = 0;
      param_2[0x68] = 0;
      param_2[0x69] = 0;
      param_2[0x6e] = 0;
      param_2[0x6f] = 0;
      param_2[0x6c] = 0;
      param_2[0x6d] = 0;
      param_2[0x62] = 0;
      param_2[99] = 0;
      param_2[0x60] = 0;
      param_2[0x61] = 0;
      param_2[0x66] = 0;
      param_2[0x67] = 0;
      param_2[100] = 0;
      param_2[0x65] = 0;
      param_2[0x5a] = 0;
      param_2[0x5b] = 0;
      param_2[0x58] = 0;
      param_2[0x59] = 0;
      param_2[0x5e] = 0;
      param_2[0x5f] = 0;
      param_2[0x5c] = 0;
      param_2[0x5d] = 0;
      param_2[0x52] = 0;
      param_2[0x53] = 0;
      param_2[0x50] = 0;
      param_2[0x51] = 0;
      param_2[0x56] = 0;
      param_2[0x57] = 0;
      param_2[0x54] = 0;
      param_2[0x55] = 0;
      param_2[0x4a] = 0;
      param_2[0x4b] = 0;
      param_2[0x48] = 0;
      param_2[0x49] = 0;
      param_2[0x4e] = 0;
      param_2[0x4f] = 0;
      param_2[0x4c] = 0;
      param_2[0x4d] = 0;
      param_2[0x42] = 0;
      param_2[0x43] = 0;
      param_2[0x40] = 0;
      param_2[0x41] = 0;
      param_2[0x46] = 0;
      param_2[0x47] = 0;
      param_2[0x44] = 0;
      param_2[0x45] = 0;
      param_2[0x3a] = 0;
      param_2[0x3b] = 0;
      param_2[0x38] = 0;
      param_2[0x39] = 0;
      param_2[0x3e] = 0;
      param_2[0x3f] = 0;
      param_2[0x3c] = 0;
      param_2[0x3d] = 0;
      param_2[0x32] = 0;
      param_2[0x33] = 0;
      param_2[0x30] = 0;
      param_2[0x31] = 0;
      param_2[0x36] = 0;
      param_2[0x37] = 0;
      param_2[0x34] = 0;
      param_2[0x35] = 0;
      param_2[0x2a] = 0;
      param_2[0x2b] = 0;
      param_2[0x28] = 0;
      param_2[0x29] = 0;
      param_2[0x2e] = 0;
      param_2[0x2f] = 0;
      param_2[0x2c] = 0;
      param_2[0x2d] = 0;
      param_2[0x22] = 0;
      param_2[0x23] = 0;
      param_2[0x20] = 0;
      param_2[0x21] = 0;
      param_2[0x26] = 0;
      param_2[0x27] = 0;
      param_2[0x24] = 0;
      param_2[0x25] = 0;
      param_2[0x1a] = 0;
      param_2[0x1b] = 0;
      param_2[0x18] = 0;
      param_2[0x19] = 0;
      param_2[0x1e] = 0;
      param_2[0x1f] = 0;
      param_2[0x1c] = 0;
      param_2[0x1d] = 0;
      param_2[0x12] = 0;
      param_2[0x13] = 0;
      param_2[0x10] = 0;
      param_2[0x11] = 0;
      param_2[0x16] = 0;
      param_2[0x17] = 0;
      param_2[0x14] = 0;
      param_2[0x15] = 0;
      param_2[10] = 0;
      param_2[0xb] = 0;
      param_2[8] = 0;
      param_2[9] = 0;
      param_2[0xe] = 0;
      param_2[0xf] = 0;
      param_2[0xc] = 0;
      param_2[0xd] = 0;
      param_2[2] = 0;
      param_2[3] = 0;
      param_2[0] = 0;
      param_2[1] = 0;
      param_2[6] = 0;
      param_2[7] = 0;
      param_2[4] = 0;
      param_2[5] = 0;
      *param_2 = *(int *)(plVar5 + -0x669);
      param_2[2] = *(int *)(plVar5 + -0x4a6);
      bVar2 = *(int *)((long)plVar5 + -0x24f4) == 0;
      if (bVar2) {
        param_2[1] = *(int *)(plVar5 + -0x49f);
        param_2[3] = *(int *)((long)plVar5 + 0x34);
      }
      param_2[4] = (uint)!bVar2;
      FUN_0015e3d0(param_2 + 5,0x40,0x40,&DAT_0021893f);
      *(undefined8 *)(param_2 + 0x15) = DAT_00216ec0;
      FUN_0015e3d0(param_2 + 0x17,0x40,0x40,&DAT_00218944);
      param_2[0x27] = 90000;
      FUN_0015e3d0(param_2 + 0x28,0x80,0x80,"%s",(long)plVar5 + -0x232c);
      FUN_0015e3d0(param_2 + 0x48,0x40,0x40,"%s",(long)plVar5 + -0x24ac);
      FUN_0015e3d0(param_2 + 0x58,0x40,0x40,"%s",(long)plVar5 + -0x23ac);
      param_2[0x68] = *(int *)(plVar5 + -0x425);
      FUN_0015e3d0(param_2 + 0x6a,0x20,0x20,"%s",plVar5 + -0x424);
      FUN_0015e3d0(param_2 + 0x72,0xffffffffffffffff,0x20,"%s",plVar5 + -0x420);
      param_2[0x69] = *(int *)((long)plVar5 + -0x2124);
      pthread_mutex_lock(__mutex_00);
      *(int *)((long)plVar5 + -0x3344) = *(int *)((long)plVar5 + -0x3344) + -1;
      pthread_mutex_unlock(__mutex_00);
      return 0;
    }
    break;
  case 0xb:
    iVar3 = -0x29;
    break;
  case 0xc:
    iVar3 = -0x17;
    break;
  case 0x10:
    iVar3 = -0x1f;
    break;
  case 0x11:
    iVar3 = -0x1e;
  }
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar5 + -0x3344) = *(int *)((long)plVar5 + -0x3344) + -1;
  pthread_mutex_unlock(__mutex_00);
  return iVar3;
}

