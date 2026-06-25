// Ghidra decompilation of imm_p2p_rtc_recv_data  (entry=0016340c)

int imm_p2p_rtc_recv_data
              (int param_1,uint param_2,undefined8 param_3,undefined4 *param_4,undefined4 param_5)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  pthread_mutex_t *__mutex_00;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  long lVar5;
  long *plVar6;
  
  uVar2 = *param_4;
  *param_4 = 0;
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar3 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar3 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1f5e,"rtc session %08x recv data: sdk not inited\n",param_1);
    return -1;
  }
  lVar5 = *(long *)PTR_g_ctx_00263e48;
  __mutex = (pthread_mutex_t *)(lVar5 + 0xa628);
  pthread_mutex_lock(__mutex);
  plVar1 = (long *)(lVar5 + 0x43e0);
  plVar6 = plVar1;
  do {
    plVar6 = (long *)*plVar6;
    if (plVar6 == plVar1) {
      pthread_mutex_unlock(__mutex);
      uVar4 = 0x1f63;
      goto LAB_00163560;
    }
  } while (*(int *)(plVar6 + -0x669) != param_1);
  __mutex_00 = (pthread_mutex_t *)(plVar6 + -0x668);
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar6 + -0x3344) = *(int *)((long)plVar6 + -0x3344) + 1;
  pthread_mutex_unlock(__mutex_00);
  pthread_mutex_unlock(__mutex);
  iVar3 = -0x13;
  switch(*(undefined4 *)(plVar6 + 0x1a)) {
  case 0:
    if (*(int *)((long)plVar6 + 0xd4) == 0) {
      iVar3 = *(int *)(plVar6 + 0x1b);
      if (iVar3 == 0) goto LAB_001635ec;
      goto LAB_0016357c;
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
    iVar3 = *(int *)(plVar6 + 0x1b);
LAB_0016357c:
    iVar3 = -100 - iVar3;
    if (iVar3 == 0) {
LAB_001635ec:
      if (*(int *)((long)plVar6 + -0x24f4) == 0) {
        if (*(uint *)((long)plVar6 + -0x212c) <= param_2) {
          imm_p2p_log_log(4,&DAT_0023571f,0x1f72,
                          "rtc session %08x recv data: invalid channel number: %d/%d\n",param_1,
                          param_2);
          pthread_mutex_lock(__mutex_00);
          *(int *)((long)plVar6 + -0x3344) = *(int *)((long)plVar6 + -0x3344) + -1;
          pthread_mutex_unlock(__mutex_00);
          return -5;
        }
        *param_4 = uVar2;
        iVar3 = FUN_001636c4(plVar6 + -0x669,param_2,param_3,param_4,param_5);
        pthread_mutex_lock(__mutex_00);
        *(int *)((long)plVar6 + -0x3344) = *(int *)((long)plVar6 + -0x3344) + -1;
        pthread_mutex_unlock(__mutex_00);
        return iVar3;
      }
      pthread_mutex_lock(__mutex_00);
      *(int *)((long)plVar6 + -0x3344) = *(int *)((long)plVar6 + -0x3344) + -1;
      pthread_mutex_unlock(__mutex_00);
      uVar4 = 0x1f6d;
LAB_00163560:
      imm_p2p_log_log(4,&DAT_0023571f,uVar4,"rtc session %08x recv data: invalid session\n",param_1)
      ;
      return -0xb;
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
  *(int *)((long)plVar6 + -0x3344) = *(int *)((long)plVar6 + -0x3344) + -1;
  pthread_mutex_unlock(__mutex_00);
  return iVar3;
}

