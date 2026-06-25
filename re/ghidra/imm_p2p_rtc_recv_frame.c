// Ghidra decompilation of imm_p2p_rtc_recv_frame  (entry=00162ad8)

int imm_p2p_rtc_recv_frame(int param_1,long *param_2)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  pthread_mutex_t *__mutex_00;
  uint uVar2;
  int iVar3;
  ulong uVar4;
  undefined8 uVar5;
  long lVar6;
  long *plVar7;
  long local_48;
  
  if (((param_2 == (long *)0x0) || (*param_2 == 0)) || ((int)param_2[1] == 0)) {
    return 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar3 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar3 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1e4b,"rtc session %08x recv frame: sdk not inited\n",param_1);
    return -1;
  }
  lVar6 = *(long *)PTR_g_ctx_00263e48;
  __mutex = (pthread_mutex_t *)(lVar6 + 0xa628);
  pthread_mutex_lock(__mutex);
  plVar1 = (long *)(lVar6 + 0x43e0);
  plVar7 = plVar1;
  do {
    plVar7 = (long *)*plVar7;
    if (plVar7 == plVar1) {
      pthread_mutex_unlock(__mutex);
      uVar5 = 0x1e50;
      goto LAB_00162c4c;
    }
  } while (*(int *)(plVar7 + -0x669) != param_1);
  __mutex_00 = (pthread_mutex_t *)(plVar7 + -0x668);
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar7 + -0x3344) = *(int *)((long)plVar7 + -0x3344) + 1;
  pthread_mutex_unlock(__mutex_00);
  pthread_mutex_unlock(__mutex);
  iVar3 = -0x13;
  switch(*(undefined4 *)(plVar7 + 0x1a)) {
  case 0:
    if (*(int *)((long)plVar7 + 0xd4) == 0) {
      iVar3 = *(int *)(plVar7 + 0x1b);
      if (iVar3 != 0) goto LAB_00162c68;
      goto LAB_00162cbc;
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
    iVar3 = *(int *)(plVar7 + 0x1b);
LAB_00162c68:
    iVar3 = -100 - iVar3;
    if (iVar3 != 0) break;
LAB_00162cbc:
    if (*(int *)((long)plVar7 + -0x24f4) == 0) {
      pthread_mutex_lock(__mutex_00);
      *(int *)((long)plVar7 + -0x3344) = *(int *)((long)plVar7 + -0x3344) + -1;
      pthread_mutex_unlock(__mutex_00);
      uVar5 = 0x1e5a;
LAB_00162c4c:
      imm_p2p_log_log(4,&DAT_0023571f,uVar5,"rtc session %08x recv frame: invalid session\n",param_1
                     );
      return -0xb;
    }
    *(undefined4 *)((long)param_2 + 0xc) = 0;
    local_48 = 0;
    iVar3 = imm_p2p_rtc_audio_frame_list_pop_front(plVar7[0xa29],&local_48);
    if (iVar3 < 0) {
      iVar3 = -0xd;
    }
    else if (local_48 == 0) {
      iVar3 = 0;
    }
    else {
      uVar2 = *(uint *)(param_2 + 1);
      if (*(uint *)(local_48 + 0x20) <= *(uint *)(param_2 + 1)) {
        uVar2 = *(uint *)(local_48 + 0x20);
      }
      memcpy((void *)*param_2,
             (void *)(local_48 + (ulong)*(uint *)(local_48 + 0x18) +
                      (ulong)*(uint *)(local_48 + 0x1c) + 0x48),(long)(int)uVar2);
      *(uint *)((long)param_2 + 0xc) = uVar2;
      *(undefined4 *)(param_2 + 4) = 0;
      uVar4 = imm_p2p_rtp_get_timestamp(local_48 + 0x48);
      uVar4 = uVar4 >> 3 & 0x1fffffff;
      param_2[2] = uVar4;
      param_2[3] = uVar4;
      imm_p2p_memory_pool_free(local_48);
      *(int *)(plVar7 + 0xc46) = *(int *)(plVar7 + 0xc46) + 1;
      iVar3 = *(int *)((long)param_2 + 0xc);
      *(int *)(plVar7 + 0xc47) = *(int *)(plVar7 + 0xc47) + iVar3;
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
  *(int *)((long)plVar7 + -0x3344) = *(int *)((long)plVar7 + -0x3344) + -1;
  pthread_mutex_unlock(__mutex_00);
  return iVar3;
}

