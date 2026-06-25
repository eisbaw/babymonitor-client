// Ghidra decompilation of imm_p2p_rtc_send_frame  (entry=001626b8)

int imm_p2p_rtc_send_frame(int param_1,undefined8 *param_2)

{
  pthread_mutex_t *__mutex;
  long *plVar1;
  pthread_mutex_t *__mutex_00;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  char *pcVar7;
  ulong uVar8;
  long lVar9;
  long *plVar10;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0026cba4);
  iVar5 = *(int *)PTR_g_ctx_inited_00263ee8;
  pthread_mutex_unlock((pthread_mutex_t *)&DAT_0026cba4);
  if (iVar5 == 0) {
    imm_p2p_log_log(4,&DAT_0023571f,0x1de8,"rtc session %08x send frame: sdk not inited\n",param_1);
    return -1;
  }
  lVar9 = *(long *)PTR_g_ctx_00263e48;
  __mutex = (pthread_mutex_t *)(lVar9 + 0xa628);
  pthread_mutex_lock(__mutex);
  plVar1 = (long *)(lVar9 + 0x43e0);
  plVar10 = plVar1;
  do {
    plVar10 = (long *)*plVar10;
    if (plVar10 == plVar1) {
      pthread_mutex_unlock(__mutex);
      uVar6 = 0x1ded;
      goto LAB_001627f8;
    }
  } while (*(int *)(plVar10 + -0x669) != param_1);
  __mutex_00 = (pthread_mutex_t *)(plVar10 + -0x668);
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar10 + -0x3344) = *(int *)((long)plVar10 + -0x3344) + 1;
  pthread_mutex_unlock(__mutex_00);
  pthread_mutex_unlock(__mutex);
  iVar5 = -0x13;
  switch(*(undefined4 *)(plVar10 + 0x1a)) {
  case 0:
    if (*(int *)((long)plVar10 + 0xd4) == 0) {
      iVar5 = *(int *)(plVar10 + 0x1b);
      if (iVar5 != 0) goto LAB_00162814;
      goto LAB_00162880;
    }
  case 4:
    iVar5 = -0xe;
    break;
  default:
    iVar5 = -3;
    break;
  case 3:
    break;
  case 5:
    iVar5 = *(int *)(plVar10 + 0x1b);
LAB_00162814:
    iVar5 = -100 - iVar5;
    if (iVar5 != 0) break;
LAB_00162880:
    if (*(int *)((long)plVar10 + -0x24f4) == 0) {
      pthread_mutex_lock(__mutex_00);
      *(int *)((long)plVar10 + -0x3344) = *(int *)((long)plVar10 + -0x3344) + -1;
      pthread_mutex_unlock(__mutex_00);
      uVar6 = 0x1df7;
LAB_001627f8:
      imm_p2p_log_log(4,&DAT_0023571f,uVar6,"rtc session %08x send frame: invalid session\n",param_1
                     );
      return -0xb;
    }
    imm_p2p_log_log(0,&DAT_0023571f,0x1dfb,
                    "user try to push a frame, type = %d, len = %d, pts: %llu\n",
                    *(undefined4 *)(param_2 + 4),*(undefined4 *)((long)param_2 + 0xc),param_2[2]);
    iVar2 = *(int *)(param_2 + 4);
    iVar5 = *(int *)((long)param_2 + 0xc);
    if (iVar2 == 0) {
      if (plVar10[0xc3a] == 0) {
        uVar6 = imm_p2p_misc_get_timestamp_ms();
        plVar10[0xc3a] = uVar6;
        iVar5 = rand();
        plVar10[0x30] = (long)iVar5;
        iVar5 = *(int *)((long)param_2 + 0xc);
      }
      *(int *)(plVar10 + 0xc36) = *(int *)(plVar10 + 0xc36) + 1;
      *(int *)((long)plVar10 + 0x61c4) = *(int *)((long)plVar10 + 0x61c4) + iVar5;
      lVar9 = imm_p2p_memory_pool_allocate(*(undefined8 *)(plVar10[0xa2a] + 0x48));
      if (lVar9 == 0) {
        pcVar7 = "allocate audio frame packet failed\n";
        uVar6 = 0x1e06;
        goto LAB_00162a9c;
      }
      *(undefined8 *)(lVar9 + 0x30) = 0;
      uVar3 = **(uint **)(plVar10[0xa2a] + 0x48);
      *(undefined8 *)(lVar9 + 0x18) = DAT_002154f8;
      uVar6 = DAT_00215678;
      *(uint *)(lVar9 + 0x10) = uVar3;
      uVar4 = *(uint *)((long)param_2 + 0xc);
      *(undefined8 *)(lVar9 + 0x24) = uVar6;
      *(uint *)(lVar9 + 0x20) = uVar4;
      *(uint *)(lVar9 + 0x14) = uVar4 + 0xc;
      uVar8 = plVar10[0x30];
      *(ulong *)(lVar9 + 0x38) = (uVar8 & 0x1fffffffffffffff) / 0x7d;
      plVar10[0x30] = uVar8 + uVar4 * 0x7d;
      if (uVar3 < uVar4 + 0xc) {
        imm_p2p_memory_pool_free(lVar9);
        iVar5 = 0;
        break;
      }
      memcpy((void *)(lVar9 + 0x54),(void *)*param_2,(ulong)uVar4);
      iVar5 = imm_p2p_rtc_audio_frame_list_push_back(plVar10[0xa2a],lVar9);
      if (-1 < iVar5) break;
      imm_p2p_memory_pool_free(lVar9);
    }
    else {
      if (plVar10[0xc3f] == 0) {
        *(undefined4 *)(plVar10 + 0xc45) = 1;
LAB_001629ec:
        if (iVar2 != 2) break;
        *(undefined4 *)(plVar10 + 0xc45) = 0;
        if (plVar10[0xc3f] == 0) {
          uVar6 = imm_p2p_misc_get_timestamp_ms();
          plVar10[0xc3f] = uVar6;
          iVar5 = *(int *)((long)param_2 + 0xc);
        }
      }
      else if (*(int *)(plVar10 + 0xc45) != 0) goto LAB_001629ec;
      *(int *)(plVar10 + 0xc3b) = *(int *)(plVar10 + 0xc3b) + 1;
      *(int *)((long)plVar10 + 0x61ec) = *(int *)((long)plVar10 + 0x61ec) + iVar5;
      lVar9 = imm_p2p_rtc_packetized_frame_create(*(undefined8 *)(plVar10[0xa28] + 0x40),param_2);
      if (lVar9 == 0) {
        *(undefined4 *)(plVar10 + 0xc45) = 1;
        pcVar7 = "packetize frame failed\n";
        uVar6 = 0x1e35;
LAB_00162a9c:
        imm_p2p_log_log(1,&DAT_0023571f,uVar6,pcVar7);
        iVar5 = 0;
        break;
      }
      iVar5 = imm_p2p_rtc_frame_list_push_back(plVar10[0xa28],lVar9);
      if (-1 < iVar5) break;
      imm_p2p_rtc_packetized_frame_destroy(0,lVar9);
    }
    iVar5 = -0xd;
    break;
  case 0xb:
    iVar5 = -0x29;
    break;
  case 0xc:
    iVar5 = -0x17;
    break;
  case 0x10:
    iVar5 = -0x1f;
    break;
  case 0x11:
    iVar5 = -0x1e;
  }
  pthread_mutex_lock(__mutex_00);
  *(int *)((long)plVar10 + -0x3344) = *(int *)((long)plVar10 + -0x3344) + -1;
  pthread_mutex_unlock(__mutex_00);
  return iVar5;
}

