// send_data_thread_real -> ghidra func send_data_thread @ 001119ac

/* send_data_thread(void*) */

undefined8 send_data_thread(void *param_1)

{
  char *__cp;
  short sVar1;
  int iVar2;
  long lVar3;
  undefined *puVar4;
  undefined *puVar5;
  bool bVar6;
  int iVar7;
  in_addr_t iVar8;
  int iVar9;
  long lVar10;
  int iVar11;
  ulong uVar12;
  int iVar13;
  int iVar14;
  ulong uVar15;
  int local_4b8;
  int local_4b4;
  undefined4 local_4a4;
  timeval local_4a0;
  undefined1 auStack_490 [1024];
  sockaddr local_90;
  sockaddr local_80;
  long local_70;
  
  lVar3 = tpidr_el0;
  local_70 = *(long *)(lVar3 + 0x28);
  __cp = (char *)((long)param_1 + 0x20);
  local_80.sa_data[6] = '\0';
  local_80.sa_data[7] = '\0';
  local_80.sa_data[8] = '\0';
  local_80.sa_data[9] = '\0';
  local_80.sa_data[10] = '\0';
  local_80.sa_data[0xb] = '\0';
  local_80.sa_data[0xc] = '\0';
  local_80.sa_data[0xd] = '\0';
  local_80.sa_family = 2;
  local_80.sa_data._0_2_ = *(ushort *)((long)param_1 + 8) >> 8 | *(ushort *)((long)param_1 + 8) << 8
  ;
  local_80.sa_data._2_4_ = inet_addr(__cp);
  local_4a4 = 1;
                    /* WARNING: Load size is inaccurate */
  iVar7 = setsockopt(*param_1,1,6,&local_4a4,4);
  if (-1 < iVar7) {
    local_90.sa_data[10] = '\0';
    local_90.sa_data[0xb] = '\0';
    local_90.sa_data[0xc] = '\0';
    local_90.sa_data[0xd] = '\0';
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    local_90.sa_data[6] = '\0';
    local_90.sa_data[7] = '\0';
    local_90.sa_data[8] = '\0';
    local_90.sa_data[9] = '\0';
    local_90.sa_family = 2;
    local_90.sa_data._0_2_ =
         *(ushort *)((long)param_1 + 4) >> 8 | *(ushort *)((long)param_1 + 4) << 8;
    iVar8 = inet_addr((char *)((long)param_1 + 0xc));
    local_90.sa_data._2_4_ = iVar8;
    memset(auStack_490,0,0x400);
    puVar5 = PTR_thing_quit_flag_00139fe0;
    puVar4 = PTR_multicast_link_info_00139f58;
    local_4b8 = 0;
    do {
      iVar9 = *(int *)((long)param_1 + 0x40);
      iVar11 = *(int *)((long)param_1 + 0x44);
      iVar13 = *(int *)((long)param_1 + 0x3c);
      iVar7 = iVar9 * 3 + iVar11 * 4;
      iVar14 = 7;
      if (iVar7 != 0) {
        iVar14 = iVar7;
      }
      iVar2 = 0;
      if (iVar14 != 0) {
        iVar2 = iVar13 / iVar14;
      }
      if (-1 < iVar2) {
        local_4b4 = 0;
        while( true ) {
          if (0 < iVar9) {
            iVar14 = 0;
            do {
              FUN_00112140(__cp);
              local_80.sa_data._2_4_ = inet_addr(__cp);
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,1,0,&local_80,0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
              FUN_00112140(__cp);
              local_80.sa_data._2_4_ = inet_addr(__cp);
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,1,0,&local_80,0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
              FUN_00112140(__cp);
              local_80.sa_data._2_4_ = inet_addr(__cp);
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,1,0,&local_80,0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
              iVar14 = iVar14 + 1;
            } while (iVar14 < *(int *)((long)param_1 + 0x40));
          }
          if (0 < *(int *)((long)param_1 + 0x44)) {
            iVar14 = 0;
            do {
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,(ulong)**(ushort **)PTR_broadcast_link_info_00139f28,0,
                     &local_90,0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,
                     (ulong)*(ushort *)(*(long *)PTR_broadcast_link_info_00139f28 + 2),0,&local_90,
                     0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,
                     (ulong)*(ushort *)(*(long *)PTR_broadcast_link_info_00139f28 + 4),0,&local_90,
                     0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
                    /* WARNING: Load size is inaccurate */
              sendto(*param_1,auStack_490,
                     (ulong)*(ushort *)(*(long *)PTR_broadcast_link_info_00139f28 + 6),0,&local_90,
                     0x10);
              local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000);
              local_4a0.tv_sec = 0;
              select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
              pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
              iVar9 = *(int *)puVar5;
              iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
              if (iVar9 == 1) goto LAB_00112108;
              iVar14 = iVar14 + 1;
            } while (iVar14 < *(int *)((long)param_1 + 0x44));
          }
          pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
          iVar14 = *(int *)puVar5;
          iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
          if (iVar14 == 1) goto LAB_00112108;
          if (local_4b4 == iVar2) break;
          iVar9 = *(int *)((long)param_1 + 0x40);
          local_4b4 = local_4b4 + 1;
        }
        iVar13 = *(int *)((long)param_1 + 0x3c);
        iVar9 = *(int *)((long)param_1 + 0x40);
        iVar11 = *(int *)((long)param_1 + 0x44);
      }
      iVar14 = 0;
      iVar7 = (int)((ulong)(*(long *)(*(long *)puVar4 + 0x30) - *(long *)(*(long *)puVar4 + 0x28))
                   >> 2) * -0x55555555;
      iVar9 = iVar9 * iVar7 +
              iVar11 * (uint)*(ushort *)(*(long *)PTR_broadcast_link_info_00139f28 + 0x10);
      iVar7 = (uint)*(ushort *)(*(long *)PTR_broadcast_link_info_00139f28 + 0x10) + iVar7;
      if (iVar9 != 0) {
        iVar7 = iVar9;
      }
      iVar9 = 0;
      if (iVar7 != 0) {
        iVar9 = iVar13 / iVar7;
      }
      do {
        if (-1 < iVar9) {
          iVar13 = 0;
          do {
            iVar7 = *(int *)((long)param_1 + 0x40);
            if (0 < iVar7) {
              lVar10 = *(long *)puVar4;
              iVar11 = 0;
              do {
                if (*(long *)(lVar10 + 0x30) != *(long *)(lVar10 + 0x28)) {
                  uVar15 = 0;
                  do {
                    FUN_00112140(__cp);
                    local_80.sa_data._2_4_ = inet_addr(__cp);
                    /* WARNING: Load size is inaccurate */
                    sendto(*param_1,auStack_490,1,0,&local_80,0x10);
                    local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000)
                    ;
                    local_4a0.tv_sec = 0;
                    select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
                    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
                    iVar2 = *(int *)puVar5;
                    iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
                    if (iVar2 == 1) goto LAB_00112108;
                    lVar10 = *(long *)puVar4;
                    uVar15 = uVar15 + 1;
                    uVar12 = (*(long *)(lVar10 + 0x30) - *(long *)(lVar10 + 0x28) >> 2) *
                             -0x5555555555555555;
                  } while (uVar15 <= uVar12 && uVar12 - uVar15 != 0);
                  iVar7 = *(int *)((long)param_1 + 0x40);
                }
                iVar11 = iVar11 + 1;
              } while (iVar11 < iVar7);
            }
            iVar7 = *(int *)((long)param_1 + 0x44);
            if (0 < iVar7) {
              iVar11 = 0;
              lVar10 = *(long *)PTR_broadcast_link_info_00139f28;
              sVar1 = *(short *)(lVar10 + 0x10);
              while( true ) {
                if (sVar1 != 0) {
                  uVar15 = 0;
                  do {
                    /* WARNING: Load size is inaccurate */
                    sendto(*param_1,auStack_490,
                           (ulong)*(ushort *)(*(long *)(lVar10 + 8) + uVar15 * 2),0,&local_90,0x10);
                    local_4a0.tv_usec = (__suseconds_t)(uint)(*(int *)((long)param_1 + 0x34) * 1000)
                    ;
                    local_4a0.tv_sec = 0;
                    select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
                    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
                    iVar2 = *(int *)puVar5;
                    iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
                    if (iVar2 == 1) goto LAB_00112108;
                    uVar15 = uVar15 + 1;
                    lVar10 = *(long *)PTR_broadcast_link_info_00139f28;
                  } while (uVar15 < *(ushort *)(lVar10 + 0x10));
                  iVar7 = *(int *)((long)param_1 + 0x44);
                }
                iVar11 = iVar11 + 1;
                if (iVar7 <= iVar11) break;
                sVar1 = *(short *)(lVar10 + 0x10);
              }
            }
            pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
            iVar11 = *(int *)puVar5;
            iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
            if (iVar11 == 1) goto LAB_00112108;
            bVar6 = iVar13 != iVar9;
            iVar13 = iVar13 + 1;
          } while (bVar6);
        }
        local_4a0.tv_sec = (__time_t)*(uint *)((long)param_1 + 0x38);
        local_4a0.tv_usec = 0;
        select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_4a0);
        pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
        iVar13 = *(int *)puVar5;
        iVar7 = pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
        if (iVar13 == 1) goto LAB_00112108;
        iVar14 = iVar14 + 1;
      } while (iVar14 != 5);
      local_4b8 = local_4b8 + 1;
    } while (local_4b8 != 2);
  }
LAB_00112108:
  if (*(long *)(lVar3 + 0x28) != local_70) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(iVar7);
  }
  return 0;
}

