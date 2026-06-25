// send_data_real -> ghidra func send_data @ 001121e4

/* send_data(int, int, int, int, int) */

void send_data(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  long lVar2;
  undefined8 extraout_x1;
  pthread_t local_b8;
  int local_b0;
  undefined8 local_ac;
  undefined1 auStack_a4 [20];
  undefined1 auStack_90 [20];
  int local_7c;
  int iStack_78;
  int local_74;
  int iStack_70;
  int local_6c;
  long local_68;
  
  lVar2 = tpidr_el0;
  local_68 = *(long *)(lVar2 + 0x28);
  local_ac = DAT_0012b098;
  FUN_00112140(auStack_a4,param_2,"%s","255.255.255.255");
  FUN_00112140(auStack_90,extraout_x1,"%s","255.255.255.255");
  local_7c = param_1;
  iStack_78 = param_2;
  local_74 = param_3;
  iStack_70 = param_4;
  local_6c = param_5;
  local_b0 = socket(2,2,0);
  bVar1 = -1 < local_b0;
  if (bVar1) {
    pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
    *(undefined4 *)PTR_thing_quit_flag_00139fe0 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
    pthread_create(&local_b8,(pthread_attr_t *)0x0,(__start_routine *)PTR_send_data_thread_00139f30,
                   &local_b0);
    pthread_join(local_b8,(void **)0x0);
    close(local_b0);
  }
  if (*(long *)(lVar2 + 0x28) != local_68) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(bVar1);
  }
  return;
}

