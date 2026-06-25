// thing_smart_link_real -> ghidra func thing_smart_link @ 001123c8

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4
thing_smart_link(char *param_1,char *param_2,char *param_3,int param_4,int param_5,int param_6,
                int param_7,int param_8)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined *puVar5;
  undefined4 uVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  
  pthread_mutex_lock((pthread_mutex_t *)&DAT_0013a250);
  puVar5 = PTR_thing_release_flag_00139ef8;
  if ((*(int *)PTR_thing_quit_flag_00139fe0 == 0) || (*PTR_thing_release_flag_00139ef8 == '\0')) {
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
    uVar6 = 0xffffffff;
  }
  else {
    *(undefined4 *)PTR_thing_quit_flag_00139fe0 = 0;
    *puVar5 = 0;
    pthread_mutex_unlock((pthread_mutex_t *)&DAT_0013a250);
    puVar7 = (undefined8 *)malloc(0x18);
    *(undefined8 **)PTR_broadcast_link_info_00139f28 = puVar7;
    puVar8 = (undefined8 *)malloc(0x40);
    puVar5 = PTR_multicast_link_info_00139f58;
    uVar1 = DAT_0012b090;
    *(undefined8 **)PTR_multicast_link_info_00139f58 = puVar8;
    puVar8[1] = 0;
    *puVar8 = 0;
    puVar8[3] = 0;
    puVar8[2] = 0;
    puVar8[5] = 0;
    puVar8[4] = 0;
    puVar8[7] = 0;
    puVar8[6] = 0;
    puVar7[1] = 0;
    puVar7[2] = 0;
    *puVar7 = uVar1;
    broadcast_body_encode(param_1,param_2,param_3);
    uVar4 = _UNK_0012b0b8;
    uVar3 = _DAT_0012b0b0;
    uVar2 = _UNK_0012b0a8;
    uVar1 = _DAT_0012b0a0;
    puVar7 = *(undefined8 **)puVar5;
    *(undefined4 *)(puVar7 + 4) = 0x30;
    puVar7[1] = uVar2;
    *puVar7 = uVar1;
    puVar7[3] = uVar4;
    puVar7[2] = uVar3;
    multicast_body_encode(param_1,param_2,param_3);
    uVar6 = send_data(param_4,param_5,param_6,param_7,param_8);
    release();
  }
  return uVar6;
}

