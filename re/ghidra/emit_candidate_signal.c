// Ghidra decompilation of emit_candidate_signal  (entry=0016d8d4)

void FUN_0016d8d4(undefined8 param_1,int param_2,char *param_3)

{
  long lVar1;
  size_t sVar2;
  long lVar3;
  ulong uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  long lVar13;
  undefined8 uVar14;
  char *__s;
  long lVar15;
  long lVar16;
  long lVar17;
  long lVar18;
  long lVar19;
  void *__ptr;
  undefined8 uVar20;

  imm_p2p_log_log(1,&DAT_0023571f,0x443,"on local ice candidate: status[%d] %s\n",param_2,param_3);
  if (((param_2 == 0) && (param_3 != (char *)0x0)) &&
     (lVar1 = imm_p2p_ice_session_get_user_data(param_1), lVar1 != 0)) {
    sVar2 = strlen(param_3);
    if (sVar2 != 0) {
      lVar3 = cJSON_CreateObject();
      uVar4 = imm_p2p_misc_get_timestamp_ms();
      uVar5 = cJSON_CreateNumber((double)uVar4);
      uVar6 = cJSON_CreateString("3.5.5");
      uVar7 = cJSON_CreateString("rtc_candidate_local");
      uVar8 = cJSON_CreateString(lVar1 + 0x101c);
      uVar9 = cJSON_CreateString(lVar1 + 0xe9c);
      uVar10 = cJSON_CreateString(*(long *)(lVar1 + 0x30) + 0x350);
      uVar11 = cJSON_CreateString(lVar1 + 0xe5c);
      uVar20 = NEON_ucvtf((ulong)*(uint *)(lVar1 + 0xe58));
      uVar20 = cJSON_CreateNumber(uVar20);
      uVar12 = cJSON_CreateString(param_3);
      lVar13 = imm_p2p_misc_get_timestamp_ms();
      uVar14 = cJSON_CreateNumber((double)(ulong)(lVar13 - *(long *)(lVar1 + 0x33a0)));
      cJSON_AddItemToObject(lVar3,"t",uVar5);
      cJSON_AddItemToObject(lVar3,&DAT_002192c1,uVar6);
      cJSON_AddItemToObject(lVar3,&DAT_00218200,uVar7);
      cJSON_AddItemToObject(lVar3,&DAT_00218a51,uVar8);
      cJSON_AddItemToObject(lVar3,"s",uVar9);
      cJSON_AddItemToObject(lVar3,"l",uVar10);
      cJSON_AddItemToObject(lVar3,"r",uVar11);
      cJSON_AddItemToObject(lVar3,&DAT_002357dc,uVar20);
      cJSON_AddItemToObject(lVar3,"c",uVar12);
      cJSON_AddItemToObject(lVar3,"d",uVar14);
      if (lVar3 != 0) {
        __s = (char *)cJSON_PrintUnformatted(lVar3);
        if (__s != (char *)0x0) {
          sVar2 = strlen(__s);
          imm_p2p_upload_log(2,__s,sVar2);
          cJSON_free(__s);
        }
        cJSON_Delete(lVar3);
      }
      imm_p2p_rtc_sdp_add_candidate(lVar1 + 0x708,param_3);
    }
    lVar3 = cJSON_CreateString(*(long *)(lVar1 + 0x30) + 0x350);
    lVar13 = cJSON_CreateString(lVar1 + 0xe5c);
    lVar15 = cJSON_CreateString(lVar1 + 0xe9c);
    lVar16 = cJSON_CreateString(lVar1 + 0xfdc);
    lVar17 = cJSON_CreateString("candidate");
    lVar18 = cJSON_CreateString(lVar1 + 0x101c);
    lVar19 = cJSON_CreateObject();
    if (((((lVar3 != 0) && (lVar13 != 0)) && ((lVar15 != 0 && ((lVar16 != 0 && (lVar17 != 0)))))) &&
        (lVar18 != 0)) && (lVar19 != 0)) {
      cJSON_AddItemToObject(lVar19,&DAT_002182e5,lVar3);
      cJSON_AddItemToObject(lVar19,"to",lVar13);
      cJSON_AddItemToObject(lVar19,"sessionid",lVar15);
      cJSON_AddItemToObject(lVar19,"moto_id",lVar16);
      cJSON_AddItemToObject(lVar19,"type",lVar17);
      cJSON_AddItemToObject(lVar19,"trace_id",lVar18);
      lVar3 = cJSON_CreateString(param_3);
      lVar13 = cJSON_CreateObject();
      if ((lVar3 != 0) && (lVar13 != 0)) {
        cJSON_AddItemToObject(lVar13,"candidate",lVar3);
        lVar3 = cJSON_CreateObject();
        if (lVar3 != 0) {
          cJSON_AddItemToObject(lVar3,"header",lVar19);
          cJSON_AddItemToObject(lVar3,"msg",lVar13);
          __ptr = (void *)cJSON_PrintUnformatted(lVar3);
          if (__ptr != (void *)0x0) {
            FUN_0016d6d0(lVar1,__ptr,0);
            FUN_00168484(lVar1,"outgoing","candidate",__ptr);
            free(__ptr);
          }
          cJSON_Delete(lVar3);
        }
      }
    }
    uv_timer_start(*(undefined8 *)(lVar1 + 0xe10),FUN_001697c4,0,5);
    return;
  }
  return;
}
