// Ghidra decompilation of ThingSmartP2PSDK_SendMessageThroughMQTT  (entry=00146b40)

/* ThingSmartP2PSDK::SendMessageThroughMQTT(char*, char*, unsigned int) */

void ThingSmartP2PSDK::SendMessageThroughMQTT(char *param_1,char *param_2,uint param_3)

{
  long lVar1;
  bool bVar2;
  undefined *puVar3;
  int iVar4;
  void *__s;
  undefined8 uVar5;
  undefined8 uVar6;
  long *plVar7;
  ulong __n;
  _jclass *local_458;
  undefined8 local_450;
  undefined8 uStack_448;
  undefined8 uStack_440;
  undefined8 uStack_438;
  undefined8 local_430;
  undefined8 uStack_428;
  undefined8 uStack_420;
  undefined8 uStack_418;
  undefined8 local_410;
  undefined8 uStack_408;
  undefined8 uStack_400;
  undefined8 uStack_3f8;
  undefined8 local_3f0;
  undefined8 uStack_3e8;
  undefined8 uStack_3e0;
  undefined8 uStack_3d8;
  undefined8 local_3d0;
  undefined8 uStack_3c8;
  undefined8 uStack_3c0;
  undefined8 uStack_3b8;
  undefined8 local_3b0;
  undefined8 uStack_3a8;
  undefined8 uStack_3a0;
  undefined8 uStack_398;
  undefined8 local_390;
  undefined8 uStack_388;
  undefined8 uStack_380;
  undefined8 uStack_378;
  undefined8 local_370;
  undefined8 uStack_368;
  undefined8 uStack_360;
  undefined8 uStack_358;
  undefined8 local_350;
  undefined8 uStack_348;
  undefined8 uStack_340;
  undefined8 uStack_338;
  undefined8 local_330;
  undefined8 uStack_328;
  undefined8 uStack_320;
  undefined8 uStack_318;
  undefined8 local_310;
  undefined8 uStack_308;
  undefined8 uStack_300;
  undefined8 uStack_2f8;
  undefined8 local_2f0;
  undefined8 uStack_2e8;
  undefined8 uStack_2e0;
  undefined8 uStack_2d8;
  undefined8 local_2d0;
  undefined8 uStack_2c8;
  undefined8 uStack_2c0;
  undefined8 uStack_2b8;
  undefined8 local_2b0;
  undefined8 uStack_2a8;
  undefined8 uStack_2a0;
  undefined8 uStack_298;
  undefined8 local_290;
  undefined8 uStack_288;
  undefined8 uStack_280;
  undefined8 uStack_278;
  undefined8 local_270;
  undefined8 uStack_268;
  undefined8 uStack_260;
  undefined8 uStack_258;
  long local_48;
  
  lVar1 = tpidr_el0;
  local_48 = *(long *)(lVar1 + 0x28);
  __n = (ulong)(param_3 + 0x80);
  __s = operator_new__(__n);
  memset(__s,0,__n);
  FUN_0014678c(__s,0xffffffffffffffff,__n,"{\"p2p_3_0_cxx_mqtt_send\":%s}",param_2);
  LOGAPM("6373a341d61c14a618387a409549afa6",__s);
  LOGI("ThingAvLoggerSDK","ThingSmartP2PSDK::%s msg:%s ...\n","SendMessageThroughMQTT",__s);
  operator_delete__(__s);
  puVar3 = PTR_m_gP2PJniParams_00263fb0;
  local_458 = (_jclass *)0x0;
  plVar7 = *(long **)PTR_m_gP2PJniParams_00263fb0;
  if ((plVar7 == (long *)0x0) || (*(long *)(PTR_m_gP2PJniParams_00263fb0 + 0x10) == 0)) {
    uStack_268 = 0;
    local_270 = 0;
    uStack_258 = 0;
    uStack_260 = 0;
    uStack_288 = 0;
    local_290 = 0;
    uStack_278 = 0;
    uStack_280 = 0;
    uStack_2a8 = 0;
    local_2b0 = 0;
    uStack_298 = 0;
    uStack_2a0 = 0;
    uStack_2c8 = 0;
    local_2d0 = 0;
    uStack_2b8 = 0;
    uStack_2c0 = 0;
    uStack_2e8 = 0;
    local_2f0 = 0;
    uStack_2d8 = 0;
    uStack_2e0 = 0;
    uStack_308 = 0;
    local_310 = 0;
    uStack_2f8 = 0;
    uStack_300 = 0;
    uStack_328 = 0;
    local_330 = 0;
    uStack_318 = 0;
    uStack_320 = 0;
    uStack_348 = 0;
    local_350 = 0;
    uStack_338 = 0;
    uStack_340 = 0;
    uStack_368 = 0;
    local_370 = 0;
    uStack_358 = 0;
    uStack_360 = 0;
    uStack_388 = 0;
    local_390 = 0;
    uStack_378 = 0;
    uStack_380 = 0;
    uStack_3a8 = 0;
    local_3b0 = 0;
    uStack_398 = 0;
    uStack_3a0 = 0;
    uStack_3c8 = 0;
    local_3d0 = 0;
    uStack_3b8 = 0;
    uStack_3c0 = 0;
    uStack_3e8 = 0;
    local_3f0 = 0;
    uStack_3d8 = 0;
    uStack_3e0 = 0;
    uStack_408 = 0;
    local_410 = 0;
    uStack_3f8 = 0;
    uStack_400 = 0;
    uStack_428 = 0;
    local_430 = 0;
    uStack_418 = 0;
    uStack_420 = 0;
    uStack_448 = 0;
    local_450 = 0;
    uStack_438 = 0;
    uStack_440 = 0;
    FUN_0014678c(&local_450,0x200,0x200,
                 "{\"android_mqtt_send_exception\":\"params invalid, jvm=%p, jMethodIdSendMessageThroughMqtt=%p\"}"
                );
LAB_00146ccc:
    LOGAPM("6373a341d61c14a618387a409549afa6",&local_450);
  }
  else {
    iVar4 = (**(code **)(*plVar7 + 0x30))(plVar7,&local_458,0x10004);
    if (iVar4 == 0) {
      bVar2 = false;
    }
    else {
      iVar4 = (**(code **)(**(long **)puVar3 + 0x20))(*(long **)puVar3,&local_458,0);
      if (iVar4 != 0) {
        memset(&local_450,0,0x400);
        FUN_0014678c(&local_450,0x400,0x400,
                     "{\"android_mqtt_send_exception\":\"AttachCurrentThread failed, func:%s, line:%d\"}"
                     ,"SendMessageThroughMQTT",0xba);
        goto LAB_00146ccc;
      }
      bVar2 = true;
    }
    uVar5 = (**(code **)(*(long *)local_458 + 0x538))(local_458,param_1);
    uVar6 = (**(code **)(*(long *)local_458 + 0x538))(local_458,param_2);
    _JNIEnv::CallStaticVoidMethod
              (local_458,*(_jmethodID **)(puVar3 + 8),*(undefined8 *)(puVar3 + 0x10),0,uVar5,uVar6);
    (**(code **)(*(long *)local_458 + 0xb8))(local_458,uVar5);
    (**(code **)(*(long *)local_458 + 0xb8))(local_458,uVar6);
    if (bVar2) {
      (**(code **)(**(long **)puVar3 + 0x28))();
    }
  }
  if (*(long *)(lVar1 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

