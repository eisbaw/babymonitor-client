// Thing_Native_SmartLink @ 0010f6bc

/* Thing_Native_SmartLink(_JNIEnv*, _jclass*, _jstring*, _jstring*, _jstring*, int, int, int, int,
   int) */

undefined8
Thing_Native_SmartLink
          (_JNIEnv *param_1,_jclass *param_2,_jstring *param_3,_jstring *param_4,_jstring *param_5,
          int param_6,int param_7,int param_8,int param_9,int param_10)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  if (((param_3 != (_jstring *)0x0) && (param_4 != (_jstring *)0x0)) && (param_5 != (_jstring *)0x0)
     ) {
    uVar1 = (**(code **)(*(long *)param_1 + 0x548))
                      (param_1,param_3,0,param_4,param_5,param_6,param_7,param_8);
    uVar2 = (**(code **)(*(long *)param_1 + 0x548))(param_1,param_4,0);
    uVar3 = (**(code **)(*(long *)param_1 + 0x548))(param_1,param_5,0);
    thing_smart_link(uVar1,uVar2,uVar3,param_6,param_7,param_8,param_9,param_10);
    (**(code **)(*(long *)param_1 + 0x550))(param_1,param_5,uVar1);
    (**(code **)(*(long *)param_1 + 0x550))(param_1,param_4,uVar2);
    (**(code **)(*(long *)param_1 + 0x550))(param_1,param_5,uVar3);
  }
  return 0;
}

