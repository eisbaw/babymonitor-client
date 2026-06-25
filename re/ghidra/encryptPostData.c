// Ghidra decompilation of encryptPostData  (entry=001151f8)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long FUN_001151f8(long *param_1,undefined8 param_2,undefined8 param_3)

{
  ulong uVar1;
  long lVar2;
  undefined1 *puVar3;
  char *__s;
  undefined8 uVar4;
  size_t sVar5;
  undefined8 *puVar6;
  long lVar7;
  undefined8 local_c0;
  undefined8 uStack_b8;
  ulong local_b0;
  undefined8 uStack_a8;
  undefined8 local_a0;
  undefined8 uStack_98;
  undefined8 uStack_90;
  undefined8 uStack_88;
  undefined1 local_78 [32];
  long local_58;
  
  puVar6 = &local_c0;
  lVar2 = tpidr_el0;
  local_58 = *(long *)(lVar2 + 0x28);
  __s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  if (__s == (char *)0x0) {
    lVar7 = 0;
  }
  else {
    local_78[0] = 0;
    uVar4 = FUN_0011775c(6);
    sVar5 = strlen(__s);
    uVar1 = ram0x00139078;
    puVar3 = DAT_00139080;
    if ((DAT_00139070 & 1) == 0) {
      uVar1 = (ulong)(DAT_00139070 >> 1);
      puVar3 = &DAT_00139071;
    }
    FUN_001179f8(uVar4,__s,sVar5,puVar3,uVar1,local_78);
    lVar7 = 0;
    uStack_b8 = 0;
    local_c0 = 0;
    uStack_a8 = 0;
    local_b0 = 0;
    uStack_98 = 0;
    local_a0 = 0;
    uStack_88 = 0;
    uStack_90 = 0;
    do {
      FUN_00116ae4(puVar6,0xffffffffffffffff,&DAT_001090ea,local_78[lVar7]);
      lVar7 = lVar7 + 1;
      puVar6 = (undefined8 *)((long)puVar6 + 2);
    } while (lVar7 != 0x20);
    local_b0 = local_b0 & 0xffffffffffffff00;
    lVar7 = (**(code **)(*param_1 + 0x580))(param_1,0x10);
    if (lVar7 != 0) {
      (**(code **)(*param_1 + 0x680))(param_1,lVar7,0,0x10,&local_c0);
    }
    (**(code **)(*param_1 + 0x550))(param_1,param_3,__s);
  }
  if (*(long *)(lVar2 + 0x28) == local_58) {
    return lVar7;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

