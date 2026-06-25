// Ghidra decompilation of imm_p2p_rtc_sdp_negotiate  (entry=00175fa0)

undefined8 imm_p2p_rtc_sdp_negotiate(long param_1,long param_2,char *param_3)

{
  undefined4 uVar1;
  long lVar2;
  int iVar3;
  long *plVar4;
  undefined8 *puVar5;
  long *plVar6;
  long *plVar7;
  long *plVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  
  iVar3 = strcmp(param_3,"offer");
  if (iVar3 == 0) {
    uVar9 = *(undefined8 *)(param_2 + 0xa6);
    uVar11 = *(undefined8 *)(param_2 + 0x9e);
    uVar10 = *(undefined8 *)(param_2 + 0x96);
    uVar13 = *(undefined8 *)(param_2 + 0x8e);
    uVar12 = *(undefined8 *)(param_2 + 0x86);
    *(undefined8 *)(param_1 + 0xae) = *(undefined8 *)(param_2 + 0xae);
    *(undefined8 *)(param_1 + 0xa6) = uVar9;
    *(undefined8 *)(param_1 + 0x9e) = uVar11;
    *(undefined8 *)(param_1 + 0x96) = uVar10;
    *(undefined8 *)(param_1 + 0x8e) = uVar13;
    *(undefined8 *)(param_1 + 0x86) = uVar12;
    plVar6 = *(long **)(param_2 + 0x3d0);
    if (plVar6 != (long *)(param_2 + 0x3d0)) {
      do {
        plVar4 = (long *)imm_p2p_pool_zmalloc(0x60);
        if (plVar4 != (long *)0x0) {
          FUN_001735c0(plVar4 + 3,0xffffffffffffffff,0x41,"%s",plVar6 + 3);
          FUN_001735c0(plVar4 + 2,8,8,"%s",plVar6 + 2);
          *plVar4 = param_1 + 0x3d0;
          puVar5 = *(undefined8 **)(param_1 + 0x3d8);
          plVar4[1] = (long)puVar5;
          *puVar5 = plVar4;
          *(long **)(param_1 + 0x3d8) = plVar4;
        }
        plVar6 = (long *)*plVar6;
      } while (plVar6 != (long *)(param_2 + 0x3d0));
    }
  }
  plVar6 = *(long **)(param_1 + 0x488);
  if (plVar6 != (long *)(param_1 + 0x488)) {
    plVar4 = *(long **)(param_2 + 0x488);
    do {
      if (plVar4 != (long *)(param_2 + 0x488)) {
        plVar8 = plVar4;
        do {
          iVar3 = strncmp((char *)(plVar6 + 2),(char *)(plVar8 + 2),0x20);
          if (((iVar3 == 0) && (lVar2 = plVar6[7], (int)lVar2 == (int)plVar8[7])) &&
             (*(int *)((long)plVar6 + 0x3c) == *(int *)((long)plVar8 + 0x3c))) {
            *(int *)(param_1 + 0x4d4) = *(int *)((long)plVar6 + 0x3c);
            *(int *)(param_1 + 0x4d0) = (int)lVar2;
            *(int *)(param_1 + 0x4c8) = (int)plVar8[6];
            *(undefined4 *)(param_1 + 0x4cc) = *(undefined4 *)((long)plVar6 + 0x34);
            FUN_001735c0(param_1 + 0x4a8,0x20,0x20,"%s",plVar6 + 2);
            *(long *)(param_2 + 0x4d0) = plVar8[7];
            *(int *)(param_2 + 0x4c8) = (int)plVar8[6];
            FUN_001735c0(param_2 + 0x4a8,0x20,0x20,"%s",plVar8 + 2);
            goto LAB_0017615c;
          }
          plVar8 = (long *)*plVar8;
        } while (plVar8 != (long *)(param_2 + 0x488));
      }
      plVar6 = (long *)*plVar6;
    } while (plVar6 != (long *)(param_1 + 0x488));
  }
LAB_0017615c:
  plVar4 = *(long **)(param_1 + 0x568);
  plVar6 = (long *)(param_1 + 0x568);
  if (plVar4 != plVar6) {
    plVar8 = *(long **)(param_2 + 0x568);
    do {
      if (plVar8 != (long *)(param_2 + 0x568)) {
        plVar7 = plVar8;
        do {
          iVar3 = strncmp((char *)(plVar4 + 2),(char *)(plVar7 + 2),0x20);
          if ((iVar3 == 0) && (*(int *)((long)plVar4 + 0x3c) == *(int *)((long)plVar7 + 0x3c))) {
            *(int *)(param_1 + 0x5b4) = *(int *)((long)plVar4 + 0x3c);
            *(int *)(param_1 + 0x5a8) = (int)plVar7[6];
            lVar2 = plVar4[7];
            *(undefined4 *)(param_1 + 0x5ac) = 0xffffffff;
            *(int *)(param_1 + 0x5b0) = (int)lVar2;
            FUN_001735c0(param_1 + 0x5b8,0x41,0x41,"%s",plVar4 + 8);
            FUN_001735c0(param_1 + 0x588,0x20,0x20,"%s",plVar4 + 2);
            *(undefined4 *)(param_2 + 0x5b4) = *(undefined4 *)((long)plVar7 + 0x3c);
            lVar2 = plVar7[6];
            *(undefined4 *)(param_2 + 0x5ac) = 0xffffffff;
            *(int *)(param_2 + 0x5a8) = (int)lVar2;
            FUN_001735c0(param_2 + 0x5b8,0x41,0x41,"%s",plVar7 + 8);
            FUN_001735c0(param_2 + 0x588,0x20,0x20,"%s",plVar7 + 2);
            goto LAB_00176268;
          }
          plVar7 = (long *)*plVar7;
        } while (plVar7 != (long *)(param_2 + 0x568));
      }
      plVar4 = (long *)*plVar4;
    } while (plVar4 != plVar6);
  }
LAB_00176268:
  for (plVar4 = *(long **)(param_2 + 0x568); plVar4 != (long *)(param_2 + 0x568);
      plVar4 = (long *)*plVar4) {
    iVar3 = strcmp((char *)(plVar4 + 2),"rtx");
    if ((iVar3 == 0) && (*(int *)((long)plVar4 + 0x34) == *(int *)(param_2 + 0x5a8))) {
      *(undefined4 *)(param_2 + 0x630) = *(undefined4 *)(plVar4 + 6);
      uVar1 = *(undefined4 *)(plVar4 + 7);
      *(undefined4 *)(param_2 + 0x55c) = 2;
      *(undefined4 *)(param_2 + 0x638) = uVar1;
    }
  }
  for (plVar4 = (long *)*plVar6; plVar4 != plVar6; plVar4 = (long *)*plVar4) {
    iVar3 = strcmp((char *)(plVar4 + 2),"rtx");
    if (iVar3 == 0) {
      *(long *)(param_1 + 0x638) = plVar4[7];
    }
  }
  *(undefined4 *)(param_1 + 0x630) = *(undefined4 *)(param_2 + 0x630);
  uVar1 = *(undefined4 *)(param_2 + 0x55c);
  *(undefined4 *)(param_1 + 0x6cc) = 3;
  *(undefined4 *)(param_1 + 0x55c) = uVar1;
  FUN_001735c0(param_1 + 0x6a8,0x20,0x20,"AES/KCP");
  *(undefined4 *)(param_1 + 0x6c8) = 0x1771;
  *(undefined4 *)(param_2 + 0x6cc) = 3;
  FUN_001735c0(param_2 + 0x6a8,0x20,0x20,"AES/KCP");
  *(undefined4 *)(param_2 + 0x6c8) = 0x1771;
  return 0;
}

