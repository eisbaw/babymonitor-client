// Ghidra decompilation of parseAesData  (entry=002938dc)

void parseAesData(long *param_1,undefined8 param_2,long param_3,long param_4)

{
  byte bVar1;
  long lVar2;
  long lVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  undefined8 uVar7;
  byte *pbVar8;
  byte *pbVar9;
  uint uStack_64;
  long lStack_60;
  long lStack_58;

  lVar2 = tpidr_el0;
  lStack_58 = *(long *)(lVar2 + 0x28);
  if (param_3 != 0) {
    uVar5 = (**(code **)(*param_1 + 0x5c0))(param_1,param_3,0);
    iVar4 = (**(code **)(*param_1 + 0x558))(param_1,param_3);
    if (iVar4 != 0) {
      if (param_4 == 0) {
LAB_002939c0:
        uStack_64 = 0;
        pbVar8 = (byte *)FUN_00247894(2);
        pbVar9 = *(byte **)(pbVar8 + 0x10);
        lVar6 = 0;
        if ((*pbVar8 & 1) == 0) {
          pbVar9 = pbVar8 + 1;
        }
        iVar4 = aes128_ecb_decode(uVar5,iVar4,&lStack_60,&uStack_64,pbVar9);
        lVar3 = lStack_60;
      }
      else {
        lVar6 = (**(code **)(*param_1 + 0x548))(param_1,param_4,0);
        uStack_64 = 0;
        if (lVar6 == 0) goto LAB_002939c0;
        iVar4 = aes128_ecb_decode(uVar5,iVar4,&lStack_60,&uStack_64,lVar6);
        lVar3 = lStack_60;
      }
      if (iVar4 == 0) {
        uVar7 = 0;
        bVar1 = *(byte *)(lVar3 + (ulong)uStack_64 + -1);
        *(undefined1 *)((lVar3 + (ulong)uStack_64) - (ulong)bVar1) = 0;
        uStack_64 = uStack_64 - bVar1;
        if ((lVar3 != 0) && (-1 < (int)uStack_64)) {
          uVar7 = (**(code **)(*param_1 + 0x580))(param_1);
          (**(code **)(*param_1 + 0x680))(param_1,uVar7,0,uStack_64,lVar3);
          aes128_free_data(lVar3);
          if (lVar6 != 0) {
            (**(code **)(*param_1 + 0x550))(param_1,param_4,lVar6);
          }
          (**(code **)(*param_1 + 0x600))(param_1,param_3,uVar5,1);
        }
        goto LAB_00293990;
      }
    }
  }
  uVar7 = 0;
LAB_00293990:
  if (*(long *)(lVar2 + 0x28) == lStack_58) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar7);
}
