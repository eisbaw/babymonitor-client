// Ghidra decompilation of encryptAesData  (entry=00293690)

undefined8 encryptAesData(long *param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  uint uVar1;
  long lVar2;
  undefined8 uVar3;
  ulong uVar4;
  bool bVar5;
  int iVar6;
  char *__s;
  byte *pbVar7;
  ulong __n;
  byte *pbVar8;
  undefined8 uVar9;
  byte *pbVar10;
  undefined1 *puVar11;
  ulong uStack_80;
  ulong uStack_78;
  undefined1 *puStack_70;
  undefined4 uStack_64;
  undefined8 uStack_60;
  long lStack_58;

  lVar2 = tpidr_el0;
  lStack_58 = *(long *)(lVar2 + 0x28);
  __s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  if (param_4 == 0) {
    pbVar7 = (byte *)0x0;
    uStack_64 = 0;
    __n = strlen(__s);
  }
  else {
    pbVar7 = (byte *)(**(code **)(*param_1 + 0x548))(param_1,param_4,0);
    uStack_64 = 0;
    __n = strlen(__s);
  }
  if (0xffffffffffffffef < __n) {
    if (*(long *)(lVar2 + 0x28) == lStack_58) {
                    /* WARNING: Subroutine does not return */
      FUN_00242b50(&uStack_80);
    }
    goto LAB_002938d8;
  }
  if (__n < 0x17) {
    puVar11 = (undefined1 *)((ulong)&uStack_80 | 1);
    uVar4 = uStack_80 >> 8;
    uStack_80 = CONCAT71((int7)uVar4,(char)((int)__n << 1));
    if (__n != 0) goto LAB_00293758;
    *puVar11 = 0;
  }
  else {
    puVar11 = (undefined1 *)FUN_0023abf0((__n | 0xf) + 1);
    uStack_80 = (__n | 0xf) + 2;
    uStack_78 = __n;
    puStack_70 = puVar11;
LAB_00293758:
    memmove(puVar11,__s,__n);
    puVar11[__n] = 0;
  }
  pbVar10 = pbVar7;
  if (pbVar7 == (byte *)0x0) {
                    /* try { // try from 00293774 to 002937bb has its CatchHandler @ 002938ac */
    pbVar8 = (byte *)FUN_00247894(2);
    pbVar10 = *(byte **)(pbVar8 + 0x10);
    if ((*pbVar8 & 1) == 0) {
      pbVar10 = pbVar8 + 1;
    }
  }
  bVar5 = (uStack_80 & 1) != 0;
  puVar11 = (undefined1 *)((ulong)&uStack_80 | 1);
  if (bVar5) {
    puVar11 = puStack_70;
  }
  uVar1 = (uint)((byte)uStack_80 >> 1);
  if (bVar5) {
    uVar1 = (uint)uStack_78;
  }
  iVar6 = aes128_ecb_encode(puVar11,uVar1,&uStack_60,&uStack_64,pbVar10);
  uVar3 = uStack_60;
  if (iVar6 != 0) {
    puts("AES128_ECB_Encode Failed ");
    uVar3 = 0;
  }
  if ((uStack_80 & 1) != 0) {
    free(puStack_70);
  }
  uVar9 = (**(code **)(*param_1 + 0x580))(param_1,uStack_64);
  (**(code **)(*param_1 + 0x680))(param_1,uVar9,0,uStack_64,uVar3);
  if (param_4 != 0) {
    (**(code **)(*param_1 + 0x550))(param_1,param_4,pbVar7);
  }
  aes128_free_data(uVar3);
  if (*(long *)(lVar2 + 0x28) == lStack_58) {
    return uVar9;
  }
LAB_002938d8:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
