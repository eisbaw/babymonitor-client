// Ghidra decompilation of frame34_builder  (entry=00247960)

void FUN_00247960(undefined8 *param_1,long param_2,undefined4 param_3,int param_4,long *param_5,
                 byte *param_6)

{
  ulong uVar1;
  uint uVar2;
  byte *pbVar3;
  long lVar4;
  undefined4 uVar5;
  uint uVar6;
  byte bVar7;
  long lVar8;
  bool bVar9;
  undefined8 *puVar10;
  ulong __n;
  undefined8 uVar11;
  int iVar12;
  byte *pbVar13;
  undefined1 *__dest;
  ulong local_80;
  ulong uStack_78;
  undefined1 *local_70;
  long local_68;

  lVar8 = tpidr_el0;
  local_68 = *(long *)(lVar8 + 0x28);
  uVar5 = *(undefined4 *)(*param_5 + 0xc0);
  __android_log_print(3,"Thing-Network","[%s:%d]Package seq: %d","Package",0x21c,uVar5);
  if (*(int *)(*param_5 + 0x160) < 5) {
    __android_log_print(3,"Thing-Network","[%s:%d]before LAN_PROTOCOL_VERSION_3_5","Package",0x223);
    pbVar3 = param_6 + 1;
    if ((*param_6 & 1) != 0) {
      pbVar3 = *(byte **)(param_6 + 0x10);
    }
    puVar10 = (undefined8 *)FUN_0023abf0(0x58);
    uVar11 = DAT_00143a88;
    puVar10[3] = 0;
    puVar10[4] = 0;
    *(undefined1 *)((long)puVar10 + 0x2f) = 1;
    puVar10[1] = uVar11;
    puVar10[2] = 0;
    *(undefined8 *)((long)puVar10 + 0x27) = 0;
    puVar10[6] = 0;
    *puVar10 = &PTR_FUN_002c5b58;
    puVar10[8] = 0;
    puVar10[7] = 0;
    puVar10[10] = 0;
    puVar10[9] = 0;
    if (pbVar3 != (byte *)0x0) {
                    /* try { // try from 00247ae0 to 00247aef has its CatchHandler @ 00247c28 */
      __n = __strlen_chk(pbVar3,0xffffffffffffffff);
      if (0xffffffffffffffef < __n) {
        if (*(long *)(lVar8 + 0x28) == local_68) {
                    /* try { // try from 00247c14 to 00247c1b has its CatchHandler @ 00247c28 */
                    /* WARNING: Subroutine does not return */
          FUN_00242b50(&local_80);
        }
        goto LAB_00247c6c;
      }
      if (__n < 0x17) {
        __dest = (undefined1 *)((ulong)&local_80 | 1);
        local_80 = CONCAT71(local_80._1_7_,(char)((int)__n << 1));
        if (__n != 0) goto LAB_00247b9c;
        bVar7 = *(byte *)(puVar10 + 8);
        *__dest = 0;
      }
      else {
        uVar1 = (__n | 0xf) + 1;
                    /* try { // try from 00247b84 to 00247b8b has its CatchHandler @ 00247c28 */
        __dest = (undefined1 *)FUN_0023abf0(uVar1);
        local_80 = uVar1 | 1;
        uStack_78 = __n;
        local_70 = __dest;
LAB_00247b9c:
        memcpy(__dest,pbVar3,__n);
        bVar7 = *(byte *)(puVar10 + 8);
        __dest[__n] = 0;
      }
      if ((bVar7 & 1) != 0) {
        free((void *)puVar10[10]);
      }
      *(undefined4 *)(puVar10 + 2) = uVar5;
      *(undefined4 *)((long)puVar10 + 0x14) = param_3;
      puVar10[9] = uStack_78;
      puVar10[8] = local_80;
      puVar10[10] = local_70;
      local_80 = local_80 & 0xffffffff00000000;
      if (param_2 == 0) {
        iVar12 = 0x24;
      }
      else {
        lVar4 = (long)puVar10 + 0x41;
        if ((*(byte *)(puVar10 + 8) & 1) != 0) {
          lVar4 = puVar10[10];
        }
                    /* try { // try from 00247b60 to 00247b6f has its CatchHandler @ 00247c24 */
        aes128_ecb_encode(param_2,param_4,puVar10 + 4,&local_80,lVar4);
        iVar12 = (int)local_80 + 0x24;
      }
      *(int *)(puVar10 + 3) = iVar12;
                    /* try { // try from 00247bc4 to 00247bcb has its CatchHandler @ 00247c24 */
      uVar11 = thunk_FUN_0023abf0(0x20);
      puVar10[7] = uVar11;
    }
  }
  else {
    __android_log_print(3,"Thing-Network","[%s:%d]LAN_PROTOCOL_VERSION_3_5","Package",0x21f);
    bVar7 = *param_6;
    pbVar13 = *(byte **)(param_6 + 0x10);
    uVar6 = *(uint *)(param_6 + 8);
    puVar10 = (undefined8 *)FUN_0023abf0(0x58);
    bVar9 = (bVar7 & 1) != 0;
    pbVar3 = param_6 + 1;
    if (bVar9) {
      pbVar3 = pbVar13;
    }
    uVar2 = (uint)(bVar7 >> 1);
    if (bVar9) {
      uVar2 = uVar6;
    }
                    /* try { // try from 00247a44 to 00247a53 has its CatchHandler @ 00247c1c */
    FUN_00264a3c(puVar10,param_3,uVar5,param_2,(long)param_4,pbVar3,uVar2);
  }
  *param_1 = puVar10;
  if (*(long *)(lVar8 + 0x28) == local_68) {
    return;
  }
LAB_00247c6c:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
