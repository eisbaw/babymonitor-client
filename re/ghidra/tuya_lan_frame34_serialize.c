// Ghidra decompilation of frame34_serialize  (entry=0026392c)

void FUN_0026392c(long *param_1,long param_2,ulong *param_3,ulong param_4)

{
  uint uVar1;
  long *plVar2;
  uint *puVar3;
  uint *__dest;
  undefined8 uVar4;
  long lVar5;
  void *__src;
  ulong uVar6;
  undefined8 *puVar7;
  ulong uVar8;
  ulong uVar9;
  undefined8 *puVar10;
  ulong uVar11;
  long lVar12;
  uint uVar13;
  undefined8 uVar14;
  undefined8 uVar15;

  uVar13 = *(uint *)(param_2 + 0x18);
  uVar11 = (ulong)(uVar13 + 0x10);
  plVar2 = (long *)FUN_0023abf0(0x40);
  *plVar2 = (long)&PTR_FUN_002c5c58;
  plVar2[1] = 0;
  plVar2[2] = 0;
  plVar2[3] = 0;
  plVar2[4] = 0;
  plVar2[5] = uVar11;
  plVar2[6] = 0;
  *(undefined1 *)(plVar2 + 7) = 0;
  *(undefined4 *)((long)plVar2 + 0x3c) = 0;
                    /* try { // try from 00263990 to 00263997 has its CatchHandler @ 00263e2c */
  puVar3 = (uint *)thunk_FUN_0023abf0(uVar11);
  plVar2[6] = (long)puVar3;
  plVar2[3] = (long)puVar3;
  if (uVar13 + 0x10 < 4) {
    uVar9 = 0;
    uVar6 = 4;
    __dest = puVar3;
    uVar8 = uVar6;
    if (uVar11 < 4) goto joined_r0x00263a04;
  }
  else {
    uVar9 = 4;
    uVar1 = (*(uint *)(param_2 + 8) & 0xff00ff00) >> 8 | (*(uint *)(param_2 + 8) & 0xff00ff) << 8;
    __dest = puVar3 + 1;
    *puVar3 = uVar1 >> 0x10 | uVar1 << 0x10;
    plVar2[3] = (long)__dest;
    plVar2[4] = 4;
    uVar6 = 8;
    uVar8 = uVar6;
    if (uVar11 < 8) goto joined_r0x00263a04;
  }
  uVar1 = (*(uint *)(param_2 + 0x10) & 0xff00ff00) >> 8 |
          (*(uint *)(param_2 + 0x10) & 0xff00ff) << 8;
  *__dest = uVar1 >> 0x10 | uVar1 << 0x10;
  plVar2[3] = (long)(__dest + 1);
  plVar2[4] = uVar6;
  __dest = __dest + 1;
  uVar8 = uVar9 | 8;
  uVar9 = uVar6;
joined_r0x00263a04:
  if (uVar8 <= uVar11) {
    lVar5 = plVar2[3];
    lVar12 = plVar2[4];
    uVar11 = plVar2[5];
    uVar13 = (*(uint *)(param_2 + 0x14) & 0xff00ff00) >> 8 |
             (*(uint *)(param_2 + 0x14) & 0xff00ff) << 8;
    *__dest = uVar13 >> 0x10 | uVar13 << 0x10;
    uVar9 = lVar12 + 4;
    __dest = (uint *)(lVar5 + 4);
    uVar13 = *(uint *)(param_2 + 0x18);
    uVar8 = lVar12 + 8;
    plVar2[3] = (long)__dest;
    plVar2[4] = uVar9;
  }
  if (uVar8 <= uVar11) {
    uVar1 = (uVar13 & 0xff00ff00) >> 8 | (uVar13 & 0xff00ff) << 8;
    uVar1 = uVar1 >> 0x10 | uVar1 << 0x10;
    if (*(int *)((long)plVar2 + 0x3c) != 0) {
      uVar1 = uVar13;
    }
    *__dest = uVar1;
    uVar13 = *(uint *)(param_2 + 0x18);
    uVar11 = plVar2[5];
    uVar9 = plVar2[4] + 4;
    __dest = (uint *)(plVar2[3] + 4);
    plVar2[3] = (long)__dest;
    plVar2[4] = uVar9;
  }
  if ((param_4 & 1) == 0) {
    uVar13 = uVar13 - 0x24;
    __src = *(void **)(param_2 + 0x20);
  }
  else {
    if (uVar9 + 4 <= uVar11) {
      uVar1 = *(uint *)(param_2 + 0x1c);
      uVar13 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
      uVar13 = uVar13 >> 0x10 | uVar13 << 0x10;
      if (*(int *)((long)plVar2 + 0x3c) != 0) {
        uVar13 = uVar1;
      }
      *__dest = uVar13;
      uVar13 = *(uint *)(param_2 + 0x18);
      uVar11 = plVar2[5];
      uVar9 = plVar2[4] + 4;
      __dest = (uint *)(plVar2[3] + 4);
      plVar2[3] = (long)__dest;
      plVar2[4] = uVar9;
    }
    uVar13 = uVar13 - 0xc;
    __src = *(void **)(param_2 + 0x20);
  }
  uVar6 = (ulong)uVar13;
  if ((__src != (void *)0x0) && (uVar9 + uVar6 <= uVar11)) {
    memcpy(__dest,__src,uVar6);
    plVar2[3] = plVar2[3] + uVar6;
    plVar2[4] = plVar2[4] + uVar6;
  }
  lVar12 = plVar2[6];
  plVar2[6] = 0;
                    /* try { // try from 00263af8 to 00263dcf has its CatchHandler @ 00263e4c */
  uVar4 = mbedcrypto_md_info_from_type(6);
  uVar11 = (ulong)(*(byte *)(param_2 + 0x40) >> 1);
  lVar5 = param_2 + 0x41;
  if ((*(byte *)(param_2 + 0x40) & 1) != 0) {
    uVar11 = *(ulong *)(param_2 + 0x48);
    lVar5 = *(long *)(param_2 + 0x50);
  }
  mbedcrypto_md_hmac(uVar4,lVar5,uVar11,lVar12,uVar13 + 0x10,*(undefined8 *)(param_2 + 0x38));
  puts("hmacA: ");
  printf("%x ",(ulong)**(byte **)(param_2 + 0x38));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 1));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 2));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 3));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 4));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 5));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 6));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 7));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 8));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 9));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 10));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0xb));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0xc));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0xd));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0xe));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0xf));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x10));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x11));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x12));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x13));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x14));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x15));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x16));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x17));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x18));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x19));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1a));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1b));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1c));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1d));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1e));
  printf("%x ",(ulong)*(byte *)(*(long *)(param_2 + 0x38) + 0x1f));
  puts("\nend");
  lVar5 = plVar2[4];
  uVar11 = plVar2[5];
  puVar10 = *(undefined8 **)(param_2 + 0x38);
  if ((puVar10 != (undefined8 *)0x0) && (lVar5 + 0x20U <= uVar11)) {
    uVar15 = *puVar10;
    uVar14 = puVar10[3];
    uVar4 = puVar10[2];
    puVar7 = (undefined8 *)plVar2[3];
    puVar7[1] = puVar10[1];
    *puVar7 = uVar15;
    puVar7[3] = uVar14;
    puVar7[2] = uVar4;
    uVar11 = plVar2[5];
    lVar5 = plVar2[4] + 0x20;
    plVar2[3] = plVar2[3] + 0x20;
    plVar2[4] = lVar5;
  }
  if (lVar5 + 4U <= uVar11) {
    uVar1 = *(uint *)(param_2 + 0xc);
    uVar13 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
    uVar13 = uVar13 >> 0x10 | uVar13 << 0x10;
    if (*(int *)((long)plVar2 + 0x3c) != 0) {
      uVar13 = uVar1;
    }
    *(uint *)plVar2[3] = uVar13;
    plVar2[3] = plVar2[3] + 4;
    plVar2[4] = plVar2[4] + 4;
  }
  uVar4 = *(undefined8 *)(param_2 + 0x20);
  *param_3 = (ulong)(*(int *)(param_2 + 0x18) + 0x10);
  aes128_free_data(uVar4);
  *(undefined8 *)(param_2 + 0x20) = 0;
  *param_1 = lVar12;
  lVar5 = FUN_0023cb40(0xffffffffffffffff,plVar2 + 1);
  if (lVar5 == 0) {
    (**(code **)(*plVar2 + 0x10))(plVar2);
    FUN_001f9ca4(plVar2);
    return;
  }
  return;
}
