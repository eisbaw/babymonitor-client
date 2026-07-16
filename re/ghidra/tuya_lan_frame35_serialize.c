// Ghidra decompilation of frame35_serialize  (entry=002647a0)

void FUN_002647a0(long *param_1,long param_2,ulong *param_3)

{
  long lVar1;
  uint uVar2;
  long *plVar3;
  uint *puVar4;
  uint *__dest;
  void *__src;
  ulong uVar5;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  uint uVar9;
  ulong uVar10;

  uVar9 = *(int *)(param_2 + 0x18) + 0x16;
  uVar10 = (ulong)uVar9;
  plVar3 = (long *)FUN_0023abf0(0x40);
  *plVar3 = (long)&PTR_FUN_002c5c58;
  plVar3[1] = 0;
  plVar3[2] = 0;
  plVar3[3] = 0;
  plVar3[4] = 0;
  plVar3[5] = uVar10;
  plVar3[6] = 0;
  *(undefined1 *)(plVar3 + 7) = 0;
  *(undefined4 *)((long)plVar3 + 0x3c) = 0;
                    /* try { // try from 002647f4 to 002647fb has its CatchHandler @ 00264a1c */
  puVar4 = (uint *)thunk_FUN_0023abf0(uVar10);
  plVar3[6] = (long)puVar4;
  plVar3[3] = (long)puVar4;
  if (uVar9 < 4) {
    uVar8 = 0;
    uVar5 = 1;
    __dest = puVar4;
    uVar6 = uVar5;
    if (uVar10 != 0) goto LAB_0026481c;
LAB_00264880:
    uVar6 = uVar8;
    if (uVar10 < uVar5) goto LAB_00264890;
LAB_00264834:
    lVar7 = plVar3[3];
    lVar1 = plVar3[4];
    *(undefined1 *)__dest = *(undefined1 *)(param_2 + 0x38);
    uVar6 = lVar1 + 1;
    uVar5 = plVar3[5];
    __dest = (uint *)(lVar7 + 1);
    plVar3[3] = (long)__dest;
    plVar3[4] = uVar6;
    uVar8 = lVar1 + 5;
    if (uVar8 <= uVar5) {
LAB_002648a0:
      uVar2 = *(uint *)(param_2 + 0x10);
      uVar9 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
      uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
      if (*(int *)((long)plVar3 + 0x3c) != 0) {
        uVar9 = uVar2;
      }
      *__dest = uVar9;
      uVar6 = plVar3[4] + 4;
      __dest = (uint *)(plVar3[3] + 4);
      uVar8 = plVar3[4] + 8;
      plVar3[3] = (long)__dest;
      plVar3[4] = uVar6;
      uVar5 = plVar3[5];
    }
  }
  else {
    uVar8 = 4;
    uVar9 = (*(uint *)(param_2 + 8) & 0xff00ff00) >> 8 | (*(uint *)(param_2 + 8) & 0xff00ff) << 8;
    __dest = puVar4 + 1;
    *puVar4 = uVar9 >> 0x10 | uVar9 << 0x10;
    plVar3[3] = (long)__dest;
    plVar3[4] = 4;
    uVar5 = 5;
    uVar6 = uVar5;
    if (uVar10 < 5) goto LAB_00264880;
LAB_0026481c:
    puVar4 = (uint *)((long)__dest + 1);
    *(undefined1 *)__dest = *(undefined1 *)(param_2 + 0x39);
    plVar3[3] = (long)puVar4;
    plVar3[4] = uVar6;
    __dest = puVar4;
    if ((uVar8 | 2) <= uVar10) goto LAB_00264834;
LAB_00264890:
    uVar8 = uVar6 + 4;
    uVar5 = uVar10;
    if (uVar8 <= uVar10) goto LAB_002648a0;
  }
  if (uVar5 < uVar8) {
    uVar9 = *(uint *)(param_2 + 0x18);
    if (uVar8 <= uVar5) {
LAB_0026492c:
      uVar2 = (uVar9 & 0xff00ff00) >> 8 | (uVar9 & 0xff00ff) << 8;
      uVar2 = uVar2 >> 0x10 | uVar2 << 0x10;
      if (*(int *)((long)plVar3 + 0x3c) != 0) {
        uVar2 = uVar9;
      }
      *__dest = uVar2;
      uVar9 = *(uint *)(param_2 + 0x18);
      uVar5 = plVar3[5];
      uVar6 = plVar3[4] + 4;
      __dest = (uint *)(plVar3[3] + 4);
      plVar3[3] = (long)__dest;
      plVar3[4] = uVar6;
      __src = *(void **)(param_2 + 0x20);
      goto joined_r0x002648e8;
    }
  }
  else {
    uVar2 = *(uint *)(param_2 + 0x14);
    uVar9 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
    uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
    if (*(int *)((long)plVar3 + 0x3c) != 0) {
      uVar9 = uVar2;
    }
    *__dest = uVar9;
    lVar7 = plVar3[4];
    uVar5 = plVar3[5];
    uVar6 = lVar7 + 4;
    __dest = (uint *)(plVar3[3] + 4);
    plVar3[3] = (long)__dest;
    plVar3[4] = uVar6;
    uVar9 = *(uint *)(param_2 + 0x18);
    if (lVar7 + 8U <= uVar5) goto LAB_0026492c;
  }
  __src = *(void **)(param_2 + 0x20);
joined_r0x002648e8:
  if ((__src != (void *)0x0) && (uVar8 = (ulong)uVar9, uVar6 + uVar8 <= uVar5)) {
    memcpy(__dest,__src,uVar8);
    uVar5 = plVar3[5];
    uVar6 = plVar3[4] + uVar8;
    __dest = (uint *)(plVar3[3] + uVar8);
    plVar3[3] = (long)__dest;
    plVar3[4] = uVar6;
  }
  if (uVar6 + 4 <= uVar5) {
    uVar2 = *(uint *)(param_2 + 0xc);
    uVar9 = (uVar2 & 0xff00ff00) >> 8 | (uVar2 & 0xff00ff) << 8;
    uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
    if (*(int *)((long)plVar3 + 0x3c) != 0) {
      uVar9 = uVar2;
    }
    *__dest = uVar9;
    plVar3[3] = plVar3[3] + 4;
    plVar3[4] = plVar3[4] + 4;
  }
  lVar7 = plVar3[6];
  *param_3 = uVar10;
  plVar3[6] = 0;
  *param_1 = lVar7;
  lVar7 = FUN_0023cb40(0xffffffffffffffff,plVar3 + 1);
  if (lVar7 != 0) {
    return;
  }
  (**(code **)(*plVar3 + 0x10))(plVar3);
  FUN_001f9ca4(plVar3);
  return;
}
