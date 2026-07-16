// Ghidra decompilation of thingframe_serialize  (entry=00262eb4)

void FUN_00262eb4(long *param_1,long param_2,ulong *param_3,ulong param_4)

{
  long lVar1;
  int iVar2;
  uint uVar3;
  long *plVar4;
  uint *puVar5;
  uint *__dest;
  void *__src;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  ulong uVar9;
  ulong uVar10;
  uint uVar11;

  uVar11 = *(uint *)(param_2 + 0x18);
  uVar9 = (ulong)(uVar11 + 0x10);
  plVar4 = (long *)FUN_0023abf0(0x40);
  *plVar4 = (long)&PTR_FUN_002c5c58;
  plVar4[1] = 0;
  plVar4[2] = 0;
  plVar4[3] = 0;
  plVar4[4] = 0;
  plVar4[5] = uVar9;
  plVar4[6] = 0;
  *(undefined1 *)(plVar4 + 7) = 0;
  *(undefined4 *)((long)plVar4 + 0x3c) = 0;
                    /* try { // try from 00262f10 to 00262f17 has its CatchHandler @ 00263148 */
  puVar5 = (uint *)thunk_FUN_0023abf0(uVar9);
  plVar4[6] = (long)puVar5;
  plVar4[3] = (long)puVar5;
  if (uVar11 + 0x10 < 4) {
    uVar8 = 0;
    uVar10 = 4;
    __dest = puVar5;
    uVar6 = uVar10;
    if (uVar9 < 4) goto joined_r0x00262f50;
  }
  else {
    uVar8 = 4;
    uVar3 = (*(uint *)(param_2 + 8) & 0xff00ff00) >> 8 | (*(uint *)(param_2 + 8) & 0xff00ff) << 8;
    __dest = puVar5 + 1;
    *puVar5 = uVar3 >> 0x10 | uVar3 << 0x10;
    plVar4[3] = (long)__dest;
    plVar4[4] = 4;
    uVar10 = 8;
    uVar6 = uVar10;
    if (uVar9 < 8) goto joined_r0x00262f50;
  }
  uVar3 = (*(uint *)(param_2 + 0x10) & 0xff00ff00) >> 8 |
          (*(uint *)(param_2 + 0x10) & 0xff00ff) << 8;
  *__dest = uVar3 >> 0x10 | uVar3 << 0x10;
  plVar4[3] = (long)(__dest + 1);
  plVar4[4] = uVar10;
  __dest = __dest + 1;
  uVar6 = uVar8 | 8;
  uVar8 = uVar10;
joined_r0x00262f50:
  if (uVar6 <= uVar9) {
    lVar7 = plVar4[3];
    lVar1 = plVar4[4];
    uVar9 = plVar4[5];
    uVar11 = (*(uint *)(param_2 + 0x14) & 0xff00ff00) >> 8 |
             (*(uint *)(param_2 + 0x14) & 0xff00ff) << 8;
    *__dest = uVar11 >> 0x10 | uVar11 << 0x10;
    uVar8 = lVar1 + 4;
    __dest = (uint *)(lVar7 + 4);
    uVar11 = *(uint *)(param_2 + 0x18);
    uVar6 = lVar1 + 8;
    plVar4[3] = (long)__dest;
    plVar4[4] = uVar8;
  }
  if (uVar6 <= uVar9) {
    uVar3 = (uVar11 & 0xff00ff00) >> 8 | (uVar11 & 0xff00ff) << 8;
    uVar3 = uVar3 >> 0x10 | uVar3 << 0x10;
    if (*(int *)((long)plVar4 + 0x3c) != 0) {
      uVar3 = uVar11;
    }
    *__dest = uVar3;
    uVar11 = *(uint *)(param_2 + 0x18);
    uVar9 = plVar4[5];
    uVar8 = plVar4[4] + 4;
    __dest = (uint *)(plVar4[3] + 4);
    plVar4[3] = (long)__dest;
    plVar4[4] = uVar8;
  }
  if ((param_4 & 1) == 0) {
    uVar11 = uVar11 - 8;
    __src = *(void **)(param_2 + 0x20);
  }
  else {
    if (uVar8 + 4 <= uVar9) {
      uVar3 = *(uint *)(param_2 + 0x1c);
      uVar11 = (uVar3 & 0xff00ff00) >> 8 | (uVar3 & 0xff00ff) << 8;
      uVar11 = uVar11 >> 0x10 | uVar11 << 0x10;
      if (*(int *)((long)plVar4 + 0x3c) != 0) {
        uVar11 = uVar3;
      }
      *__dest = uVar11;
      uVar11 = *(uint *)(param_2 + 0x18);
      uVar9 = plVar4[5];
      uVar8 = plVar4[4] + 4;
      __dest = (uint *)(plVar4[3] + 4);
      plVar4[3] = (long)__dest;
      plVar4[4] = uVar8;
    }
    uVar11 = uVar11 - 0xc;
    __src = *(void **)(param_2 + 0x20);
  }
  if ((__src != (void *)0x0) && (uVar10 = (ulong)uVar11, uVar8 + uVar10 <= uVar9)) {
    memcpy(__dest,__src,uVar10);
    uVar9 = plVar4[5];
    uVar8 = plVar4[4] + uVar10;
    __dest = (uint *)(plVar4[3] + uVar10);
    plVar4[3] = (long)__dest;
    plVar4[4] = uVar8;
  }
  uVar8 = uVar8 + 4;
  if (uVar8 <= uVar9) {
    uVar3 = *(uint *)(param_2 + 0x28);
    uVar11 = (uVar3 & 0xff00ff00) >> 8 | (uVar3 & 0xff00ff) << 8;
    uVar11 = uVar11 >> 0x10 | uVar11 << 0x10;
    if (*(int *)((long)plVar4 + 0x3c) != 0) {
      uVar11 = uVar3;
    }
    *__dest = uVar11;
    uVar9 = plVar4[5];
    __dest = (uint *)(plVar4[3] + 4);
    uVar8 = plVar4[4] + 8;
    plVar4[3] = (long)__dest;
    plVar4[4] = plVar4[4] + 4;
  }
  if (uVar8 <= uVar9) {
    uVar3 = *(uint *)(param_2 + 0xc);
    uVar11 = (uVar3 & 0xff00ff00) >> 8 | (uVar3 & 0xff00ff) << 8;
    uVar11 = uVar11 >> 0x10 | uVar11 << 0x10;
    if (*(int *)((long)plVar4 + 0x3c) != 0) {
      uVar11 = uVar3;
    }
    *__dest = uVar11;
    plVar4[3] = plVar4[3] + 4;
    plVar4[4] = plVar4[4] + 4;
  }
  iVar2 = *(int *)(param_2 + 0x18);
  lVar7 = plVar4[6];
  plVar4[6] = 0;
  *param_1 = lVar7;
  *param_3 = (ulong)(iVar2 + 0x10);
  lVar7 = FUN_0023cb40(0xffffffffffffffff,plVar4 + 1);
  if (lVar7 != 0) {
    return;
  }
  (**(code **)(*plVar4 + 0x10))(plVar4);
  FUN_001f9ca4(plVar4);
  return;
}
