// Ghidra decompilation of getEncryptoKey  (entry=00115368)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long FUN_00115368(long *param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  ulong uVar1;
  ulong uVar2;
  long lVar3;
  byte bVar4;
  long lVar5;
  long lVar6;
  ulong *puVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  size_t sVar10;
  uint uVar11;
  undefined1 *puVar12;
  size_t sVar13;
  void *pvVar14;
  ulong local_e8;
  size_t local_e0;
  undefined1 *local_d8;
  ulong local_d0;
  ulong uStack_c8;
  void *local_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  ulong local_88;
  ulong local_80;
  void *local_78;
  long local_68;
  
  lVar3 = tpidr_el0;
  local_68 = *(long *)(lVar3 + 0x28);
  local_e8 = 0;
  local_e0 = 0;
  local_d8 = (undefined1 *)0x0;
                    /* try { // try from 001153b0 to 001153db has its CatchHandler @ 00115708 */
  lVar5 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
  if (lVar5 != 0) {
    if (param_4 == 0) {
      sVar10 = 0;
      uVar11 = 0;
    }
    else {
      lVar6 = (**(code **)(*param_1 + 0x548))(param_1,param_4,0);
      bVar4 = DAT_00139070;
      if (lVar6 == 0) {
        lVar5 = 0;
        goto LAB_00115630;
      }
      sVar10 = (ulong)(DAT_00139070 >> 1);
      if ((DAT_00139070 & 1) != 0) {
        sVar10 = ram0x00139078;
      }
      uVar1 = sVar10 + 1;
      if (0xffffffffffffffef < uVar1) {
        if (*(long *)(lVar3 + 0x28) == local_68) {
                    /* try { // try from 00115684 to 0011568b has its CatchHandler @ 00115700 */
                    /* WARNING: Subroutine does not return */
          FUN_001171f4(&local_88);
        }
        goto LAB_001156c8;
      }
      if (uVar1 < 0x17) {
        local_80 = 0;
        pvVar14 = (void *)((ulong)&local_88 | 1);
        local_78 = (void *)0x0;
        local_88 = (ulong)(byte)((int)uVar1 << 1);
        if (sVar10 != 0) goto LAB_00115468;
      }
      else {
        uVar2 = (uVar1 | 0xf) + 1;
                    /* try { // try from 00115450 to 00115457 has its CatchHandler @ 00115700 */
        pvVar14 = operator_new(uVar2);
        local_88 = uVar2 | 1;
        local_80 = uVar1;
        local_78 = pvVar14;
LAB_00115468:
        puVar12 = &DAT_00139071;
        if ((bVar4 & 1) != 0) {
          puVar12 = DAT_00139080;
        }
        memmove(pvVar14,puVar12,sVar10);
      }
      *(undefined2 *)((long)pvVar14 + sVar10) = 0x5f;
                    /* try { // try from 00115490 to 0011549b has its CatchHandler @ 001156e0 */
      puVar7 = (ulong *)std::__ndk1::
                        basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
                        ::append((char *)&local_88);
      local_c0 = (void *)puVar7[2];
      uStack_c8 = puVar7[1];
      local_d0 = *puVar7;
      puVar7[1] = 0;
      puVar7[2] = 0;
      *puVar7 = 0;
      pvVar14 = (void *)((ulong)&local_d0 | 1);
      if ((local_d0 & 1) != 0) {
        pvVar14 = local_c0;
      }
                    /* try { // try from 001154d4 to 001154db has its CatchHandler @ 0011568c */
      std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::
      append((char *)&local_e8,(ulong)pvVar14);
      if ((local_d0 & 1) != 0) {
        operator_delete(local_c0);
      }
      if ((local_88 & 1) != 0) {
        operator_delete(local_78);
      }
      uVar11 = (uint)(byte)local_e8;
      sVar10 = local_e0;
    }
    sVar13 = (ulong)(uVar11 >> 1);
    if ((uVar11 & 1) != 0) {
      sVar13 = sVar10;
    }
    if ((sVar13 == 0) && (sVar13 = (ulong)(DAT_00139070 >> 1), (DAT_00139070 & 1) != 0)) {
      sVar13 = ram0x00139078;
    }
    local_88 = local_88 & 0xffffffffffffff00;
                    /* try { // try from 00115534 to 001155af has its CatchHandler @ 0011570c */
    uVar8 = FUN_0011775c(6);
    uVar9 = __strlen_chk(lVar5,0xffffffffffffffff);
    sVar10 = local_e8 >> 1 & 0x7f;
    if ((local_e8 & 1) != 0) {
      sVar10 = local_e0;
    }
    if (sVar10 == 0) {
      puVar12 = DAT_00139080;
      if ((DAT_00139070 & 1) == 0) {
        puVar12 = &DAT_00139071;
      }
    }
    else {
      puVar12 = (undefined1 *)((ulong)&local_e8 | 1);
      if ((local_e8 & 1) != 0) {
        puVar12 = local_d8;
      }
    }
    FUN_001179f8(uVar8,lVar5,uVar9,puVar12,sVar13,&local_88);
    lVar5 = 0;
    puVar7 = &local_d0;
    uStack_c8 = 0;
    local_d0 = 0;
    uStack_b8 = 0;
    local_c0 = (void *)0x0;
    uStack_a8 = 0;
    local_b0 = 0;
    uStack_98 = 0;
    uStack_a0 = 0;
    do {
                    /* try { // try from 001155d0 to 001155df has its CatchHandler @ 00115710 */
      FUN_00116ae4(puVar7,0xffffffffffffffff,&DAT_001090ea,*(undefined1 *)((long)&local_88 + lVar5))
      ;
      lVar5 = lVar5 + 1;
      puVar7 = (ulong *)((long)puVar7 + 2);
    } while (lVar5 != 0x20);
    local_c0 = (void *)((ulong)local_c0 & 0xffffffffffffff00);
                    /* try { // try from 001155fc to 0011562f has its CatchHandler @ 00115704 */
    lVar5 = (**(code **)(*param_1 + 0x580))(param_1,0x10);
    if (lVar5 != 0) {
      (**(code **)(*param_1 + 0x680))(param_1,lVar5,0,0x10,&local_d0);
    }
  }
LAB_00115630:
  if ((local_e8 & 1) != 0) {
    operator_delete(local_d8);
  }
  if (*(long *)(lVar3 + 0x28) == local_68) {
    return lVar5;
  }
LAB_001156c8:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

