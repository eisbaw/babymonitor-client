// Ghidra decompilation of computeDigest  (entry=00115ad0)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00115ad0(long *param_1,undefined8 param_2,long param_3,long param_4)

{
  ulong uVar1;
  long lVar2;
  undefined1 *puVar3;
  char *__s;
  long lVar4;
  size_t __n;
  undefined8 uVar5;
  void *pvVar6;
  ulong local_d0;
  size_t sStack_c8;
  void *local_c0;
  ulong local_b0;
  undefined8 local_a8;
  void *local_a0;
  ulong local_98;
  size_t sStack_90;
  void *local_88;
  ulong local_80;
  undefined8 uStack_78;
  void *local_70;
  long local_68;
  
  lVar2 = tpidr_el0;
  local_68 = *(long *)(lVar2 + 0x28);
  if ((param_4 == 0) ||
     (__s = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_4,0), __s == (char *)0x0)) {
    uVar5 = 0;
  }
  else {
    local_80 = 0;
    uStack_78 = 0;
    local_70 = (void *)0x0;
    if (param_3 == 0) {
      lVar4 = 0;
    }
    else {
                    /* try { // try from 00115b3c to 00115ba7 has its CatchHandler @ 00115dd0 */
      lVar4 = (**(code **)(*param_1 + 0x548))(param_1,param_3,0);
      if (lVar4 != 0) {
        std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
        ::assign((char *)&local_80);
        std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>
        ::append((char *)&local_80);
      }
    }
    puVar3 = DAT_00139080;
    if ((DAT_00139070 & 1) == 0) {
      puVar3 = &DAT_00139071;
    }
    std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::
    append((char *)&local_80,(ulong)puVar3);
    __n = strlen(__s);
    if (0xffffffffffffffef < __n) {
      if (*(long *)(lVar2 + 0x28) == local_68) {
                    /* try { // try from 00115d90 to 00115d97 has its CatchHandler @ 00115dc8 */
                    /* WARNING: Subroutine does not return */
        FUN_001171f4(&local_98);
      }
      goto LAB_00115e24;
    }
    if (__n < 0x17) {
      pvVar6 = (void *)((ulong)&local_98 | 1);
      local_98 = CONCAT71(local_98._1_7_,(char)((int)__n << 1));
      if (__n != 0) goto LAB_00115bfc;
    }
    else {
      uVar1 = (__n | 0xf) + 1;
                    /* try { // try from 00115be4 to 00115beb has its CatchHandler @ 00115dc8 */
      pvVar6 = operator_new(uVar1);
      local_98 = uVar1 | 1;
      sStack_90 = __n;
      local_88 = pvVar6;
LAB_00115bfc:
      memmove(pvVar6,__s,__n);
    }
    *(undefined1 *)((long)pvVar6 + __n) = 0;
                    /* try { // try from 00115c10 to 00115c27 has its CatchHandler @ 00115dc0 */
    std::__ndk1::operator+("||",(basic_string *)&local_80);
    pvVar6 = (void *)((ulong)&local_b0 | 1);
    if ((local_b0 & 1) != 0) {
      pvVar6 = local_a0;
    }
                    /* try { // try from 00115c44 to 00115c4b has its CatchHandler @ 00115db0 */
    std::__ndk1::basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>::
    append((char *)&local_98,(ulong)pvVar6);
    if (((byte)local_b0 & 1) != 0) {
      operator_delete(local_a0);
    }
    local_b0 = 0;
    local_a8 = 0;
    local_a0 = (void *)0x0;
    if ((local_98 & 1) == 0) {
      sStack_c8 = sStack_90;
      local_d0 = local_98;
      local_c0 = local_88;
    }
    else {
                    /* try { // try from 00115c84 to 00115c8b has its CatchHandler @ 00115dd8 */
      FUN_001172b0(&local_d0,local_88,sStack_90);
    }
                    /* try { // try from 00115c8c to 00115c97 has its CatchHandler @ 00115d98 */
    FUN_00113318(&local_d0,&local_b0);
    if ((local_d0 & 1) != 0) {
      operator_delete(local_c0);
    }
                    /* try { // try from 00115cb0 to 00115d03 has its CatchHandler @ 00115dd8 */
    (**(code **)(*param_1 + 0x550))(param_1,param_4,__s);
    if (lVar4 != 0) {
      (**(code **)(*param_1 + 0x550))(param_1,param_3,lVar4);
    }
    pvVar6 = (void *)((ulong)&local_b0 | 1);
    if ((local_b0 & 1) != 0) {
      pvVar6 = local_a0;
    }
    uVar5 = (**(code **)(*param_1 + 0x538))(param_1,pvVar6);
    if ((local_b0 & 1) != 0) {
      operator_delete(local_a0);
    }
    if ((local_98 & 1) != 0) {
      operator_delete(local_88);
    }
    if ((local_80 & 1) != 0) {
      operator_delete(local_70);
    }
  }
  if (*(long *)(lVar2 + 0x28) == local_68) {
    return uVar5;
  }
LAB_00115e24:
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

