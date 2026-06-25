// Ghidra decompilation of jstr_to_std  (entry=001139cc)

void FUN_001139cc(long *param_1,long *param_2,undefined8 param_3)

{
  char *__s;
  size_t __n;
  void *__dest;
  
  __s = (char *)(**(code **)(*param_2 + 0x548))(param_2,param_3,0);
  if (__s == (char *)0x0) {
    *(undefined2 *)param_1 = 0;
    return;
  }
  __n = strlen(__s);
  if (0xffffffffffffffef < __n) {
                    /* WARNING: Subroutine does not return */
    FUN_001171f4(param_1);
  }
  if (__n < 0x17) {
    __dest = (void *)((long)param_1 + 1);
    *(char *)param_1 = (char)((int)__n << 1);
    if (__n == 0) goto LAB_00113a68;
  }
  else {
    __dest = operator_new((__n | 0xf) + 1);
    param_1[1] = __n;
    param_1[2] = (long)__dest;
    *param_1 = (__n | 0xf) + 2;
  }
  memmove(__dest,__s,__n);
LAB_00113a68:
  *(undefined1 *)((long)__dest + __n) = 0;
                    /* try { // try from 00113a74 to 00113a83 has its CatchHandler @ 00113aa4 */
  (**(code **)(*param_2 + 0x550))(param_2,param_3,__s);
  return;
}

