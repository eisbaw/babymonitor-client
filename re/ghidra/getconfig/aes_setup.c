// Ghidra decompilation of aes_setup  (entry=00111f04)

void FUN_00111f04(long param_1,undefined8 param_2,int param_3)

{
  int iVar1;
  
  *(undefined1 *)(param_1 + 0x1a8) = 0;
  mbedtls_gcm_init();
  iVar1 = mbedtls_gcm_setkey(param_1,2,param_2,param_3 << 3);
  *(bool *)(param_1 + 0x1a8) = iVar1 == 0;
  return;
}

