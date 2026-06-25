// Ghidra decompilation of aes_decrypt  (entry=00111f80)

undefined8
FUN_00111f80(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined8 param_9,undefined8 param_10)

{
  undefined8 uVar1;
  
  if (*(char *)(param_1 + 0x1a8) != '\0') {
    uVar1 = mbedtls_gcm_auth_decrypt
                      (param_1,param_6,param_2,param_8,param_3,param_9,param_4,param_10);
    return uVar1;
  }
  return 0xffffffff;
}

