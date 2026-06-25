// Ghidra decompilation of imm_p2p_rtc_sdp_set_aes_key  (entry=00173750)

undefined8 imm_p2p_rtc_sdp_set_aes_key(long param_1,byte *param_2,uint param_3)

{
  undefined1 uVar1;
  undefined8 uVar2;
  int iVar3;
  ulong uVar4;
  
  if (param_3 << 1 < 0x30) {
    *(undefined8 *)(param_1 + 0xae) = 0;
    *(undefined8 *)(param_1 + 0xa6) = 0;
    *(undefined8 *)(param_1 + 0x9e) = 0;
    *(undefined8 *)(param_1 + 0x96) = 0;
    *(undefined8 *)(param_1 + 0x8e) = 0;
    *(undefined8 *)(param_1 + 0x86) = 0;
    if (param_3 != 0) {
      uVar4 = 0;
      do {
        uVar1 = imm_p2p_misc_hex_to_char(*param_2 >> 4);
        *(undefined1 *)(param_1 + 0x86 + (uVar4 & 0xffffffff)) = uVar1;
        uVar1 = imm_p2p_misc_hex_to_char(*param_2 & 0xf);
        iVar3 = (int)uVar4;
        uVar4 = uVar4 + 2;
        *(undefined1 *)(param_1 + 0x86 + (ulong)(iVar3 + 1)) = uVar1;
        param_2 = param_2 + 1;
      } while ((ulong)param_3 * 2 - uVar4 != 0);
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

