// Ghidra decompilation of imm_p2p_rtc_sdp_get_aes_key  (entry=001737ec)

undefined8 imm_p2p_rtc_sdp_get_aes_key(long param_1,byte *param_2,uint param_3)

{
  char cVar1;
  byte bVar2;
  ulong uVar3;
  
  if (0x2f < param_3 << 1) {
    return 0xffffffff;
  }
  if (param_3 != 0) {
    uVar3 = 0;
    do {
      cVar1 = imm_p2p_misc_char_to_hex(*(undefined1 *)(param_1 + 0x86 + (uVar3 & 0xffffffff)));
      *param_2 = cVar1 << 4;
      bVar2 = imm_p2p_misc_char_to_hex(*(undefined1 *)(param_1 + 0x86 + (ulong)((int)uVar3 + 1)));
      uVar3 = uVar3 + 2;
      *param_2 = *param_2 | bVar2;
      param_2 = param_2 + 1;
    } while ((ulong)param_3 * 2 - uVar3 != 0);
    return 0;
  }
  return 0;
}

