// Ghidra decompilation of imm_p2p_h264_packetize  (entry=00150580)

int imm_p2p_h264_packetize(undefined8 param_1,char *param_2,int param_3,undefined8 param_4)

{
  char *pcVar1;
  char cVar2;
  long lVar3;
  int iVar4;
  undefined8 uVar5;
  char *pcVar6;
  long lVar7;
  int iVar8;
  char *pcVar9;
  char *pcVar10;
  ulong uVar11;
  
  if (param_3 < 1) {
    iVar8 = 0;
  }
  else {
    pcVar6 = param_2 + param_3;
    iVar8 = 0;
    pcVar10 = pcVar6 + -3;
    do {
      if (pcVar10 < param_2) {
LAB_00150700:
        pcVar6 = "find next nal unit failed: can find nal start\n";
        uVar5 = 0x8c;
LAB_00150718:
        imm_p2p_log_log(4,&DAT_0023571f,uVar5,pcVar6);
        pcVar6 = "h264 packetize failed: find next nal unit failed\n";
        uVar5 = 0xb0;
LAB_00150734:
        imm_p2p_log_log(4,&DAT_0023571f,uVar5,pcVar6);
        return -1;
      }
      if (*param_2 == '\0') goto LAB_001505f8;
      do {
        do {
          param_2 = param_2 + 1;
          if (pcVar10 < param_2) goto LAB_00150700;
        } while (*param_2 != '\0');
LAB_001505f8:
      } while ((param_2[1] != '\0') || (param_2[2] != '\x01'));
      if (pcVar6 <= param_2 + 3) {
        pcVar6 = "find next nal unit failed: can find nal header\n";
        uVar5 = 0x91;
        goto LAB_00150718;
      }
      cVar2 = param_2[3];
      pcVar1 = param_2 + 4;
      pcVar9 = pcVar6;
      if (pcVar1 <= pcVar10) {
        lVar7 = 0;
        do {
          if (((param_2[lVar7 + 4] == '\0') && (param_2[lVar7 + 5] == '\0')) &&
             (param_2[lVar7 + 6] == '\x01')) {
            pcVar9 = param_2 + lVar7 + 4;
            if ((4 < lVar7 + 4U) && (pcVar9 = param_2 + lVar7 + 3, param_2[lVar7 + 3] != '\0')) {
              pcVar9 = param_2 + lVar7 + 4;
            }
            break;
          }
          lVar3 = lVar7 + 5;
          lVar7 = lVar7 + 1;
        } while (param_2 + lVar3 <= pcVar10);
      }
      uVar11 = (long)pcVar9 - (long)pcVar1;
      imm_p2p_log_log(1,&DAT_0023571f,0x77,"h264 packetize nal: %p:%d\n",pcVar1,uVar11 & 0xffffffff)
      ;
      if ((int)uVar11 < 0x4a7) {
        iVar4 = imm_p2p_h264_packetize_nal_stapa(param_1,pcVar1,uVar11 & 0xffffffff,cVar2,param_4);
      }
      else {
        iVar4 = imm_p2p_h264_packetize_nal_fua();
      }
      if (iVar4 < 0) {
        pcVar6 = "h264 packetize failed: packetize nal failed\n";
        uVar5 = 0xb5;
        goto LAB_00150734;
      }
      iVar8 = iVar4 + iVar8;
      param_2 = pcVar9;
    } while (pcVar9 < pcVar6);
  }
  return iVar8;
}

