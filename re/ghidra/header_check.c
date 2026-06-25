// Ghidra decompilation of header_check  (entry=00104a34)

undefined4 FUN_00104a34(char *param_1,long param_2)

{
  undefined4 local_4;
  
  if ((*param_1 == 'B') && (param_1[1] == 'M')) {
    if (*(uint *)(param_1 + 2) < 0x200001) {
      if (*(uint *)(param_1 + 2) < 0x2800) {
        local_4 = 0x15;
      }
      else if ((ulong)*(uint *)(param_1 + 2) - 0x36 < (ulong)*(uint *)(param_1 + 10)) {
        local_4 = 0x15;
      }
      else if ((*(short *)(param_2 + 0xe) == 0x18) || (*(short *)(param_2 + 0xe) == 0x20)) {
        if (*(int *)(param_2 + 0x10) == 0) {
          local_4 = 0;
        }
        else {
          local_4 = 0x15;
        }
      }
      else {
        local_4 = 0x15;
      }
    }
    else {
      local_4 = 0x15;
    }
  }
  else {
    local_4 = 0x15;
  }
  return local_4;
}

