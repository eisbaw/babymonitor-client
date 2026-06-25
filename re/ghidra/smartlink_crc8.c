// crc8 @ 00110a60

/* crc8(unsigned char*, unsigned char) */

uint crc8(uchar *param_1,uchar param_2)

{
  uint uVar1;
  
  if (param_2 != '\0') {
    uVar1 = 0;
    do {
      param_2 = param_2 + 0xff;
      uVar1 = (uint)(byte)PTR_crc8_table_00139ff8[*param_1 ^ uVar1];
      param_1 = param_1 + 1;
    } while (param_2 != '\0');
    return uVar1;
  }
  return 0;
}

