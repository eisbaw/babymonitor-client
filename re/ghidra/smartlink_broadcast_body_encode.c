// broadcast_body_encode_real -> ghidra func broadcast_body_encode @ 00110b7c

/* broadcast_body_encode(char const*, char const*, char const*) */

void broadcast_body_encode(char *param_1,char *param_2,char *param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  undefined *puVar5;
  size_t sVar6;
  size_t sVar7;
  size_t sVar8;
  undefined1 *__s;
  ushort *puVar9;
  ulong uVar10;
  ulong uVar11;
  uint uVar12;
  ulong uVar13;
  ulong __size;
  long lVar14;
  
  sVar6 = strlen(param_1);
  sVar7 = strlen(param_2);
  sVar8 = strlen(param_3);
  puVar5 = PTR_crc8_table_00139ff8;
  iVar2 = (uint)sVar7 + (int)sVar6 + (int)sVar8;
  uVar1 = iVar2 + 2;
  bVar4 = PTR_crc8_table_00139ff8[(ulong)uVar1 & 0xff];
  uVar3 = (2U - iVar2 & 3) + uVar1;
  __size = (ulong)uVar3 & 0xff;
  uVar12 = (uint)sVar7 & 0xff;
  __s = (undefined1 *)malloc(__size);
  memset(__s,0,__size);
  *__s = (char)sVar7;
  memcpy(__s + 1,param_2,sVar7 & 0xff);
  __s[(ulong)uVar12 + 1] = (char)sVar8;
  memcpy(__s + (ulong)uVar12 + 2,param_3,sVar8 & 0xff);
  memcpy(__s + (sVar8 & 0xff) + (ulong)uVar12 + 2,param_1,sVar6 & 0xff);
  lVar14 = *(long *)PTR_broadcast_link_info_00139f28;
  iVar2 = (uVar3 >> 2 & 0x3f) * 6 + 4;
  *(short *)(lVar14 + 0x10) = (short)iVar2;
  puVar9 = (ushort *)malloc((ulong)(uint)(iVar2 * 2));
  *(ushort **)(lVar14 + 8) = puVar9;
  if ((uVar3 & 0xff) != 0) {
    uVar10 = 0;
    uVar11 = 0;
    uVar13 = 4;
    do {
      uVar3 = *(uint *)(__s + uVar10);
      uVar10 = uVar10 + 4;
      uVar12 = (uint)uVar13;
      puVar9[uVar13 & 0xff] =
           (byte)puVar5[(uint)(byte)puVar5[(ulong)((uint)(byte)puVar5[(ulong)((uint)(byte)puVar5[(
                                                  ulong)((byte)puVar5[uVar11 & 0xff] ^ uVar3) & 0xff
                                                  ] ^ uVar3 >> 8) & 0xff] ^ uVar3 >> 0x10) & 0xff] ^
                        uVar3 >> 0x18] | 0x80;
      puVar9[(ulong)(uVar12 | 1) & 0xff] = (ushort)uVar11 & 0xff | 0x80;
      puVar9[(ulong)(uVar12 + 2) & 0xff] = (ushort)uVar3 & 0xff | 0x100;
      puVar9[(ulong)(uVar12 + 3) & 0xff] = (ushort)(uVar3 >> 8) & 0xff | 0x100;
      uVar13 = (ulong)(uVar12 + 6);
      uVar11 = (ulong)((int)uVar11 + 1);
      puVar9[(ulong)(uVar12 + 4) & 0xff] = (ushort)(uVar3 >> 0x10) & 0xff | 0x100;
      puVar9[(ulong)(uVar12 + 5) & 0xff] = (byte)(uVar3 >> 0x18) | 0x100;
    } while (uVar10 < __size);
  }
  *puVar9 = (ushort)(uVar1 >> 4) & 0xf | 0x10;
  puVar9[1] = (ushort)uVar1 & 0xf | 0x20;
  puVar9[2] = bVar4 >> 4 | 0x30;
  puVar9[3] = bVar4 & 0xf | 0x40;
  free(__s);
  return;
}

