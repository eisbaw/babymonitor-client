// multicast_body_encode_real -> ghidra func multicast_body_encode @ 00111190

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* multicast_body_encode(char const*, char const*, char const*) */

void multicast_body_encode(char *param_1,char *param_2,char *param_3)

{
  uint uVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  long lVar5;
  int iVar6;
  size_t sVar7;
  size_t sVar8;
  size_t sVar9;
  uchar *__s;
  void *pvVar10;
  void *pvVar11;
  uint *puVar12;
  uint uVar13;
  long lVar14;
  ulong uVar15;
  ulong uVar16;
  byte *pbVar17;
  int iVar18;
  ulong uVar19;
  long *plVar20;
  int iVar21;
  long lVar22;
  int iVar23;
  int iVar24;
  ushort *puVar25;
  long lVar26;
  uint local_d4;
  uint local_c4;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 local_78;
  undefined8 uStack_70;
  long local_68;
  
  lVar5 = tpidr_el0;
  local_68 = *(long *)(lVar5 + 0x28);
  sVar7 = strlen(param_1);
  sVar8 = strlen(param_2);
  sVar9 = strlen(param_3);
  iVar21 = (int)sVar7;
  iVar6 = (int)sVar9;
  if (iVar21 < 1) {
    uVar13 = 0;
  }
  else {
    uVar16 = sVar7 & 0xffffffff;
    uVar13 = 0xffffffff;
    pbVar17 = (byte *)param_1;
    do {
      uVar1 = uVar13 & 0xff ^ (uint)*pbVar17;
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar4 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar16 = uVar16 - 1;
      uVar13 = uVar1 ^ uVar13 >> 8;
      pbVar17 = pbVar17 + 1;
    } while (uVar16 != 0);
    uVar13 = ~uVar13;
  }
  if (iVar6 < 1) {
    local_c4 = 0;
  }
  else {
    uVar16 = sVar9 & 0xffffffff;
    local_c4 = 0xffffffff;
    pbVar17 = (byte *)param_3;
    do {
      uVar1 = local_c4 & 0xff ^ (uint)*pbVar17;
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar4 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar16 = uVar16 - 1;
      local_c4 = uVar1 ^ local_c4 >> 8;
      pbVar17 = pbVar17 + 1;
    } while (uVar16 != 0);
    local_c4 = ~local_c4;
  }
  iVar23 = (int)sVar8;
  if (iVar23 < 1) {
    local_d4 = 0;
    uVar16 = 0x10;
  }
  else {
    uVar16 = sVar8 & 0xffffffff;
    local_d4 = 0xffffffff;
    pbVar17 = (byte *)param_2;
    do {
      uVar1 = local_d4 & 0xff ^ (uint)*pbVar17;
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar4 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar4 = uVar1 >> 1;
      if ((uVar1 & 1) != 0) {
        uVar4 = uVar1 >> 1 ^ 0xedb88320;
      }
      uVar1 = uVar4 >> 1;
      if ((uVar4 & 1) != 0) {
        uVar1 = uVar4 >> 1 ^ 0xedb88320;
      }
      uVar16 = uVar16 - 1;
      local_d4 = uVar1 ^ local_d4 >> 8;
      pbVar17 = pbVar17 + 1;
    } while (uVar16 != 0);
    local_d4 = ~local_d4;
    uVar16 = (ulong)((-iVar23 & 0xfU) + iVar23);
  }
  uVar19 = uVar16 & 0xff;
  __s = (uchar *)malloc(uVar19);
  memset(__s,0,uVar19);
  memcpy(__s,param_2,(long)iVar23);
  local_78 = 0;
  uStack_70 = 0;
  uVar4 = (uint)uVar16 & 0xff;
  uStack_88 = _UNK_0012b0c8;
  local_90 = _DAT_0012b0c0;
  pvVar10 = malloc(uVar19 << 1);
  memset(pvVar10,0,uVar19 << 1);
  AES128_CBC_encrypt_buffer(pvVar10,__s,uVar4,&local_90,&local_78);
  memcpy(__s,pvVar10,uVar19);
  free(pvVar10);
  plVar20 = (long *)PTR_multicast_link_info_00139f58;
  lVar22 = 0;
  lVar26 = *(long *)PTR_multicast_link_info_00139f58;
  puVar25 = &DAT_0012b0d2;
  puVar12 = *(uint **)(lVar26 + 0x28);
  *(uint **)(lVar26 + 0x30) = puVar12;
  do {
    uVar3 = puVar25[-1];
    uVar2 = *puVar25;
    uVar1 = (uint)lVar22 | 0x78;
    if (puVar12 == *(uint **)(lVar26 + 0x38)) {
      pvVar10 = *(void **)(lVar26 + 0x28);
      sVar8 = *(long *)(lVar26 + 0x30) - (long)pvVar10;
      uVar16 = ((long)sVar8 >> 2) * -0x5555555555555555 + 1;
      if (0x1555555555555555 < uVar16) {
        std::__ndk1::__vector_base_common<true>::__throw_length_error();
        goto LAB_0011179c;
      }
      lVar14 = (long)*(uint **)(lVar26 + 0x38) - (long)pvVar10 >> 2;
      uVar19 = 0x1555555555555555;
      if ((ulong)(lVar14 * -0x5555555555555555) < 0xaaaaaaaaaaaaaaa) {
        uVar15 = lVar14 * 0x5555555555555556;
        uVar19 = uVar16;
        if (uVar16 <= uVar15) {
          uVar19 = uVar15;
        }
        if (uVar19 != 0) goto LAB_00111594;
        pvVar11 = (void *)0x0;
      }
      else {
LAB_00111594:
        pvVar11 = operator_new(uVar19 * 0xc);
      }
      puVar12 = (uint *)((long)pvVar11 + ((long)sVar8 >> 2) * 4);
      puVar12[2] = (uint)uVar3;
      *puVar12 = uVar1;
      puVar12[1] = (uint)uVar2;
      if (0 < (long)sVar8) {
        memcpy((void *)((long)puVar12 - sVar8),pvVar10,sVar8);
      }
      *(void **)(lVar26 + 0x28) = (void *)((long)puVar12 - sVar8);
      *(uint **)(lVar26 + 0x30) = puVar12 + 3;
      *(void **)(lVar26 + 0x38) = (void *)((long)pvVar11 + uVar19 * 0xc);
      plVar20 = (long *)PTR_multicast_link_info_00139f58;
      if (pvVar10 != (void *)0x0) {
        operator_delete(pvVar10);
      }
    }
    else {
      *puVar12 = uVar1;
      puVar12[1] = (uint)uVar2;
      puVar12[2] = (uint)uVar3;
      *(uint **)(lVar26 + 0x30) = puVar12 + 3;
    }
    if (lVar22 == 2) break;
    lVar26 = *plVar20;
    lVar22 = lVar22 + 1;
    puVar25 = puVar25 + 2;
    puVar12 = *(uint **)(lVar26 + 0x30);
  } while( true );
  iVar24 = 0;
  iVar18 = iVar21 + 4;
  do {
    xmitState((uchar *)param_1,iVar21,uVar13,0x40,iVar24,2);
    if ((sVar7 & 1) == 0) {
      if (iVar18 == 0) goto LAB_00111688;
    }
    else if (iVar18 == 1) break;
    iVar24 = iVar24 + 1;
    iVar18 = iVar18 + -2;
  } while( true );
  xmitState((uchar *)param_1,iVar21,uVar13,0x40,iVar24 + 1,1);
LAB_00111688:
  iVar21 = 0;
  uVar13 = 0;
  if (iVar23 != 0) {
    uVar13 = uVar4;
  }
  iVar23 = uVar13 + 4;
  do {
    xmitState(__s,uVar13,local_d4,0,iVar21,2);
    if ((uVar13 & 1) == 0) {
      if (iVar23 == 0) goto LAB_001116f8;
    }
    else if (iVar23 == 1) break;
    iVar21 = iVar21 + 1;
    iVar23 = iVar23 + -2;
  } while( true );
  xmitState(__s,uVar13,local_d4,0,iVar21 + 1,1);
LAB_001116f8:
  iVar23 = 0;
  iVar21 = iVar6 + 4;
  do {
    xmitState((uchar *)param_3,iVar6,local_c4,0x20,iVar23,2);
    if ((sVar9 & 1) == 0) {
      if (iVar21 == 0) goto LAB_00111758;
    }
    else if (iVar21 == 1) {
      xmitState((uchar *)param_3,iVar6,local_c4,0x20,iVar23 + 1,1);
LAB_00111758:
      free(__s);
      if (*(long *)(lVar5 + 0x28) == local_68) {
        return;
      }
LAB_0011179c:
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    iVar23 = iVar23 + 1;
    iVar21 = iVar21 + -2;
  } while( true );
}

