// Ghidra decompilation of ice_gather_complete  (entry=00152e9c)

void FUN_00152e9c(undefined8 *param_1)

{
  undefined8 *puVar1;
  long *plVar2;
  long lVar3;
  int iVar4;
  size_t sVar5;
  undefined8 uVar6;
  long lVar7;
  undefined4 uVar8;
  long lVar9;
  long *plVar10;
  undefined8 *puVar11;
  long *plVar12;
  long *plVar13;
  undefined8 *local_e0;
  code *pcStack_d8;
  undefined8 local_d0;
  long local_c8;
  undefined8 local_c0;
  code *local_b8;
  code *pcStack_b0;
  code *local_a8;
  code *pcStack_a0;
  undefined4 local_94;
  undefined1 local_4c;
  long local_48;

  lVar3 = tpidr_el0;
  local_48 = *(long *)(lVar3 + 0x28);
  if (*(int *)((long)param_1 + 0x9d4) == 0) {
    *(undefined4 *)((long)param_1 + 0x9d4) = 1;
    uVar6 = imm_p2p_misc_get_timestamp_ms();
    param_1[0x13b] = uVar6;
    *(undefined4 *)(param_1 + 0x13c) = 30000;
    if ((code *)param_1[1] != (code *)0x0) {
      (*(code *)param_1[1])(param_1,*(undefined4 *)(param_1 + 0x13a));
    }
    imm_p2p_stun_session_cfg_default(&local_c0);
    local_c0 = param_1[5];
    local_94 = 1;
    local_b8 = FUN_00153fac;
    pcStack_b0 = FUN_00153fe4;
    local_a8 = FUN_0015428c;
    pcStack_a0 = FUN_00154288;
    local_4c = *(undefined1 *)(param_1 + 0xb);
    iVar4 = imm_p2p_stun_session_create(&local_c0,&local_c8);
    if ((iVar4 == 0) && (local_c8 != 0)) {
      local_d0 = 0;
      pcStack_d8 = FUN_00154778;
      local_e0 = param_1;
      imm_p2p_stun_session_set_credential(local_c8,&local_e0);
      plVar12 = (long *)param_1[0x114];
      param_1[0x111] = local_c8;
      while (param_1 + 0x114 != plVar12) {
        FUN_0015493c(plVar12);
        *(long *)plVar12[1] = *plVar12;
        *(long *)(*plVar12 + 8) = plVar12[1];
        free(plVar12);
        plVar12 = (long *)param_1[0x114];
      }
      goto LAB_00152ecc;
    }
  }
  else {
LAB_00152ecc:
    if (*(int *)(param_1 + 0x135) == 0) {
      if (*(int *)((long)param_1 + 0x9ac) == 0) {
        plVar12 = (long *)param_1[0x10e];
        if (plVar12 != param_1 + 0x10e) {
          iVar4 = 0;
          lVar9 = plVar12[0xd];
          while( true ) {
            if ((lVar9 == 0) && ((int)plVar12[0xe] == 0)) {
              iVar4 = iVar4 + 1;
            }
            plVar12 = (long *)*plVar12;
            if (plVar12 == param_1 + 0x10e) break;
            lVar9 = plVar12[0xd];
          }
          if (iVar4 != 0) goto LAB_00152ff0;
        }
        *(undefined4 *)((long)param_1 + 0x9ac) = 1;
        if ((code *)*param_1 == (code *)0x0) goto LAB_00152ff0;
        (*(code *)*param_1)(param_1,0,&DAT_0023571f);
        lVar9 = param_1[0x113];
      }
      else {
LAB_00152ff0:
        lVar9 = param_1[0x113];
      }
      if (((lVar9 != 0) && (sVar5 = strlen((char *)(lVar9 + 8)), sVar5 != 0)) &&
         (sVar5 = strlen((char *)(param_1[0x113] + 0x48)), sVar5 != 0)) {
        lVar9 = param_1[0x124];
        plVar12 = *(long **)(lVar9 + 0x900);
joined_r0x00153024:
        if (plVar12 != (long *)(lVar9 + 0x900)) {
          do {
            if ((int)plVar12[8] == 2) {
              if (*(int *)(*(long *)(plVar12[5] + 0x18) + 0x10) == 1) {
LAB_0015302c:
                if (*(long *)(lVar9 + 0xa10) == 0) {
                  uVar6 = imm_p2p_misc_get_timestamp_ms();
                  *(undefined8 *)(lVar9 + 0xa10) = uVar6;
                }
              }
              else {
                if (1 < *(uint *)(plVar12[6] + 0x10)) {
                  if (*(uint *)(plVar12[6] + 0x10) == 3) goto LAB_0015302c;
                  if (*(int *)(plVar12[4] + 0x9b0) == 0) goto LAB_00153034;
                }
                if (*(long *)(lVar9 + 0xa08) == 0) goto code_r0x001530b8;
              }
LAB_00153034:
              plVar12 = (long *)*plVar12;
            }
            else {
              if ((int)plVar12[8] != 0) goto LAB_00153034;
              FUN_0015518c(plVar12);
              plVar12 = (long *)*plVar12;
            }
            if (plVar12 == (long *)(lVar9 + 0x900)) break;
          } while( true );
        }
        lVar9 = param_1[0x12e];
        if ((*(int *)(lVar9 + 0x20) == 2) && (*(int *)(lVar9 + 0x9b8) == 0)) {
          plVar10 = *(long **)(lVar9 + 0x950);
          plVar12 = (long *)(lVar9 + 0x950);
          if (plVar12 != plVar10) {
            lVar7 = *(long *)(lVar9 + 0x9c0);
            if (lVar7 == 0) {
              lVar7 = imm_p2p_misc_get_timestamp_ms();
              plVar10 = *(long **)(lVar9 + 0x950);
              *(long *)(lVar9 + 0x9c0) = lVar7;
            }
            if (plVar10 == plVar12) {
LAB_00153274:
              iVar4 = imm_p2p_misc_check_timeout(lVar7,*(undefined4 *)(lVar9 + 0x5c));
              if (iVar4 == 0) {
                if ((*(int *)(lVar9 + 0x9ac) != 0) && (*(int *)(lVar9 + 0x9b0) != 0)) {
                  plVar10 = (long *)(lVar9 + 0x900);
                  do {
                    plVar10 = (long *)*plVar10;
                    if (plVar10 == (long *)(lVar9 + 0x900)) goto LAB_00153280;
                  } while (1 < *(uint *)(plVar10 + 8));
                }
              }
              else {
LAB_00153280:
                plVar10 = (long *)*plVar12;
                if (plVar10 != plVar12) {
                  plVar13 = (long *)0x0;
                  do {
                    plVar2 = plVar10;
                    if (plVar13 != (long *)0x0) {
                      plVar2 = plVar13;
                    }
                    plVar13 = plVar10;
                    if ((ulong)plVar10[7] <= (ulong)plVar2[7]) {
                      plVar13 = plVar2;
                    }
                    plVar10 = (long *)*plVar10;
                  } while (plVar10 != plVar12);
                  if (plVar13 != (long *)0x0) goto LAB_001532b8;
                }
              }
            }
            else {
              plVar13 = (long *)0x0;
              do {
                if ((*(int *)(*(long *)(plVar10[5] + 0x18) + 0x10) != 1) &&
                   ((*(uint *)(plVar10[6] + 0x10) < 2 ||
                    ((*(uint *)(plVar10[6] + 0x10) != 3 && (*(int *)(plVar10[4] + 0x9b0) != 0))))))
                {
                  plVar2 = plVar10;
                  if (plVar13 != (long *)0x0) {
                    plVar2 = plVar13;
                  }
                  plVar13 = plVar10;
                  if ((ulong)plVar10[7] <= (ulong)plVar2[7]) {
                    plVar13 = plVar2;
                  }
                }
                plVar10 = (long *)*plVar10;
              } while (plVar10 != plVar12);
              if (plVar13 == (long *)0x0) goto LAB_00153274;
LAB_001532b8:
              if ((int)plVar13[8] == 2) {
                plVar13[8] = DAT_00215680;
                imm_p2p_log_log(1,&DAT_0023571f,0x3f2,"ice %u check %u: try nominate\n",
                                *(undefined4 *)(lVar9 + 0x860),(int)plVar13[2]);
                FUN_0015518c(plVar13);
                *(undefined4 *)(lVar9 + 0x9b8) = 1;
              }
            }
          }
        }
      }
      lVar9 = param_1[0x124];
      if (*(long *)(lVar9 + 0x9a0) == 0) {
        if ((*(int *)(lVar9 + 0x9ac) == 0) || (*(int *)(lVar9 + 0x9b0) == 0)) {
LAB_001531ec:
          iVar4 = imm_p2p_misc_check_timeout(param_1[0x13b],*(undefined4 *)(param_1 + 0x13c));
          uVar8 = 1;
          if (iVar4 == 0) {
            uVar8 = 2;
          }
          goto LAB_00152ed8;
        }
        puVar1 = param_1 + 0x120;
        puVar11 = (undefined8 *)*puVar1;
        if (puVar11 != puVar1) {
          uVar8 = 1;
          do {
            if (*(uint *)(puVar11 + 8) < 3) goto LAB_001531ec;
            puVar11 = (undefined8 *)*puVar11;
          } while (puVar11 != puVar1);
          goto LAB_00152ed8;
        }
      }
      else {
        iVar4 = *(int *)(*(long *)(lVar9 + 0x9a0) + 0x40);
        if (iVar4 == 2) {
          uVar8 = 0;
          goto LAB_00152ed8;
        }
        if (iVar4 != 3) goto LAB_001531ec;
      }
    }
  }
  uVar8 = 1;
LAB_00152ed8:
  if (*(long *)(lVar3 + 0x28) == local_48) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar8);
code_r0x001530b8:
  uVar6 = imm_p2p_misc_get_timestamp_ms();
  *(undefined8 *)(lVar9 + 0xa08) = uVar6;
  plVar12 = (long *)*plVar12;
  goto joined_r0x00153024;
}
