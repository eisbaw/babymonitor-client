// Ghidra decompilation of matrix_fcn5eb0  (entry=00105eb0)

int FUN_00105eb0(undefined8 *param_1,undefined8 param_2,int param_3,int param_4)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  char *__ptr;
  void *pvVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  undefined8 uVar19;
  undefined8 uVar20;
  undefined8 uVar21;
  undefined8 uVar22;
  undefined8 uVar23;
  undefined8 uVar24;
  undefined8 uVar25;
  char *local_128;
  int local_118;
  int local_fc;
  int local_d4;
  int local_c4;
  int local_ac;
  int local_a8;
  int local_74;
  long local_30;
  long local_28;
  
  lVar4 = tpidr_el0;
  local_28 = *(long *)(lVar4 + 0x28);
  lVar4 = mp_rat_alloc();
  local_74 = FUN_001065f8(&local_30,param_2,param_3);
  FUN_001068a4(local_30,"inited matrix:");
  if (local_74 == 0) {
    for (local_a8 = 1; local_a8 <= param_3; local_a8 = local_a8 + 1) {
      (**(code **)(local_30 + 0x10))(local_30,local_a8);
      iVar3 = mp_rat_compare_zero();
      local_ac = local_a8;
      if (iVar3 == 0) {
        do {
          local_ac = local_ac + 1;
          if (param_3 < local_ac) goto LAB_001060bc;
          (**(code **)(local_30 + 0x10))(local_30,local_a8,local_ac);
          iVar3 = mp_rat_compare_zero();
        } while (iVar3 == 0);
        lVar5 = (**(code **)(local_30 + 0x18))(local_30,local_a8);
        lVar6 = (**(code **)(local_30 + 0x18))(local_30,local_ac);
        for (local_c4 = 0; local_c4 < param_3 + 1; local_c4 = local_c4 + 1) {
          puVar1 = (undefined8 *)(lVar5 + (long)local_c4 * 0x40);
          uVar13 = puVar1[1];
          uVar7 = *puVar1;
          uVar17 = puVar1[3];
          uVar15 = puVar1[2];
          uVar21 = puVar1[5];
          uVar19 = puVar1[4];
          uVar25 = puVar1[7];
          uVar23 = puVar1[6];
          puVar1 = (undefined8 *)(lVar5 + (long)local_c4 * 0x40);
          puVar2 = (undefined8 *)(lVar6 + (long)local_c4 * 0x40);
          uVar14 = puVar2[1];
          uVar8 = *puVar2;
          uVar18 = puVar2[3];
          uVar16 = puVar2[2];
          uVar22 = puVar2[5];
          uVar20 = puVar2[4];
          uVar24 = puVar2[6];
          puVar1[7] = puVar2[7];
          puVar1[6] = uVar24;
          puVar1[5] = uVar22;
          puVar1[4] = uVar20;
          puVar1[3] = uVar18;
          puVar1[2] = uVar16;
          puVar1[1] = uVar14;
          *puVar1 = uVar8;
          puVar1 = (undefined8 *)(lVar6 + (long)local_c4 * 0x40);
          puVar1[7] = uVar25;
          puVar1[6] = uVar23;
          puVar1[5] = uVar21;
          puVar1[4] = uVar19;
          puVar1[3] = uVar17;
          puVar1[2] = uVar15;
          puVar1[1] = uVar13;
          *puVar1 = uVar7;
        }
      }
LAB_001060bc:
      if (local_a8 < param_3) {
        (**(code **)(local_30 + 0x10))(local_30,local_a8);
        iVar3 = mp_rat_compare_zero();
        if (iVar3 != 0) {
          lVar5 = (**(code **)(local_30 + 0x18))(local_30,local_a8);
          local_d4 = local_a8;
          while (local_d4 = local_d4 + 1, local_d4 <= param_3) {
            (**(code **)(local_30 + 0x10))(local_30,local_a8,local_d4);
            iVar3 = mp_rat_compare_zero();
            if (iVar3 != 0) {
              lVar6 = (**(code **)(local_30 + 0x18))(local_30,local_d4);
              uVar7 = (**(code **)(local_30 + 0x10))(local_30,local_a8);
              uVar8 = (**(code **)(local_30 + 0x10))(local_30,local_a8,local_d4);
              lVar9 = mp_rat_alloc();
              if (lVar9 == 0) {
                local_74 = 1;
                goto LAB_001065c0;
              }
              local_74 = mp_rat_div(uVar7,uVar8,lVar9);
              if (local_74 != *(int *)PTR_MP_OK_001160e8) goto LAB_001065c0;
              for (local_fc = local_a8; iVar3 = local_fc - (param_3 + 1),
                  iVar3 == 0 || local_fc < param_3 + 1; local_fc = local_fc + 1) {
                lVar10 = mp_rat_alloc();
                if (lVar10 == 0) {
                  local_74 = 1;
                  goto LAB_001065c0;
                }
                lVar11 = mp_rat_alloc();
                if (lVar11 == 0) {
                  local_74 = 1;
                  goto LAB_001065c0;
                }
                local_74 = mp_rat_mul(lVar6 + (long)local_fc * 0x40 + -0x40,lVar9,lVar10);
                if (((local_74 != *(int *)PTR_MP_OK_001160e8) ||
                    (local_74 = mp_rat_sub(lVar10,lVar5 + (long)local_fc * 0x40 + -0x40,lVar11),
                    local_74 != *(int *)PTR_MP_OK_001160e8)) ||
                   (local_74 = mp_rat_copy(lVar11,lVar6 + (long)local_fc * 0x40 + -0x40),
                   local_74 != *(int *)PTR_MP_OK_001160e8)) goto LAB_001065c0;
                mp_rat_free(0,lVar10);
                mp_rat_free(lVar11);
              }
              FUN_001068a4(iVar3,local_30,"processing:");
              mp_rat_free(lVar9);
            }
          }
          goto LAB_00106390;
        }
        local_a8 = local_a8 + 1;
      }
      else {
LAB_00106390:
        if (local_a8 == param_3) {
          (**(code **)(local_30 + 0x10))(local_30,local_a8);
          iVar3 = mp_rat_compare_zero();
          if (iVar3 == 0) {
            FUN_001068b8(local_30);
            local_74 = 0xb;
          }
          else {
            uVar7 = (**(code **)(local_30 + 0x10))(local_30,local_a8 + 1);
            uVar8 = (**(code **)(local_30 + 0x10))(local_30,local_a8);
            local_74 = mp_rat_div(uVar7,uVar8,lVar4);
            if (local_74 == *(int *)PTR_MP_OK_001160e8) {
              mp_rat_reduce(0,lVar4);
              iVar3 = mp_int_compare_value(lVar4 + 0x20,1);
              if (iVar3 == 0) {
                local_118 = mp_int_binary_len(lVar4);
                __ptr = (char *)calloc((long)(local_118 + 1),1);
                mp_int_to_binary(lVar4,__ptr,local_118 + 1);
                for (local_128 = __ptr; *local_128 == '\0' && 0 < local_118;
                    local_128 = local_128 + 1) {
                  local_118 = local_118 + -1;
                }
                if (param_4 + -1 != 0) {
                  transform(param_4 + -1,local_128,local_118);
                }
                pvVar12 = calloc((long)(int)(local_118 << 1 | 1),1);
                *param_1 = pvVar12;
                FUN_0010693c(local_128,(long)local_118,*param_1);
                free(__ptr);
                mp_rat_free(lVar4);
                FUN_001068b8(local_30);
                local_74 = 0;
              }
              else {
                FUN_001068b8(local_30);
                local_74 = 0xb;
              }
            }
            else {
              FUN_001068b8(local_30);
            }
          }
          goto LAB_001065c0;
        }
      }
    }
    local_74 = 0xb;
  }
LAB_001065c0:
  lVar4 = tpidr_el0;
  lVar4 = *(long *)(lVar4 + 0x28) - local_28;
  if (lVar4 == 0) {
    return local_74;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(lVar4);
}

