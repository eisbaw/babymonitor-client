// pkt_delay @ 00111944

/* pkt_delay(unsigned int, unsigned int) */

void pkt_delay(uint param_1,uint param_2)

{
  long lVar1;
  int iVar2;
  timeval local_38;
  long local_28;
  
  lVar1 = tpidr_el0;
  local_28 = *(long *)(lVar1 + 0x28);
  local_38.tv_sec = (__time_t)param_1;
  local_38.tv_usec = (__suseconds_t)(param_2 * 1000);
  iVar2 = select(0,(fd_set *)0x0,(fd_set *)0x0,(fd_set *)0x0,&local_38);
  if (*(long *)(lVar1 + 0x28) == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(iVar2);
}

