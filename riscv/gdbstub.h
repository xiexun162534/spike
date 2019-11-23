#ifndef _RISCV_GDBSTUB_H
#define _RISCV_GDBSTUB_H

#include <stdint.h>
#include <vector>
#include <set>
#include "sim.h"


struct gdb_core_t
{
  enum status_t
    {
     RUNNING, STOPPED
    } status;
  std::set<reg_t> breakpoints;
  gdb_core_t() : status(STOPPED)
  {
  }
};

class gdbstub_t {
public:
  gdbstub_t(sim_t *sim, uint port);
  ~gdbstub_t();

  void run();
private:
  int gdb_escape;
  int core_sel;
  sim_t *sim;
  std::vector<gdb_core_t *> cores;

  int socket_fd;
  int client_fd;

  void accept();
  void execute_commands();
  int get_char();
  int put_buffer(const char *buf, int len);
  int put_char(char ch);
  int put_packet(const char *buf);
  char *get_packet();
  void handle_gen_query(char *packet);
  void handle_gen_set(char *packet);
  void handle_v_commands(char *packet);
  void handle_q_attached(char *args);
  void handle_q_threadid(char *args);
  void handle_q_supported(char *args);
  void handle_get_registers(char *packet);
  void handle_set_registers(char *packet);
  void handle_terminate(char *packet);
  void handle_v_cont(char *packet);
  void handle_get_reg(char *packet);
  void handle_set_reg(char *packet);
  void handle_get_mem(char *packet);
  void handle_set_mem(char *packet);
  void handle_set_breakpoint(char *packet);
  void handle_remove_breakpoint(char *packet);
  void handle_kill(char *packet);
  void handle_detach(char *packet);
  bool set_reg(int regnum, reg_t regval);
  bool set_freg(int regnum, freg_t fregval);
  reg_t get_reg(int regnum);
  freg_t get_freg(int regnum);
  reg_t get_csr(int regnum);
  bool step(size_t n);
  bool should_break();
};

#endif
