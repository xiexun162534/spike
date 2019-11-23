#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef AF_INET
#include <sys/socket.h>
#endif
#ifndef INADDR_ANY
#include <netinet/in.h>
#endif

#include <algorithm>
#include <unordered_map>
#include <cassert>
#include <cstdio>
#include <cstdlib>

#include "mmu.h"
#include "gdbstub.h"

#if 0
#define D(x) x
#else
#define D(x)
#endif

#define PACKET_BUF_SIZE 1024


static bool is_host_le()
{
  uint16_t a = 0x0001;
  return (*(uint8_t *)&a != 0);
}

template<class T> static T endian_convert(T in)
{
  uint8_t a[sizeof(T)];
  uint8_t b[sizeof(T)];
  T c;
  *(T *)a = in;
  for (unsigned i = 0; i < sizeof(T); i++) {
    b[sizeof(T) - 1 - i] = a[i];
  }
  c = *(T *)b;
  return c;
}

template<class T> static T host2be(T i)
{
  if (is_host_le())
    return endian_convert<T>(i);
  else
    return i;
}

template<class T> static T be2host(T i)
{
  if (is_host_le())
    return endian_convert<T>(i);
  else
    return i;
}

template<class T, bool is_be = false> static T mem2val(unsigned char *mem, int length)
{
  assert(length <= (int)sizeof(T));
  unsigned char memt[sizeof(T)] = {};
  T t;
  if (is_be ^ is_host_le()) {
    memcpy(memt, mem, length);
    t = *(T *)memt;
  }
  else {
    memcpy(&memt[(int)sizeof(T) - length], mem, length);
    t = endian_convert<T>(*(T *)memt);
  }
  return t;
}

static char hexchars[] = {'0', '1', '2', '3',
                          '4', '5', '6', '7',
                          '8', '9', 'A', 'B',
                          'C', 'D', 'E', 'F'};

static int hex(unsigned char ch)
{
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static char *mem2hex(unsigned char *mem, int length) {
  static char hex_buf[PACKET_BUF_SIZE];
  for (int i = 0; i < length; i++) {
    hex_buf[2 * i] = hexchars[mem[i] >> 4];
    hex_buf[2 * i + 1] = hexchars[mem[i] & 0xf];
  }
  hex_buf[2 * length] = '\0';
  return hex_buf;
}

static unsigned char *hex2mem(char *hex_buf, int *length_p) {
  static unsigned char mem_buf[PACKET_BUF_SIZE / 2];
  int offset = 0;
  *length_p = 0;
  if (strlen(hex_buf) % 2 != 0) {
    mem_buf[offset++] = hex(*hex_buf);
    hex_buf++;
  }
  while (*hex_buf) {
    int hex0, hex1;
    hex0 = hex(hex_buf[0]);
    hex1 = hex(hex_buf[1]);
    if (hex0 == -1 || hex1 == -1)
      return NULL;
    mem_buf[offset++] = ((unsigned char)hex0 << 4) | ((unsigned char)hex1 & 0xf);
    hex_buf += 2;
  }
  *length_p = offset;
  return mem_buf;
}

static char *split(char *str, char by, int num, char **where)
{
  int count = 0;
  where[count] = NULL;
  while (*str && count < num) {
    if (where[count] == NULL) {
      where[count] = str;
    }
    if (*str == by) {
      *str = '\0';
      count += 1;
      where[count] = NULL;
    }
    str++;
  }
  if (where[count] != NULL && count < num) {
    count += 1;
    if (count < num)
      where[count] = NULL;
  }
  return str;
}

gdbstub_t::~gdbstub_t()
{
  if (client_fd != -1)
    close(client_fd);
  if (socket_fd != -1)
    close(socket_fd);
}

gdbstub_t::gdbstub_t(sim_t *sim, uint port) :
  core_sel(0), sim(sim)
{
  for (int i = 0; i < (int)sim->nprocs(); i++) {
    cores.push_back(new gdb_core_t());
  }
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd == -1) {
    fprintf(stderr, "gdbstub failed to make socket: %s (%d)\n",
            strerror(errno), errno);
    abort();
  }
  
  fcntl(socket_fd, F_SETFL, 0);
  int reuseaddr = 1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
        sizeof(int)) == -1) {
    fprintf(stderr, "gdbstub failed setsockopt: %s (%d)\n",
            strerror(errno), errno);
    abort();
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  
  if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    fprintf(stderr, "gdbstub failed to bind socket: %s (%d)\n",
            strerror(errno), errno);
    abort();
  }

  if (listen(socket_fd, 1) == -1) {
    fprintf(stderr, "gdbstub failed to listen on socket: %s (%d)\n",
            strerror(errno), errno);
    abort();
  }
  fprintf(stderr, "Listening for gdbstub connection on port %d.\n",
          ntohs(addr.sin_port));
  
  socklen_t addrlen = sizeof(addr);
  if (getsockname(socket_fd, (struct sockaddr *) &addr, &addrlen) == -1) {
    fprintf(stderr, "gdbstub getsockname failed: %s (%d)\n",
        strerror(errno), errno);
    abort();
  }
}

void gdbstub_t::accept()
{
  client_fd = ::accept(socket_fd, NULL, NULL);
  if (client_fd == -1) {
    if (errno == EAGAIN) {
      // No client waiting to connect right now.
    } else {
      fprintf(stderr, "failed to accept on socket: %s (%d)\n", strerror(errno),
          errno);
      abort();
    }
  } else {
    fcntl(client_fd, F_SETFL, 0);
  }
}

bool gdbstub_t::should_break()
{
  reg_t pc = sim->get_core(core_sel)->get_state()->pc;
  auto it = cores[core_sel]->breakpoints.find(pc);
  if (it != cores[core_sel]->breakpoints.end())
    return true;
  else
    return false;
}

bool gdbstub_t::step(size_t n)
{
  for (size_t i = 0; i < n; i++) {
    if (should_break()) {
      cores[core_sel]->status = gdb_core_t::STOPPED;
      D(fprintf(stderr, "breakpoint\n"));
      return false;
    }
    if (sim->done())
      return true;
    sim->step(1);
  }
  return true;
}

void gdbstub_t::run()
{
  if (cores[core_sel]->status == gdb_core_t::RUNNING) {
    if (step(1))
      return ;
  }
  if (client_fd > 0) {
    execute_commands();
  } else {
    this->accept();
  }
}

int gdbstub_t::get_char()
{
  uint8_t ch;
  int ret;

  for(;;) {
    ret = read(client_fd, &ch, 1);
    if (ret < 0) {
      if (errno == ECONNRESET)
        client_fd = -1;
      if (errno != EINTR)
        return -1;
    } else if (ret == 0) {
      close(client_fd);
      client_fd = -1;
      return -1;
    } else {
      break;
    }
  }
  return ch;
}

int gdbstub_t::put_buffer(const char *buf, int len)
{
  int ret;

  D(fprintf(stderr, "put: "));
  D(fwrite(buf, 1, len, stderr));
  D(fprintf(stderr, "\n"));
  while (len > 0) {
    ret = send(client_fd, buf, len, 0);
    if (ret < 0) {
      if (errno != EINTR)
        return ret;
    } else {
      buf += ret;
      len -= ret;
    }
  }
  return 0;
}

int gdbstub_t::put_char(char ch)
{
  return put_buffer(&ch, 1);
}

int gdbstub_t::put_packet(const char *buf)
{
  unsigned char checksum = 0;
  int send_count = 0, count = 0;
  unsigned char ch;
  static char send_buf[PACKET_BUF_SIZE];
  send_buf[send_count++] = '$';
  while (buf[count]) {
    checksum += (unsigned char)buf[count];
    send_buf[send_count++] = buf[count++];
  }
  send_buf[send_count++] = '#';
  send_buf[send_count++] = hexchars[((unsigned char)checksum) >> 4];
  send_buf[send_count++] = hexchars[((unsigned char)checksum) & 0xf];

  do {
    put_buffer(send_buf, send_count);
    ch = get_char();
    if (ch == -1)
      return -1;
    if (ch != '+') {
      D(fprintf(stderr, "put_puffer: receive %c\n", ch));
      sleep(1);
    }
  } while (ch != '+');

  return 0;
}


char *gdbstub_t::get_packet()
{
  static char buf[PACKET_BUF_SIZE];
  while (1) {
    int ch = '\0';
    while (ch != '$') {
      ch = get_char();
      if (ch == -1)
        return NULL;
    }
  retry:
    {
      unsigned char checksum = 0;
      unsigned char xmitcsum = (unsigned char)-1;
      int count = 0;
      while (count < PACKET_BUF_SIZE - 1) {
        ch = get_char();
        if (ch == '$')
          goto retry;
        if (ch == '#')
          break;
        buf[count++] = ch;
        checksum += (unsigned char)ch;
      }
      buf[count] = '\0';

      if (ch == '#') {
        ch = get_char();
        xmitcsum = hex(ch) << 4;
        ch = get_char();
        xmitcsum += hex(ch);

        if (checksum != xmitcsum)
          put_char('-');
        else {
          D(fprintf(stderr, "csum: %x\n", (unsigned)xmitcsum));
          put_char('+');
          if (buf[2] == ':') {
            put_buffer(buf, 2);
            return &buf[3];
          } else {
            return &buf[0];
          }
        }
      }
    }
  }
}

void gdbstub_t::handle_v_commands(char *packet)
{
  if (strstr(packet, "Cont") == packet) {
    handle_v_cont(&packet[sizeof("Cont") - 1]);
  } else
    put_packet("");
}

void gdbstub_t::handle_q_threadid(char *args)
{
  put_packet("QC1");
}

void gdbstub_t::handle_q_attached(char *args)
{
  put_packet("1");
}

void gdbstub_t::handle_q_supported(char *args)
{
  char packet_buf[PACKET_BUF_SIZE];
  sprintf(packet_buf, "PacketSize=%d;vContSupported+;BreakpointCommands+", (int)(PACKET_BUF_SIZE - 1));
  put_packet(packet_buf);
}

void gdbstub_t::handle_gen_query(char *packet)
{
  switch (packet[0]) {
  case 'P':
    put_packet("");
    break;
  case 'L':
    put_packet("");
    break;
  default:
    {
      char *command;
      char *args;
      args = split(packet, ':', 1, &command);
      if (command) {
        std::string cmd(command);
        if (cmd == "Attached")
          handle_q_attached(args);
        else if (cmd == "C")
          handle_q_threadid(args);
        else if (cmd == "Supported")
          handle_q_supported(args);
        else
          put_packet("");
      }
      else
        put_packet("");
    }
    break;
  }
}

void gdbstub_t::handle_gen_set(char *packet)
{
  put_packet("OK");
}

reg_t gdbstub_t::get_csr(int regnum)
{
  D(fprintf(stderr, "get csr: %d\n", regnum));
  return sim->get_core(core_sel)->get_csr(regnum);
}

freg_t gdbstub_t::get_freg(int regnum)
{
  if (regnum >= 33 && regnum < 65)
    return sim->get_core(core_sel)->get_state()->FPR[regnum - 33];
  else
    return freg_t{};
}

reg_t gdbstub_t::get_reg(int regnum)
{
  if (regnum == 0)
    return 0;
  else if (regnum > 0 && regnum < 32)
    return sim->get_core(core_sel)->get_state()->XPR[regnum];
  else if (regnum == 32)
    return sim->get_core(core_sel)->get_state()->pc;
  else if (regnum == 0x1000 + 65)
    return sim->get_core(core_sel)->get_state()->prv;
  else if (regnum >= 65)
    return get_csr(regnum - 65);
  
  else
    return 0;
}

bool gdbstub_t::set_reg(int regnum, reg_t regval)
{
  if (regnum == 0)
    return false;
  else if (regnum > 0 && regnum < 32) {
    sim->get_core(core_sel)->get_state()->XPR.write(regnum, regval);
    return true;
  } else if (regnum == 32) {
    sim->get_core(core_sel)->get_state()->pc = regval;
    return true;
  } else if (regnum == 0x1000 + 65) {
    sim->get_core(core_sel)->get_state()->prv = regval;
    return true;
  } else if (regnum >= 65) {
    try {
      sim->get_core(core_sel)->set_csr(regnum - 65, regval);
    } catch (...) {
      return false;
    }
    return true;
  } else
    return false;
}

bool gdbstub_t::set_freg(int regnum, freg_t fregval)
{
  if (regnum >= 33 && regnum < 65) {
    sim->get_core(core_sel)->get_state()->FPR.write(regnum - 33, fregval);
    return true;
  }
  else
    return false;
}


void gdbstub_t::handle_set_reg(char *packet)
{
  char *packet_split[2];
  split(packet, '=', 2, packet_split);
  if (!packet_split[0] || !packet_split[1]) {
    put_packet("E01");
    return ;
  }
  int buf_len;
  unsigned char *regnum_buf = hex2mem(packet_split[0], &buf_len);
  if (!regnum_buf) {
    put_packet("E02");
    return ;
  }
  if (buf_len > (int)sizeof(int)) {
    put_packet("E03");
    return ;
  }
  int regnum = 0;
  for (int i = 0; i < buf_len; i++) {
    regnum <<= 8;
    regnum += regnum_buf[i];
  }
  unsigned char *regval_buf = hex2mem(packet_split[1], &buf_len);
  if (regnum >= 33 && regnum < 65) {
    if (buf_len > (int)sizeof(freg_t)) {
      put_packet("E04");
      return ;
    }
    freg_t fregval = mem2val<freg_t>(regval_buf, buf_len);
    if (!set_freg(regnum, fregval)) {
      put_packet("E05");
      return ;
    }
  } else {
    if (buf_len > (int)sizeof(reg_t)) {
      put_packet("E04");
      return ;
    }
    reg_t regval = mem2val<reg_t>(regval_buf, buf_len);
    if (!set_reg(regnum, regval)) {
      put_packet("E05");
      return ;
    }
  }
  put_packet("OK");
}

void gdbstub_t::handle_get_reg(char *packet)
{
  int buf_len;
  unsigned char *regnum_buf = hex2mem(packet, &buf_len);
  if (!regnum_buf) {
    put_packet("E01");
    return ;
  }
  if (buf_len > (int)sizeof(int)) {
    put_packet("E02");
    return ;
  }
  int regnum = 0;
  for (int i = 0; i < buf_len; i++) {
    regnum <<= 8;
    regnum += regnum_buf[i];
  }
  if (regnum >= 33 && regnum < 65) {
    freg_t fregval = get_freg(regnum);
    put_packet(mem2hex((unsigned char *)&fregval, sizeof(fregval)));
  } else {
    reg_t regval;
    try {
      regval = get_reg(regnum);
    } catch (...) {
      put_packet("E03");
      return ;
    }
    put_packet(mem2hex((unsigned char *)&regval, sizeof(regval)));
  }
}


void gdbstub_t::handle_set_registers(char *packet)
{
  int regnum;
  int buf_len;
  reg_t *regfile_buf = (reg_t *)hex2mem(packet, &buf_len);
  if (buf_len != 33 * sizeof(reg_t)) {
    put_packet("E01");
    return ;
  }
  for (regnum = 0; regnum < 33; regnum++){
    set_reg(regnum, regfile_buf[regnum]);
  }
  put_packet("OK");
}

void gdbstub_t::handle_get_registers(char *packet)
{
  int regnum;
  reg_t regfile_buf[33];
  for (regnum = 0; regnum < 33; regnum++){
    reg_t reg = get_reg(regnum);
    regfile_buf[regnum] = reg;
  }
  put_packet(mem2hex((unsigned char *)regfile_buf, sizeof(regfile_buf)));
}

void gdbstub_t::handle_get_mem(char *packet)
{
  char *packet_split[2];
  split(packet, ',', 2, packet_split);
  if (!packet_split[0] || !packet_split[1]) {
    put_packet("E01");
    return ;
  }
  int buf_len;
  unsigned char *buf = hex2mem(packet_split[0], &buf_len);
  if (!buf || buf_len > (int)sizeof(reg_t)) {
    put_packet("E02");
    return ;
  }
  reg_t addr = mem2val<reg_t, true>(buf, buf_len);
  buf = hex2mem(packet_split[1], &buf_len);
  if (!buf || buf_len > (int)sizeof(reg_t)) {
    put_packet("E02");
    return ;
  }
  reg_t len = mem2val<reg_t, true>(buf, buf_len);
  reg_t paddr;
  try {
    paddr = sim->get_core(core_sel)->get_mmu()->translate(addr, len, LOAD);
  } catch (...) {
    put_packet("E03");
    return ;
  }
  char *haddr = sim->addr_to_mem(paddr);
  D(fprintf(stderr, "get mem: vaddr %p, paddr %p, haddr %p\n", (void *)addr, (void *)paddr, (void *)haddr));
  if (haddr == NULL) {
    put_packet("E05");
    return ;
  }
  if (len > PACKET_BUF_SIZE / 2) {
    put_packet("E04");
    return ;
  }
  char *hex_buf = mem2hex((unsigned char *)haddr, len);
  put_packet(hex_buf);
}

void gdbstub_t::handle_set_mem(char *packet)
{
  char *packet_split[2], *packet_split2[2];
  split(packet, ',', 2, packet_split);
  if (!packet_split[0] || !packet_split[1]) {
    put_packet("E01");
    return ;
  }
  split(packet_split[1], ':', 2, packet_split2);
  if (!packet_split2[0] || !packet_split2[1]) {
    put_packet("E01");
    return ;
  }
  int buf_len;
  unsigned char *buf = hex2mem(packet_split[0], &buf_len);
  if (!buf || buf_len > (int)sizeof(reg_t)) {
    put_packet("E02");
    return ;
  }
  reg_t addr = mem2val<reg_t, true>(buf, buf_len);
  buf = hex2mem(packet_split2[0], &buf_len);
  if (!buf || buf_len > (int)sizeof(reg_t)) {
    put_packet("E02");
    return ;
  }
  reg_t len = mem2val<reg_t, true>(buf, buf_len);
  reg_t paddr;
  try {
    paddr = sim->get_core(core_sel)->get_mmu()->translate(addr, len, LOAD);
  } catch (...) {
    put_packet("E03");
    return ;
  }
  char *haddr = sim->addr_to_mem(paddr);
  D(fprintf(stderr, "get mem: vaddr %p, paddr %p, haddr %p\n", (void *)addr, (void *)paddr, (void *)haddr));
  if (haddr == NULL) {
    put_packet("E05");
    return ;
  }
  buf = hex2mem(packet_split2[1], &buf_len);
  if (len > PACKET_BUF_SIZE / 2 || (int)len != buf_len) {
    put_packet("E04");
    return ;
  }
  memcpy(haddr, buf, len);
  put_packet("OK");
}

void gdbstub_t::handle_set_breakpoint(char *packet)
{
  reg_t addr;
  char *packet_split[3];
  split(packet, ',', 3, packet_split);
  if (!packet_split[0] || !packet_split[1] || !packet_split[2] || packet_split[0][1]) {
    put_packet("E01");
    return ;
  }
  char type = packet_split[0][0];
  unsigned char *buf;
  int buf_len;
  buf = hex2mem(packet_split[1], &buf_len);
  if (!buf) {
    put_packet("E02");
    return ;
  }
  if (buf_len > (int)sizeof(reg_t)) {
    put_packet("E03");
    return ;
  }
  addr = mem2val<reg_t, true>(buf, buf_len);
  switch (type) {
  case '0':
  case '1':
    cores[core_sel]->breakpoints.insert(addr);
    D(fprintf(stderr, "insert: %p\n", (void *)addr));
    put_packet("OK");
    break;
  default:
    put_packet("");
    break;
  }
}

void gdbstub_t::handle_remove_breakpoint(char *packet)
{
  reg_t addr;
  char *packet_split[3];
  split(packet, ',', 3, packet_split);
  if (!packet_split[0] || !packet_split[1] || !packet_split[2] || packet_split[0][1]) {
    put_packet("E01");
    return ;
  }
  char type = packet_split[0][0];
  unsigned char *buf;
  int buf_len;
  buf = hex2mem(packet_split[1], &buf_len);
  if (!buf) {
    put_packet("E02");
    return ;
  }
  if (buf_len > (int)sizeof(reg_t)) {
    put_packet("E03");
    return ;
  }
  addr = mem2val<reg_t, true>(buf, buf_len);
  switch (type) {
  case '0':
  case '1': {
    auto it = cores[core_sel]->breakpoints.find(addr);
    if (it == cores[core_sel]->breakpoints.end()) {
      put_packet("E04");
      return ;
    }
    cores[core_sel]->breakpoints.erase(it);
    D(fprintf(stderr, "remove: %p\n", (void *)addr));
    put_packet("OK");
  } break;
  default:
    put_packet("");
    break;
  }
}

void gdbstub_t::handle_v_cont(char *packet)
{
  if (packet[0] == '?') {
    put_packet("vCont;C;c;S;s;t");
    return ;
  }
  if (packet[0] != ';') {
    put_packet("");
    return ;
  }
  packet++;
  switch (packet[0]) {
  case 'c':
  case 'C':
    cores[core_sel]->status = gdb_core_t::RUNNING;
    gdb_escape = 1;
    break;
  case 'S':
  case 's':
    step(1);
    put_packet("S00");
    break;
  case 't':
    break;
  default:
    put_packet("");
  }
}

void gdbstub_t::handle_terminate(char *packet)
{
  put_packet("OK");
}

void gdbstub_t::handle_detach(char *packet)
{
  put_packet("OK");
  close(client_fd);
  client_fd = -1;
  gdb_escape = 1;
}

void gdbstub_t::handle_kill(char *packet)
{
  exit(0);
}

void gdbstub_t::execute_commands()
{
  D(fprintf(stderr, "gdb stub execute_commands\n"));
  put_packet("S00");
  gdb_escape = 0;
  while (!gdb_escape)
    {
      char *packet = get_packet();
      if (packet == NULL) {
        fprintf(stderr, "gdbstub: connection lost\n");
        break;
      }
      D(fprintf(stderr, "packet:%s\n", packet));
      switch(packet[0]) {
      case '!':
        put_packet("OK");
        break;
      case '?':
        put_packet("S00");
        break;
      case 'q':
        handle_gen_query(&packet[1]);
        break;
      case 'Q':
        handle_gen_set(&packet[1]);
        break;
      case 'v':
        handle_v_commands(&packet[1]);
        break;
      case 'g':
        handle_get_registers(&packet[1]);
        break;
      case 'p':
        handle_get_reg(&packet[1]);
        break;
      case 'P':
        handle_set_reg(&packet[1]);
        break;
      case 'T':
        handle_terminate(&packet[1]);
        break;
      case 'm':
        handle_get_mem(&packet[1]);
        break;
      case 'M':
        handle_set_mem(&packet[1]);
        break;
      case 'H':
        put_packet("E01");
        break;
      case 'z':
        handle_remove_breakpoint(&packet[1]);
        break;
      case 'Z':
        handle_set_breakpoint(&packet[1]);
        break;
      case 'k':
        handle_kill(&packet[1]);
        break;
      case 'D':
        handle_detach(&packet[1]);
        break;
      default:
        put_packet("");
        break;
      }
    }
}
