static __always_inline void pid_to_string(u32 pid, char *str, int max_len) {
  int i = 0;
  int temp = pid;
  int digits = 0;

  // Handle zero case
  if (pid == 0) {
    if (max_len > 0)
      str[0] = '0';
    if (max_len > 1)
      str[1] = '\0';
    return;
  }

  // Count digits
#pragma unroll
  while (temp > 0 && digits < 10) { // Max PID is ~7 digits typically
    temp /= 10;
    digits++;
  }

  if (digits >= max_len) {
    digits = max_len - 1;
  }

  // Null terminate
  str[digits] = '\0';

// Convert backwards
#pragma unroll
  for (i = digits - 1; i >= 0; i--) {
    str[i] = '0' + (pid % 10);
    pid /= 10;
  }
}

static __always_inline int strings_equal(const char *s1, const char *s2,
                                         int max_len) {
#pragma unroll
  for (int i = 0; i < max_len; i++) {
    if (s1[i] != s2[i]) {
      return 0; // Not equal
    }
    if (s1[i] == '\0') {
      return 1; // Equal (reached end of both strings)
    }
  }
  return 1; // Equal (both strings are max_len long)
}
