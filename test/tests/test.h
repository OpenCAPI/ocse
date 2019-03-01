#define WED_REGISTER 0x0000

struct work_element {
  uint8_t  command_byte; // left to right - 7:2 cmd, 1 wrap, 0 valid
  uint8_t  status;
  uint16_t length;
  uint8_t  command_extra;
  uint8_t  UNUSED_5;
  uint16_t UNUSED_6to7;
  uint64_t atomic_op1;
  uint64_t source_ea; // or atomic_op2
  uint64_t dest_ea;
};