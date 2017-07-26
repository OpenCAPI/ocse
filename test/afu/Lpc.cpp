#include "Lpc.h"
#include <stdio.h>

Lpc::Lpc() {
    std::vector<uint8_t> x32k(32);
    std::vector<uint8_t> x256(128);
    std::vector<uint8_t> x64(4);
    printf("Lpc: allocating LPC memory\n");
    lpc_memory = new uint8_t[0x100000];
}

uint8_t
Lpc::is_lpc_addr(uint64_t addr) {
    uint8_t x32k_index;
    uint64_t list_addr;

    x32k_index = (uint8_t)((addr & 0x00000000000F8000)>> 15);
    list_addr = addr & 0xFFFFFFFFFFF00000;

    if(addr_list.size() == 0) {
	printf("Lpc: no lpc memory indexed\n");
	return 2;
    }
}

void
Lpc::read_lpc_mem(uint64_t addr, uint16_t size) {

}

void
Lpc::write_lpc_mem(uint64_t addr, uint16_t size, uint8_t *data) {

}

Lpc::~Lpc() {
    delete[] lpc_memory;
}

