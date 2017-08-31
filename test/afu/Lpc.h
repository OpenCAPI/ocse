#ifndef	__lpc_h__
#define	__lpc_h__

#include <stdint.h>
#include <vector>
#include <list>

class Lpc
{
private:
    std::vector<uint8_t> x32k;	// 32x32k block [19:15]
    std::vector<uint8_t>::iterator it_x32k;
    std::vector<uint8_t> x256;	// 128x256B block [14:8]
    std::vector<uint8_t>::iterator it_x256;
    std::vector<uint8_t> x64;	// 4x64B block [7:6]
    std::vector<uint8_t>::iterator it_x64;
    std::list<uint64_t> addr_list;
    std::list<uint64_t>::iterator it_list;
    //uint8_t *lpc_memory;
    std::vector<uint8_t> lpc_memory; 

public:
    Lpc();
    uint8_t lpc_addr_exist(uint64_t addr);
    void read_lpc_mem(uint64_t addr, uint16_t size, uint8_t* data);
    void write_lpc_mem(uint64_t addr, uint16_t size, uint8_t* data);
    ~Lpc();
};

#endif



