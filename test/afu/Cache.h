#ifndef __CACHE__
#define __CACHE__

#define CACHE_LINE 128
#define CACHE_SIZE  4096
#define CACHE_BLOCK_SIZE  64
#define CACHE_TAG 20
#define CACHE_INDEX 6
#define CACHE_OFFSET 6    // 64 bytes offset

typedef struct sBlock* psBlock;
typedef struct sCache* psCache;

struct sBlock
{
  int   valid;
  int   tag;
  int   dirty;
  char  data[64];
};

struct sCache
{
  int hits;
  int misses;
  int reads;
  int writes;
  int cache_size;
  int block_size;
  int cache_lines;
  int write_policy;
  psBlock* ppBlock;
};

class Cache
{
  private:

  public:
    Cache();  // constructor
    psCache Create(int cache_size, int block_size, int write_policy);
    char* Read(psCache pCache, int address);
    int Write(psCache pCache, int address, char* data);
    void Print(psCache pCache);
    void Destroy(psCache pCache);
    ~Cache(); // desctructor
};

#endif
