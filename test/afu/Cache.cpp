#include "Cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

Cache::Cache() { }

psCache Cache::Create(int cache_size, int block_size, int write_policy)
{
  psCache pCache;
  int i;

  pCache = (psCache)malloc(sizeof(sCache));
  if(pCache == NULL)
  {
    fprintf(stderr, "Could not allocate memory for cache.\n");
    return NULL;
  }

  pCache->hits = 0;
  pCache->misses = 0;
  pCache->reads = 0;
  pCache->writes = 0;
  pCache->write_policy= write_policy;
  pCache->block_size = block_size;
  pCache->cache_size = cache_size;
  pCache->cache_lines = CACHE_SIZE/CACHE_BLOCK_SIZE;
  // create cache blocks
  printf("Cache: Create cache with\n");
  printf("Cache: block size = %d\n", block_size);
  printf("Cache: cache lines = %d\n", pCache->cache_lines);
  printf("Cache: cache size = %d\n", cache_size);
  pCache->ppBlock = 
          (psBlock*) malloc(sizeof(psBlock)*pCache->cache_lines);
  assert(pCache->ppBlock != NULL);
  printf("Cache: pointer to cache = 0x%x\n", pCache->ppBlock);
  printf("Cache: create cache blocks\n");
  for(i=0; i<pCache->cache_lines; i++) {
    // create cache blocks attributes
    pCache->ppBlock[i] = (psBlock) malloc(sizeof(sBlock));
    assert(pCache->ppBlock != NULL);
    printf("Cache: address of block[%d] = 0x%x\n", i, &pCache->ppBlock[i]);
    printf("Cache: pointer to block attribute = 0x%x\n", pCache->ppBlock[i]);
    pCache->ppBlock[i]->valid = 0;
    pCache->ppBlock[i]->dirty = 0;
    pCache->ppBlock[i]->tag = NULL;
  }
  return pCache;
}

/*  offset  = 6 bit
    index   = 4 bits
    tag     = 22 bits
*/
char* Cache::Read(psCache pCache, int address)
{
  int index;
  int tag;
  char* data;
  psBlock block;

  index = (address & 0xFFFFFFC0) >> 6;
  printf("Cache: index = 0x%x\n", index);
  tag = (address & 0xFFFFFC00) >> 10;
  printf("Cache: tag = 0x%x\n", tag);
  if(pCache->ppBlock[index]->valid ==1 && 
      (pCache->ppBlock[index]->tag == tag)) {
    block = pCache->ppBlock[index];
    data = block->data;
  }
  else {
    printf("Cache: no data found in cache\n");
    data = NULL;
  }

  return data;
}

int Cache::Write(psCache pCache, int address)
{
  int index;
  psBlock block;

  index=0;

  //calculate address to get the cache block
  block = pCache->ppBlock[index];

  return 0;
}

void Cache::Destroy(psCache pCache)
{
  int i;

  if(pCache != NULL) {
    for(i=0; i< pCache->cache_lines; i++) {
      free(pCache->ppBlock[i]);
    }
    free(pCache->ppBlock);
    free(pCache);
  }

  return;
}

 
Cache::~Cache() { }

