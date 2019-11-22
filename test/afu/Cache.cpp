#include "Cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  // create cache
  printf("Cache: Create cache with\n");
  printf("Cache: block size = %d\n", block_size);
  printf("Cache: cache lines = %d\n", pCache->cache_lines);
  printf("Cache: cache size = %d\n", cache_size);
  pCache->ppBlock = 
          (psBlock*) malloc(sizeof(psBlock)*pCache->cache_lines);
  assert(pCache->ppBlock != NULL);
  //printf("Cache: pointer to cache = 0x%x\n", pCache->ppBlock);
  printf("Cache: create cache blocks\n");
  for(i=0; i<pCache->cache_lines; i++) {
    // create cache blocks and attributes
    pCache->ppBlock[i] = (psBlock) malloc(sizeof(sBlock));
    assert(pCache->ppBlock != NULL);
    //printf("Cache: address of block[%d] = 0x%x\n", i, &pCache->ppBlock[i]);
    //printf("Cache: pointer to block attribute = 0x%x\n", pCache->ppBlock[i]);
    pCache->ppBlock[i]->valid = 0;
    pCache->ppBlock[i]->dirty = 0;
    pCache->ppBlock[i]->tag = NULL;
  }
  return pCache;
}

/*  offset  = 6 bit
    index   = 6 bits
    tag     = 20 bits
*/
char* Cache::Read(psCache pCache, int address)
{
  int index;
  int tag;
  char* data;

  // tag=[31:12], index=[11:6], offset=[5:0]
  index = (address & 0x00000FC0) >> 6;
  printf("Cache: index = 0x%x\n", index);
  tag = (address & 0xFFFFF000) >> 12;
  printf("Cache: tag = 0x%x\n", tag);
  if((pCache->ppBlock[index]->valid == 1) && 
      (pCache->ppBlock[index]->tag == tag)) {
    data = pCache->ppBlock[index]->data;
  }
  else {
    printf("Cache: no data found in cache\n");
    data = NULL;
  }

  return data;
}

int Cache::Write(psCache pCache, int address, char* data)
{
  int index;
  int tag;

  index=0;

  // tag=[31:12], index=[11:6], offset=[5:0]
  printf("address = 0x%x\n", address);
  index = (address & 0x00000FC0) >> 6;
  printf("Cache: index = 0x%x\n", index);
  tag = (address & 0xFFFFF000) >> 12;
  printf("Cache: tag = 0x%x\n", tag);
  if((pCache->ppBlock[index]->tag == tag) &&
     (pCache->ppBlock[index]->valid==1)) {
    printf("Cache: tag exist, update cache line\n");
    pCache->ppBlock[index]->dirty = 1;
  }
  else {
    printf("Cache: new tag, add cache line.\n");
    pCache->ppBlock[index]->tag = tag;
    pCache->ppBlock[index]->valid = 1;
    pCache->ppBlock[index]->dirty = 0;
  }
  memcpy(pCache->ppBlock[index]->data, data, 64);
  //printf("cache data = 0x");
  //for(int i=0; i<64;i++){
  //  printf("%02x", (unsigned char)pCache->ppBlock[index]->data[i]);
  //}
  return 0;
}

void Cache::UpdateAttribute(psCache pCache, int address, int valid, int dirty) {
  int index;
  int tag;

  index = (address & 0x00000FC0) >> 6;
  tag = (address & 0xFFFFF000) >> 12;
  if(pCache->ppBlock[index]->tag == tag) {
    pCache->ppBlock[index]->valid = valid;
    pCache->ppBlock[index]->dirty = dirty;
  }
  else {
    printf("Cache: cache line does not exist.\n");
  }
  
}

void Cache::Print(psCache pCache)
{
  int i;
  int j;

  for(i=0; i<pCache->cache_lines; i++) {
    if(pCache->ppBlock[i]->tag != NULL) {
      printf("tag\t0x%x\n", pCache->ppBlock[i]->tag);
      printf("index\t0x%x\n",i);
      printf("valid\t0x%x\n",pCache->ppBlock[i]->valid);
      printf("dirty\t0x%x\n",pCache->ppBlock[i]->dirty);
      printf("\ncache = 0x");
      for(j=0; j<64; j++) {
        printf("%02x", (unsigned char)pCache->ppBlock[i]->data[j]);
      }
      printf("\n");
    }
  }
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

