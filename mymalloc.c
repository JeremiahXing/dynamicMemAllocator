#include "mymalloc.h"
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#define PORT PROT_READ|PROT_WRITE
#define FLAGS MAP_PRIVATE|MAP_ANONYMOUS
#define FD 0
#define OFFSET 0
#define is_dummy(ptr) (ptr->size == 0)
#define is_free(header) (!(header->size & 1)) //LSB of size == 0 means free
#define set_allocated(header) (header->size = (header->size & -2) + 1) //set LSB to 1
#define set_free(header) (header->size = header->size & -2) //set LSB to 0
#define get_size(header) (header->size & -2)

typedef struct Header {
  size_t size;  //the size well include metadata
  size_t left_size; //the size of the left block, if this value is 0 then there is no left block, 
                    //if this value is -1 then this is large block(using HD optimization)
  struct Header *next;
  struct Header *prev;
} Header;

typedef struct Range_Mark {
    Header* start;
    Header* end;
    struct Range_Mark * next;
}Range_Mark;

const size_t kMaxAllocationSize = (16ull << 20);  // maximum allocation size
const size_t kLargeAllocationSize = (8ull << 20); // large allocation size using mmap directly
const size_t kMateDataSize = sizeof(Header);  // metadata size

Header free_lists[N_LISTS];  // free lists
Range_Mark range_mark[N_LISTS]; //marks the pointer range of each list

inline static size_t round_up(size_t size, size_t alignment) //this function works when alignment is power of 2
{
  const size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}


Header * init_list(int idx, size_t size)
{
  Header* list_head = &free_lists[idx];
  int n = (size + kMateDataSize) / ARENA_SIZE + 1;
  Header* header = mmap(NULL, n*ARENA_SIZE, PORT, FLAGS, FD, OFFSET);
  if (header == NULL) 
  {
    errno = ENOMEM;
    fprintf(stderr, "%s %d list can't initialized\n", strerror((int)errno), (int)errno);
    return NULL;
  }
  header->size = n*ARENA_SIZE - round_up(kMateDataSize, sizeof(size_t));  //it's free by default
  header->left_size = 0;

  Header* dummy = (Header*)((char*)header + header->size);
  dummy->size = 0;
  dummy->next = NULL;
  header->next = dummy;
  dummy->prev = header;
  header->prev = list_head;  //add in free list
  list_head->next = header;

  Range_Mark * rm_ptr = &range_mark[idx];
  if(rm_ptr->start == NULL && rm_ptr->end == NULL)
  {
    rm_ptr->start = header;
    rm_ptr->end = dummy;
  }
  else
  {
    Range_Mark * new_rm = mmap(NULL, sizeof(Range_Mark), PORT, FLAGS, FD, OFFSET);
    if (header == NULL)
    {
      errno = ENOMEM;
      fprintf(stderr, "%s %d list can't initialized\n", strerror((int)errno), (int)errno);
      return NULL;
    }
    new_rm->start = header;
    new_rm->end = dummy;
    new_rm->next = rm_ptr->next;
    rm_ptr->next = new_rm;
  }
  return header;
}


static Header * fit_list(int idx, size_t size)
{
  Header* list_head = &free_lists[idx];
  Header* ptr = list_head->next;
  while(ptr != NULL)
  {
    if(get_size(ptr) < size)
      ptr = ptr->next;
    else
      return ptr;
  }
  if (ptr == NULL)
  {
    return init_list(idx, size);
  }
}

void * split_block(Header *header, size_t right_size) // we're going to allocate right split block
{
  size_t origin_size = get_size(header);
  size_t left_size = origin_size - right_size;
  if (left_size < kMateDataSize + kMinAllocationSize) //can't be split
  {
    header->prev->next = header->next;
    header->next->prev = header->prev;  // remove header from the free list
    set_allocated(header);
    char* ptr = (char*)header + kMateDataSize;
    return (void*)((void**)ptr-2); // as this part is allocated, we optimize 2 pointers' size
  }
  else
  {
    Header *new_header = (Header*)((char*)header + left_size); //new_header block is allocated
    new_header->size = right_size;
    new_header->left_size = left_size;
    set_allocated(new_header);
    header->size = left_size;
    Header* new_right_header = (Header*)((char*)new_header + get_size(new_header));
    new_right_header->left_size = right_size;
    char* ptr = (char*)new_header + kMateDataSize;
    return (void*)((void**)ptr-2); 
  }
}


static void append_block(int idx, Header * header)
{
  Header * list_head = &free_lists[idx];
  Header * successor = list_head->next;
  list_head->next = header; //insert to head
  header->prev = list_head;
  header->next = successor;
  successor->prev = header;
}

void *my_malloc(size_t size)
{
  if(size == 0) 
  {
    errno = EINVAL;
    fprintf(stderr, "%s %d allocation size can't be 0\n", strerror((int)errno), (int)errno);
    return NULL;
  }
  if (size > kMaxAllocationSize)
  {
    errno = EINVAL;
    fprintf(stderr, "%s %d allocation size too large\n", strerror((int)errno), (int)errno);
    return NULL;
  }
  if(size >= kLargeAllocationSize && size <= kMaxAllocationSize) //optimize large size allocation;
  {
    size = round_up(size + kMateDataSize, sizeof(size_t));
    Header * header = mmap(NULL, size + kMateDataSize, PORT, FLAGS, FD, OFFSET);
    if (header == NULL)
    {
      errno = ENOMEM;
      fprintf(stderr, "%s %d allocation failed\n", strerror((int)errno), (int)errno);
      return NULL;
    }
    header->size = size;
    header->left_size = -1; //mark as large block
    char* ptr = (char*)header + kMateDataSize;
    return (void*)((void**)ptr-2);
  }
  size = round_up(size + kMateDataSize, sizeof(size_t)); // we need to count metadata in size
  int list_idx = size / round_up(sizeof(size_t)+kMateDataSize, sizeof(size_t));
  if (list_idx >= N_LISTS - 1)
  {
    list_idx = N_LISTS - 1;
  }

  Header *header = fit_list(list_idx, size);
  return split_block(header, size);
}

void my_free(void *ptr)
{
  if(ptr == NULL)
  {
    errno = EINVAL;
    fprintf(stderr, "%s %d can't free NULL pointer\n", strerror((int)errno), (int)errno);
    exit(1);
  }

  Header* header = (Header*)((char*)((void**)ptr+2)-kMateDataSize);
  int list_idx = get_size(header) / round_up(sizeof(size_t)+kMateDataSize, sizeof(size_t));
  if (list_idx >= N_LISTS - 1)
  {
    list_idx = N_LISTS - 1;
  }
  
  //check if it is large block
  if (header->left_size == -1)
  {
    munmap(header, header->size);
    return;
  }

  //check if the block is in the free lists range
  int check_flag = 0;
  Range_Mark * rm_ptr = &range_mark[list_idx];
  while(rm_ptr)
  {
    if(ptr >= rm_ptr->start && ptr < rm_ptr->end)
    {
      check_flag = 1;
      break;
    }
    else
      rm_ptr = rm_ptr->next;
  }
  if(!check_flag)
  {
    errno = EINVAL;
    fprintf(stderr, "my_free: %s\n", strerror((int)errno));
    exit(1);
  }

  set_free(header);
  Header* left_header = (Header*)((char*)header - header->left_size);
  Header* right_header = (Header*)((char*)header + get_size(header));
  size_t new_size = get_size(header);
  if(is_free(right_header) && !is_dummy(right_header))
  {
    new_size += get_size(right_header);
    right_header->prev->next = right_header->next;
    right_header->next->prev = right_header->prev;
  }
  if(is_free(left_header) && !is_dummy(left_header))
  {
    header = left_header;
    new_size += get_size(left_header);
    left_header->prev->next = left_header->next;
    left_header->next->prev = left_header->prev;
  }
  header->size = new_size;
  Header* new_right_header = (Header*)((char*)header + get_size(header));
  new_right_header->left_size = header->size;
  append_block(list_idx, header);
}
