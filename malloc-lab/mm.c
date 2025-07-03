/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"


/* Basic constants and macros */
#define WSIZE       4       /* Word and header/footer size (bytes) */
#define DSIZE       8       /* Double word size (bytes) */
#define CHUNKSIZE (1<<12)   /* Extend heap by this amount (bytes) */

// 최댓값 판별
#define MAX(x,y) ((x) > (y)? (x) : (y))
#define MIN(x,y) ((x) < (y)? (x) : (y))

// 사이즈와 할당 여부를 워드로 압축
#define PACK(size, alloc) ((size) | (alloc))

// 주소 p의 워드 읽고 쓰기
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

// 주소 p에서 크기와 할당여부를 읽음
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

// 블록 포인트를 받으면 헤더, 푸터의 주소 계산
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

// 블록 포인터 bp로 이전, 다음 블록의 주소 계산
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)bp - WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)bp - DSIZE)))

static void place(void *bp, size_t asize);
static void *extend_heap(size_t words);
static void *coalesce(void *bp);

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "4team",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT size를 8바이트 단위로 올림(정렬)해줌*/
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// 포인터 생성
static char *heap_listp = NULL;

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    // 1. 최소 필요한 힙 공간(16바이트=4*WSIZE)을 요청 (mem_sbrk)
    if ((heap_listp = mem_sbrk(4*WSIZE)) == (void *)-1){
        return -1;
    }
    // padding 4bytes 추가
    // PUT(p, val) (*(unsigned int *)(p) = (val))이기 때문에 
    // int 4바이트로 heap_listp시작 4바이트 모두 0으로 초기화
    PUT(heap_listp, 0);

    // 2. Prologue Block-header 생성 (PUT, PACK 사용)
    PUT(heap_listp + WSIZE, PACK(DSIZE, 1));  

    // 3. Prologue Block-footer 생성 (PUT, PACK 사용)
    PUT(heap_listp + DSIZE, PACK(DSIZE, 1));

    // 4. Epilogue Block-header 생성 (PUT, PACK 사용)
    PUT(heap_listp + 3 * WSIZE, PACK(0, 1));

    // (취소) 5. 힙 포인터를 epilogue block 뒤의 첫 블록으로 지정
    // (최종) 5. 힙 포인터를 payload 시작 위치로 이동 
    heap_listp += (2 * WSIZE);

    // 6. 힙 확장 (최소 CHUNKSIZE만큼 늘리기)해서 free block으로 세팅 (extend_heap)
    if(extend_heap(CHUNKSIZE/WSIZE) == NULL){
        return -1;
    }

    return 0;
}

/*
 * first-fit - search for a block of at least asize bytes.
*/
static void *find_fit(size_t asize) {
	void *bp;
	bp = heap_listp;
	
	while (GET_SIZE(HDRP(bp)) > 0){
		if((GET_SIZE(HDRP(bp)) >= asize) && (!GET_ALLOC(HDRP(bp)))){
			return bp;
		}
		bp = NEXT_BLKP(bp);
	}
	return NULL;
}

/*
 * place - Place block of asize bytes at start of free block bp,
 *         splitting only if the remainder would be at least minimum block size.
 */
static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));

    if ((csize - asize) >= (2 * DSIZE)) {
        // Case 1: Split
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));
    }
    else {
        // Case 2: Use entire block
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    // 1. 요청 사이즈 정렬 (align)
    size = ALIGN(size + DSIZE);

    // 2. find_fit으로 size에 맞는 free블록 있는지 확인
    void *bp = find_fit(size);
    if (bp != NULL){
        // 3. 크기에 맞는 블록 있으면
        place(bp, size);
        return bp;
    }
    else{
        // 4. 없으면 extend_heap()로 힙 늘려서 free 블록 만들고 새로 할당
        size_t extend_size = MAX(size, CHUNKSIZE);
        bp = extend_heap(extend_size/WSIZE);
        place(bp, size);
        return bp;
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    // 1. 해당 블록의 header와 footer의 alloc을 0으로 세팅
    PUT(HDRP(ptr), PACK((GET_SIZE(HDRP(ptr))), 0));
    PUT(FTRP(ptr), PACK((GET_SIZE(HDRP(ptr))), 0));

    // 2. coalesce(bp) 호출
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 이전에 할당된 메모리 블록에 대한 포인터 ptr, 새 크기(바이트) size
 */
void *mm_realloc(void *ptr, size_t size)
{
    // void *oldptr = ptr;
    // void *newptr;
    // size_t copySize;

    // newptr = mm_malloc(size);
    // if (newptr == NULL)
    //     return NULL;
    // copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    // if (size < copySize)
    //     copySize = size;
    // memcpy(newptr, oldptr, copySize);
    // mm_free(oldptr);
    // return newptr;

    // 1. ptr == NULL이면
    if (ptr == NULL){
        // 새로 malloc(size) 반환
        return mm_malloc(size);
    }
    // 2. size == 0이면
    if (size == 0){
        // ptr을 free
        free(ptr);
        return NULL;
    }
    // 3. (ptr ≠ NULL) & size ≠ 0이면 → relloc
    else {
        // 새로운 크기의 블록을 mm_malloc(size)로 할당
        void *new_ptr = mm_malloc(size);

        if(new_ptr == NULL){
            return NULL;
        }

        // 기존 블록 크기 저장
        size_t old_size = GET_SIZE(HDRP(ptr));

        // 기존 블록 크기와 매개변수로 들어온 size 중 작은 크기만큼 memcpy로 내용 복사
        size_t copy_size = MIN(old_size, size);
        // memcpy(복사받을 메모리 주소, 복사할 메모리 주소, 몇 바이트를 복사할지)
        memcpy(new_ptr, ptr, copy_size);

        // 기존 크기보다 더 큰 공간을 할당받으면 새로 늘어난 부분 0으로 초기화
        if (size > old_size){
            // mem_set(시작주소, 채울 값, 몇 바이트)
            memset((char *)new_ptr + old_size, 0, size - old_size);
        }

        // 기존 블록 mm_free(ptr)
        mm_free(ptr);

        // 새 블록 포인터 리턴
        return new_ptr;
    }
}

static void *extend_heap(size_t words){
    // 블록 포인터 생성 : 현재 블록의 시작 주소 가리키는 포인터
    char *bp;
    size_t size;

    // 1. words가 홀수면 짝수로 반올림 (8바이트 정렬)
    if (words % 2 == 1){
        words += 1;
    }

    size = words * WSIZE;
    // 2. mem_sbrk로 힙 확장
	// 새 메모리 요청 = words * WSIZE
    if((bp = mem_sbrk(words * WSIZE)) == (void *)-1){
    // 실패하면 NULL 리턴f
        return NULL;
    }

    // 3. 새 free block 헤더/푸터 설정
	//     - 확보한 블록 크기 = 요청 크기
	//     - alloc = 0
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));

    // 4. 새 Epilogue Header 생성
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0,1));

    // 5. coalesce 호출
	// 새 free block을 coalesce로 병합
    return coalesce(bp);
}

// 앞 뒤 블록 확인해서 free 블록이면 병합하는 함수
static void *coalesce(void *bp){
    // 1. prev의 푸터 위치
    // GET_ALLOC으로 할당 여부 확인 후 변수(prev_alloc)에 저장
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));

    // 2. next의 헤더 위치
    // GET_ALLOC으로 할당 여부 확인 후 변수(next_alloc)에 저장
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));

    // 현재 블록의 사이즈 저장
    size_t size = GET_SIZE(HDRP(bp));
    
    if(!prev_alloc){
        // 현재 블록 size + 앞 블록 size 더해서 size 늘리고
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        // 늘린 size를 현재 블록 푸터 & 앞 블록 헤더에 기록 & alloc도 0으로 기록
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        // bp를 prev 블록의 payload로 이동
        bp = PREV_BLKP(bp);
    }

 // 4. if 뒷 블록이 free인 경우
    if(!next_alloc){
        // 현재 블록 size + 뒷 블록 size 더해서 size 늘리고
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        // 늘린 size를 현재 블록 헤더 & 뒷 블록 푸터에 기록 & alloc도 0으로 기록

        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    return bp;
}