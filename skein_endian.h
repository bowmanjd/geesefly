#ifndef _SKEIN_ENDIAN_H_
#define _SKEIN_ENDIAN_H_	1

#include <stdint.h>
#include <sys/param.h>

#ifndef BIGENDIAN
# ifdef BYTE_ORDER
#  if BYTE_ORDER == BIG_ENDIAN
#   define BIGENDIAN	1
#  endif
# endif
#endif

#ifdef BIGENDIAN
uint64_t byte_swap64(uint64_t words)
{
	return  ((words & 0xFF) << 56) |
		(((words >> 8) & 0xFF) << 48) |
		(((words >>16) & 0xFF) << 40) |
		(((words >>24) & 0xFF) << 32) |
		(((words >>32) & 0xFF) << 24) |
		(((words >>40) & 0xFF) << 16) |
		(((words >>48) & 0xFF) <<  8) |
		(((words >>56) & 0xFF));
}

void words2bytes(uint8_t *dst,const uint64_t *src, uint16_t length)
{
	uint16_t n;

	for (n=0;n<length;n++)
		dst[n] = (uint8_t) (src[n>>3] >> (8*(n&7)));
}

void bytes2words(uint64_t *dst,const uint8_t *src, uint16_t length)
{
	uint16_t n;

	for (n=0;n<8*length;n+=8)
		dst[n/8] = (((uint64_t) src[n])) +
			   (((uint64_t) src[n+1]) <<  8) +
			   (((uint64_t) src[n+2]) << 16) +
			   (((uint64_t) src[n+3]) << 24) +
			   (((uint64_t) src[n+4]) << 32) +
			   (((uint64_t) src[n+5]) << 40) +
			   (((uint64_t) src[n+6]) << 48) +
			   (((uint64_t) src[n+7]) << 56);
}
#else
#define byte_swap64(words)  (words)
#define words2bytes(dst08,src64,bCnt) memcpy(dst08,src64,bCnt)
#define bytes2words(dst64,src08,wCnt) memcpy(dst64,src08,8*(wCnt))
#endif

#endif  /* ifndef _SKEIN_ENDIAN_H_ */
