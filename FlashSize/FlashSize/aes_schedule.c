/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in Oct 2016
 * Updated in Jan 2017, update muliple function on GF(2^8).
 *
 */
#include <stdint.h>

//#include <avr/pgmspace.h>
#include "aes_schedule.h"
#include "aes_encrypt.h"
/*
 * round constants
 */
//static uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
void aes_key_schedule_128(register uint8_t *roundkeys) {

    uint8_t temp[4];
    register uint8_t *last4bytes; // point to the last 4 bytes of one round
    register uint8_t *lastround;
    register uint8_t i , j;
	i=0;
	while(i<16){
		*roundkeys++ = ++i;
	}
    last4bytes = roundkeys-4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] =  SBOX[*last4bytes++];
        temp[0] =  SBOX[*last4bytes++];
        temp[1] =  SBOX[*last4bytes++];
        temp[2] =  SBOX[*last4bytes++];
		if(i<8){
			temp[0] ^= 1<<i;
		}else if(i==8){
			temp[0] ^=0x1b ;
		}else if(i==9){
			temp[0] ^=0x36;
		}
        lastround = roundkeys-16;
		j=-1;
		while(++j<4){
			*roundkeys++ = temp[j] ^ *lastround++;
		}
        // k4-k7 for next round
		j=13;
		while(--j)
		{        
			*roundkeys++ = *last4bytes++ ^ *lastround++;
		}
/*        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
  */
    }
}
