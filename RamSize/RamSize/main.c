/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security
 * Institute of Information Engineering
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * LuoPeng, luopeng@iie.ac.cn
 * Updated in May 2016
 *
 */

#include <stdio.h>

//#include <avr/io.h>
#include <avr/pgmspace.h> 
#include "aes_decrypt.h"
#include "aes_encrypt.h"
#include "aes_schedule.h"

const uint8_t const_cipher[AES_BLOCK_SIZE] PROGMEM = {
	//0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
	//0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9,
	0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
	0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};
const uint8_t plaintext[] PROGMEM= {
	//0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	//0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

int main(int argc, char *argv[]) {

	uint8_t i;

	/* 128 bit key */

/*s
	data types changed to const
*/

 
	 uint8_t ciphertext[AES_BLOCK_SIZE];


	const uint8_t*plaintext1=plaintext;
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];

	// key schedule
	aes_key_schedule_128(roundkeys);

	// encryption
	aes_encrypt_128(roundkeys, plaintext1, ciphertext);

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		if ( ciphertext[i] != pgm_read_byte(&const_cipher[i]) ) { break; }
	}


	// decryption
	aes_decrypt_128(roundkeys, ciphertext, ciphertext);
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		if ( ciphertext[i] != pgm_read_byte(&plaintext[i]) ) { break; }
	}

	return 0;
}
