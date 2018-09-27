/*
 * Copyright (c) 2017-2018 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _SECURITY_SI_32_SECTRUST_PINNING_REQUIRED_H_
#define _SECURITY_SI_32_SECTRUST_PINNING_REQUIRED_H_

/* subject:/CN=query.ess.apple.com/OU=IDS SRE/O=Apple Inc./C=US */
/* issuer :/CN=Apple Server Authentication CA/OU=Certification Authority/O=Apple Inc./C=US */
uint8_t _ids_prod[]={
    0x30,0x82,0x07,0x86,0x30,0x82,0x06,0x6E,0xA0,0x03,0x02,0x01,0x02,0x02,0x08,0x1A,
    0xFE,0x9C,0x01,0x42,0x80,0xFB,0xAE,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,
    0x0D,0x01,0x01,0x0B,0x05,0x00,0x30,0x6D,0x31,0x27,0x30,0x25,0x06,0x03,0x55,0x04,
    0x03,0x0C,0x1E,0x41,0x70,0x70,0x6C,0x65,0x20,0x53,0x65,0x72,0x76,0x65,0x72,0x20,
    0x41,0x75,0x74,0x68,0x65,0x6E,0x74,0x69,0x63,0x61,0x74,0x69,0x6F,0x6E,0x20,0x43,
    0x41,0x31,0x20,0x30,0x1E,0x06,0x03,0x55,0x04,0x0B,0x0C,0x17,0x43,0x65,0x72,0x74,
    0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6F,0x6E,0x20,0x41,0x75,0x74,0x68,0x6F,0x72,
    0x69,0x74,0x79,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x0A,0x0C,0x0A,0x41,0x70,
    0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,
    0x06,0x13,0x02,0x55,0x53,0x30,0x1E,0x17,0x0D,0x31,0x37,0x30,0x39,0x31,0x39,0x32,
    0x30,0x35,0x36,0x31,0x35,0x5A,0x17,0x0D,0x31,0x38,0x31,0x30,0x31,0x39,0x32,0x30,
    0x35,0x36,0x31,0x35,0x5A,0x30,0x52,0x31,0x1C,0x30,0x1A,0x06,0x03,0x55,0x04,0x03,
    0x0C,0x13,0x71,0x75,0x65,0x72,0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,
    0x65,0x2E,0x63,0x6F,0x6D,0x31,0x10,0x30,0x0E,0x06,0x03,0x55,0x04,0x0B,0x0C,0x07,
    0x49,0x44,0x53,0x20,0x53,0x52,0x45,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x0A,
    0x0C,0x0A,0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x31,0x0B,0x30,0x09,
    0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x30,0x82,0x01,0x22,0x30,0x0D,0x06,
    0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0F,
    0x00,0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00,0xBE,0x9A,0x0A,0x7E,0x25,0xE0,
    0x09,0xD1,0xC4,0x0E,0xC6,0xCB,0x15,0xB6,0xE0,0xB2,0xF8,0xB6,0xDB,0x9D,0xC7,0x5D,
    0x40,0xA3,0x82,0x03,0xE6,0x8A,0x66,0x0F,0x87,0x10,0xA9,0x58,0x2B,0xCB,0x94,0x60,
    0xB6,0x13,0x8B,0x78,0xB0,0xE6,0x9B,0xA6,0xEF,0x1E,0xE2,0xF2,0xC2,0xC6,0x69,0x67,
    0xA2,0xB6,0x5C,0xA7,0x6C,0xA8,0x3C,0xC7,0xBC,0x3B,0x6E,0x96,0xEE,0x65,0x19,0x8D,
    0x37,0x9A,0xAF,0x35,0xBF,0x51,0xB0,0xD6,0xEC,0x9D,0xBF,0x05,0x44,0xBD,0x2F,0x70,
    0x9D,0x3B,0x84,0xEC,0x2C,0x74,0x48,0x8E,0x68,0x00,0x7E,0x9B,0x19,0xA2,0xE9,0x11,
    0xF7,0x35,0x16,0x3E,0x03,0xD0,0x42,0x4E,0x97,0xC2,0xA9,0x48,0x9F,0x13,0xD8,0x74,
    0x5C,0xD6,0x3D,0xC3,0x8B,0x59,0x76,0xD6,0xC4,0x9D,0x60,0x1D,0xE8,0x8B,0x0D,0x5D,
    0x38,0xB6,0x7F,0xC7,0xE4,0x55,0xCC,0x29,0x52,0x92,0xB8,0x79,0x60,0x3A,0x25,0xE4,
    0xE9,0xA0,0xAE,0xAB,0xF2,0x0F,0x15,0x6C,0xD3,0x10,0x01,0x33,0x18,0x91,0x68,0x49,
    0x37,0x7C,0x61,0x26,0x44,0xE9,0xDE,0x4E,0x8B,0xE5,0x3C,0x2E,0xBE,0x3F,0x8C,0x0D,
    0x4D,0x7E,0x8B,0x43,0x4F,0x5E,0x09,0xF3,0xD2,0x6B,0xA2,0x27,0xAF,0xDE,0x9C,0x9A,
    0xEB,0xD4,0x76,0x40,0x69,0x82,0xB7,0x94,0xF3,0x2B,0x2E,0xA8,0xA4,0x97,0x38,0x02,
    0xEE,0x3B,0x8C,0x82,0x16,0x9E,0x12,0x42,0x57,0x05,0x9F,0xC7,0x07,0x82,0x78,0x3D,
    0x47,0xB8,0x11,0xDD,0x81,0x25,0x24,0xF2,0x49,0x7B,0x34,0x7A,0xC1,0x16,0xE4,0x34,
    0x36,0x67,0xAF,0x75,0x4F,0xB3,0x3D,0xEF,0x83,0xF7,0x02,0x03,0x01,0x00,0x01,0xA3,
    0x82,0x04,0x43,0x30,0x82,0x04,0x3F,0x30,0x1D,0x06,0x03,0x55,0x1D,0x0E,0x04,0x16,
    0x04,0x14,0x6F,0xD8,0x77,0x83,0x70,0xEB,0x9F,0xB6,0x01,0x22,0xDB,0x03,0x56,0x6B,
    0x20,0x12,0xAC,0x2F,0x3F,0x9A,0x30,0x0C,0x06,0x03,0x55,0x1D,0x13,0x01,0x01,0xFF,
    0x04,0x02,0x30,0x00,0x30,0x1F,0x06,0x03,0x55,0x1D,0x23,0x04,0x18,0x30,0x16,0x80,
    0x14,0x2C,0xC5,0x6D,0x52,0xDD,0x31,0xEF,0x8C,0xEC,0x08,0x81,0xED,0xDF,0xDC,0xCA,
    0x43,0x00,0x45,0x01,0xD0,0x30,0x3C,0x06,0x03,0x55,0x1D,0x1F,0x04,0x35,0x30,0x33,
    0x30,0x31,0xA0,0x2F,0xA0,0x2D,0x86,0x2B,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x63,
    0x72,0x6C,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x2F,0x61,0x70,0x70,
    0x6C,0x65,0x73,0x65,0x72,0x76,0x65,0x72,0x61,0x75,0x74,0x68,0x63,0x61,0x31,0x2E,
    0x63,0x72,0x6C,0x30,0x0E,0x06,0x03,0x55,0x1D,0x0F,0x01,0x01,0xFF,0x04,0x04,0x03,
    0x02,0x05,0xA0,0x30,0x13,0x06,0x03,0x55,0x1D,0x25,0x04,0x0C,0x30,0x0A,0x06,0x08,
    0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01,0x30,0x82,0x03,0x77,0x06,0x03,0x55,0x1D,
    0x11,0x04,0x82,0x03,0x6E,0x30,0x82,0x03,0x6A,0x82,0x13,0x71,0x75,0x65,0x72,0x79,
    0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x16,
    0x73,0x6D,0x73,0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,
    0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x16,0x71,0x75,0x65,0x72,0x79,0x2D,0x70,0x76,
    0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x18,
    0x6F,0x70,0x65,0x6E,0x6D,0x61,0x72,0x6B,0x65,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,
    0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x69,0x6E,0x76,0x69,0x74,0x61,
    0x74,0x69,0x6F,0x6E,0x2D,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,
    0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x70,0x72,0x6F,0x66,0x69,0x6C,0x65,0x2D,0x63,
    0x61,0x72,0x72,0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,
    0x6F,0x6D,0x82,0x1F,0x72,0x65,0x67,0x69,0x73,0x74,0x72,0x61,0x74,0x69,0x6F,0x6E,
    0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,
    0x63,0x6F,0x6D,0x82,0x16,0x69,0x64,0x65,0x6E,0x74,0x69,0x74,0x79,0x2E,0x65,0x73,
    0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1E,0x69,0x6E,0x76,
    0x69,0x74,0x61,0x74,0x69,0x6F,0x6E,0x2D,0x63,0x61,0x72,0x72,0x79,0x2E,0x65,0x73,
    0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1E,0x61,0x67,0x67,
    0x72,0x65,0x67,0x61,0x74,0x6F,0x72,0x2D,0x63,0x61,0x72,0x72,0x79,0x2E,0x65,0x73,
    0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x69,0x64,0x65,
    0x6E,0x74,0x69,0x74,0x79,0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,
    0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x18,0x61,0x67,0x67,0x72,0x65,0x67,
    0x61,0x74,0x6F,0x72,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,
    0x6F,0x6D,0x82,0x1C,0x69,0x64,0x65,0x6E,0x74,0x69,0x74,0x79,0x2D,0x63,0x61,0x72,
    0x72,0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,
    0x82,0x16,0x71,0x75,0x65,0x72,0x79,0x2D,0x6D,0x72,0x2E,0x65,0x73,0x73,0x2E,0x61,
    0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1A,0x70,0x72,0x6F,0x66,0x69,0x6C,
    0x65,0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,
    0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x61,0x67,0x67,0x72,0x65,0x67,0x61,0x74,0x6F,0x72,
    0x2D,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,
    0x6D,0x82,0x1A,0x72,0x65,0x67,0x69,0x73,0x74,0x72,0x61,0x74,0x69,0x6F,0x6E,0x2E,
    0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x20,0x72,
    0x65,0x67,0x69,0x73,0x74,0x72,0x61,0x74,0x69,0x6F,0x6E,0x2D,0x63,0x61,0x72,0x72,
    0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,
    0x17,0x73,0x6D,0x73,0x2D,0x63,0x61,0x72,0x72,0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,
    0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x18,0x71,0x75,0x65,0x72,0x79,0x2D,
    0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,
    0x6F,0x6D,0x82,0x16,0x6A,0x75,0x6E,0x63,0x74,0x69,0x6F,0x6E,0x2E,0x65,0x73,0x73,
    0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x11,0x73,0x6D,0x73,0x2E,
    0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x61,
    0x67,0x67,0x72,0x65,0x67,0x61,0x74,0x6F,0x72,0x2D,0x70,0x76,0x2E,0x65,0x73,0x73,
    0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x16,0x71,0x75,0x65,0x72,
    0x79,0x2D,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,
    0x6F,0x6D,0x82,0x15,0x70,0x72,0x6F,0x66,0x69,0x6C,0x65,0x2E,0x65,0x73,0x73,0x2E,
    0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x19,0x71,0x75,0x65,0x72,0x79,
    0x2D,0x63,0x61,0x72,0x72,0x79,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,
    0x2E,0x63,0x6F,0x6D,0x82,0x1B,0x69,0x6E,0x76,0x69,0x74,0x61,0x74,0x69,0x6F,0x6E,
    0x2D,0x6D,0x72,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,
    0x6D,0x82,0x1B,0x61,0x67,0x67,0x72,0x65,0x67,0x61,0x74,0x6F,0x72,0x2D,0x6D,0x72,
    0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1B,
    0x69,0x6E,0x76,0x69,0x74,0x61,0x74,0x69,0x6F,0x6E,0x2D,0x70,0x76,0x2E,0x65,0x73,
    0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x82,0x18,0x69,0x6E,0x76,
    0x69,0x74,0x61,0x74,0x69,0x6F,0x6E,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,
    0x65,0x2E,0x63,0x6F,0x6D,0x82,0x1D,0x61,0x67,0x67,0x72,0x65,0x67,0x61,0x74,0x6F,
    0x72,0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,
    0x2E,0x63,0x6F,0x6D,0x82,0x1D,0x69,0x6E,0x76,0x69,0x74,0x61,0x74,0x69,0x6F,0x6E,
    0x2D,0x74,0x65,0x73,0x74,0x2E,0x65,0x73,0x73,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,
    0x63,0x6F,0x6D,0x30,0x11,0x06,0x0B,0x2A,0x86,0x48,0x86,0xF7,0x63,0x64,0x06,0x1B,
    0x04,0x02,0x04,0x02,0x05,0x00,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,
    0x01,0x01,0x0B,0x05,0x00,0x03,0x82,0x01,0x01,0x00,0x2D,0x0C,0xCF,0x60,0xD4,0xBF,
    0xAE,0x51,0x01,0xF9,0xDF,0x46,0xBD,0xDE,0x39,0xEF,0xCA,0x36,0x6F,0xD0,0x31,0xCE,
    0x2C,0x04,0x05,0x46,0x7E,0xB5,0xC8,0x16,0xAD,0xCF,0xC2,0x3F,0xFB,0xB7,0x44,0x06,
    0xB2,0x73,0x09,0xBE,0x30,0x78,0xD9,0x90,0xED,0x73,0x7B,0x6B,0xF9,0xDC,0x7F,0x16,
    0xE7,0x6F,0x55,0x9E,0x6F,0x4B,0xD9,0x77,0x53,0xAA,0xCB,0xAA,0x98,0x76,0x07,0xE9,
    0x49,0x3C,0x52,0x91,0x22,0xEA,0x9A,0x57,0x0D,0x7E,0x2E,0x1B,0xA8,0xD5,0x55,0x70,
    0xE1,0x47,0x2B,0x55,0x04,0x9A,0x98,0x79,0x30,0x08,0xEF,0x1D,0xB7,0x2C,0x0B,0xB0,
    0x42,0x11,0x4A,0xB5,0xB5,0xB7,0xCE,0xAC,0xD1,0x8C,0x0B,0x52,0x62,0xBB,0x32,0x4A,
    0xAB,0x22,0x40,0x37,0x10,0x1B,0x67,0x51,0x4A,0x06,0x00,0x70,0xB5,0x6F,0x0B,0x45,
    0x7F,0xA0,0x8A,0x30,0xF5,0xF1,0x70,0x1F,0x61,0xBC,0xB0,0xDD,0x38,0xC1,0xAF,0xCA,
    0x26,0x79,0x90,0xFC,0x7D,0x59,0xA5,0x75,0xB4,0x89,0x11,0x2B,0xAD,0x93,0xB5,0xFE,
    0xD4,0x1A,0xC1,0xDC,0x19,0x01,0xC7,0xF6,0x6C,0xFA,0x36,0xDD,0x7F,0xBD,0x28,0x70,
    0x8E,0xC9,0xE5,0xF3,0xEB,0xC2,0xA9,0x5A,0x9D,0xBB,0x2F,0xCE,0xE6,0x8B,0x28,0xEA,
    0x8D,0x28,0x37,0x0A,0x65,0x1F,0x4E,0x03,0xC6,0xCE,0x22,0x56,0x46,0x1E,0xAF,0xC9,
    0x38,0x99,0xCA,0xE4,0x5E,0x50,0xEF,0xCE,0x63,0x29,0x1A,0x9E,0xCA,0xE2,0xAE,0x30,
    0xD4,0x99,0xC0,0x49,0x38,0xA3,0x51,0xDD,0xF2,0xA8,0x4C,0x81,0x4A,0xF7,0x36,0x9C,
    0xC2,0x18,0xC5,0xCF,0x22,0xF2,0xE9,0x8A,0xD2,0x87,
};

/* subject:/CN=Apple Server Authentication CA/OU=Certification Authority/O=Apple Inc./C=US */
/* issuer :/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA */
uint8_t _AppleServerAuth[1020]={
    0x30,0x82,0x03,0xF8,0x30,0x82,0x02,0xE0,0xA0,0x03,0x02,0x01,0x02,0x02,0x08,0x23,
    0x69,0x74,0x04,0xAD,0xCB,0x83,0x14,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,
    0x0D,0x01,0x01,0x0B,0x05,0x00,0x30,0x62,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,
    0x06,0x13,0x02,0x55,0x53,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x0A,0x13,0x0A,
    0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x31,0x26,0x30,0x24,0x06,0x03,
    0x55,0x04,0x0B,0x13,0x1D,0x41,0x70,0x70,0x6C,0x65,0x20,0x43,0x65,0x72,0x74,0x69,
    0x66,0x69,0x63,0x61,0x74,0x69,0x6F,0x6E,0x20,0x41,0x75,0x74,0x68,0x6F,0x72,0x69,
    0x74,0x79,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x03,0x13,0x0D,0x41,0x70,0x70,
    0x6C,0x65,0x20,0x52,0x6F,0x6F,0x74,0x20,0x43,0x41,0x30,0x1E,0x17,0x0D,0x31,0x34,
    0x30,0x33,0x30,0x38,0x30,0x31,0x35,0x33,0x30,0x34,0x5A,0x17,0x0D,0x32,0x39,0x30,
    0x33,0x30,0x38,0x30,0x31,0x35,0x33,0x30,0x34,0x5A,0x30,0x6D,0x31,0x27,0x30,0x25,
    0x06,0x03,0x55,0x04,0x03,0x0C,0x1E,0x41,0x70,0x70,0x6C,0x65,0x20,0x53,0x65,0x72,
    0x76,0x65,0x72,0x20,0x41,0x75,0x74,0x68,0x65,0x6E,0x74,0x69,0x63,0x61,0x74,0x69,
    0x6F,0x6E,0x20,0x43,0x41,0x31,0x20,0x30,0x1E,0x06,0x03,0x55,0x04,0x0B,0x0C,0x17,
    0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6F,0x6E,0x20,0x41,0x75,
    0x74,0x68,0x6F,0x72,0x69,0x74,0x79,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x0A,
    0x0C,0x0A,0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x31,0x0B,0x30,0x09,
    0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x30,0x82,0x01,0x22,0x30,0x0D,0x06,
    0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0F,
    0x00,0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00,0xB9,0x26,0x16,0xB0,0xCB,0x87,
    0xAB,0x71,0x15,0x92,0x8E,0xDF,0xAA,0x3E,0xE1,0x80,0xD7,0x53,0xBA,0xA4,0x60,0xCC,
    0x7C,0x85,0x72,0xF7,0x30,0x7C,0x09,0x4F,0x57,0x0D,0x4A,0xFF,0xE1,0x5E,0xC9,0x4B,
    0x50,0x13,0x02,0x64,0xB1,0xBD,0x39,0x35,0xD1,0xD7,0x04,0x51,0xC1,0x18,0xFA,0x22,
    0xFA,0xAE,0xDF,0x98,0x18,0xD6,0xBF,0x4E,0x4D,0x43,0x10,0xFA,0x25,0x88,0x9F,0xD3,
    0x40,0x85,0x76,0xE5,0x22,0x81,0xB6,0x54,0x45,0x73,0x9A,0x8B,0xE3,0x9C,0x48,0x1A,
    0x86,0x7A,0xC3,0x51,0xE2,0xDA,0x95,0xF8,0xA4,0x7D,0xDB,0x30,0xDE,0x6C,0x0E,0xC4,
    0xC5,0xF5,0x6C,0x98,0xE7,0xA6,0xFA,0x57,0x20,0x1D,0x19,0x73,0x7A,0x0E,0xCD,0x63,
    0x0F,0xB7,0x27,0x88,0x2E,0xE1,0x9A,0x68,0x82,0xB8,0x40,0x6C,0x63,0x16,0x24,0x66,
    0x2B,0xE7,0xB2,0xE2,0x54,0x7D,0xE7,0x88,0x39,0xA2,0x1B,0x81,0x3E,0x02,0xD3,0x39,
    0xD8,0x97,0x77,0x4A,0x32,0x0C,0xD6,0x0A,0x0A,0xB3,0x04,0x9B,0xF1,0x72,0x6F,0x63,
    0xA8,0x15,0x1E,0x6C,0x37,0xE8,0x0F,0xDB,0x53,0x90,0xD6,0x29,0x5C,0xBC,0x6A,0x57,
    0x9B,0x46,0x78,0x0A,0x3E,0x24,0xEA,0x9A,0x3F,0xA1,0xD8,0x3F,0xF5,0xDB,0x6E,0xA8,
    0x6C,0x82,0xB5,0xDD,0x99,0x38,0xEC,0x92,0x56,0x94,0xA6,0xC5,0x73,0x26,0xD1,0xAE,
    0x08,0xB2,0xC6,0x52,0xE7,0x8E,0x76,0x4B,0x89,0xB8,0x54,0x0F,0x6E,0xE0,0xD9,0x42,
    0xDB,0x2A,0x65,0x87,0x46,0x14,0xBB,0x96,0xB8,0x57,0xBB,0x51,0xE6,0x84,0x13,0xF7,
    0x0D,0xA1,0xB6,0x89,0xAC,0x7C,0xD1,0x21,0x74,0xAB,0x02,0x03,0x01,0x00,0x01,0xA3,
    0x81,0xA6,0x30,0x81,0xA3,0x30,0x1D,0x06,0x03,0x55,0x1D,0x0E,0x04,0x16,0x04,0x14,
    0x2C,0xC5,0x6D,0x52,0xDD,0x31,0xEF,0x8C,0xEC,0x08,0x81,0xED,0xDF,0xDC,0xCA,0x43,
    0x00,0x45,0x01,0xD0,0x30,0x0F,0x06,0x03,0x55,0x1D,0x13,0x01,0x01,0xFF,0x04,0x05,
    0x30,0x03,0x01,0x01,0xFF,0x30,0x1F,0x06,0x03,0x55,0x1D,0x23,0x04,0x18,0x30,0x16,
    0x80,0x14,0x2B,0xD0,0x69,0x47,0x94,0x76,0x09,0xFE,0xF4,0x6B,0x8D,0x2E,0x40,0xA6,
    0xF7,0x47,0x4D,0x7F,0x08,0x5E,0x30,0x2E,0x06,0x03,0x55,0x1D,0x1F,0x04,0x27,0x30,
    0x25,0x30,0x23,0xA0,0x21,0xA0,0x1F,0x86,0x1D,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,
    0x63,0x72,0x6C,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x2F,0x72,0x6F,
    0x6F,0x74,0x2E,0x63,0x72,0x6C,0x30,0x0E,0x06,0x03,0x55,0x1D,0x0F,0x01,0x01,0xFF,
    0x04,0x04,0x03,0x02,0x01,0x06,0x30,0x10,0x06,0x0A,0x2A,0x86,0x48,0x86,0xF7,0x63,
    0x64,0x06,0x02,0x0C,0x04,0x02,0x05,0x00,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,
    0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00,0x03,0x82,0x01,0x01,0x00,0x23,0xF1,0x06,0x7E,
    0x50,0x41,0x81,0xA2,0x5E,0xD3,0x70,0xA4,0x49,0x91,0xAF,0xD8,0xCC,0x67,0x8C,0xA1,
    0x25,0x7D,0xC4,0x9A,0x93,0x39,0x2F,0xD8,0x69,0xFB,0x1B,0x41,0x5B,0x44,0xD7,0xD9,
    0x6B,0xCB,0x3B,0x25,0x09,0x1A,0xF2,0xF4,0xE3,0xC7,0x9C,0xE8,0xB0,0x5B,0xF0,0xDF,
    0xDD,0x22,0x25,0x11,0x15,0x93,0xB9,0x49,0x5E,0xDA,0x0C,0x66,0x7A,0x5E,0xD7,0x6F,
    0xF0,0x63,0xD4,0x65,0x8C,0xC4,0x7A,0x54,0x7D,0x56,0x4F,0x65,0x9A,0xFD,0xDA,0xC4,
    0xB2,0xC8,0xB0,0xB8,0xA1,0xCB,0x7D,0xE0,0x47,0xA8,0x40,0x15,0xB8,0x16,0x19,0xED,
    0x5B,0x61,0x8E,0xDF,0xAA,0xD0,0xCD,0xD2,0x3A,0xC0,0x7E,0x3A,0x9F,0x22,0x4E,0xDF,
    0xDF,0xF4,0x4E,0x1A,0xCD,0x93,0xFF,0xD0,0xF0,0x45,0x55,0x64,0x33,0x3E,0xD4,0xE5,
    0xDA,0x68,0xA0,0x13,0x8A,0x76,0x30,0x27,0xD4,0xBF,0xF8,0x1E,0x76,0xF6,0xF9,0xC3,
    0x00,0xEF,0xB1,0x83,0xEA,0x53,0x6D,0x5C,0x35,0xC7,0x0D,0x07,0x01,0xBA,0xF8,0x61,
    0xB9,0xFE,0xC5,0x9A,0x6B,0x43,0x61,0x81,0x03,0xEB,0xBA,0x5F,0x70,0x9D,0xE8,0x6F,
    0x94,0x24,0x4B,0xDC,0xCE,0x92,0xA8,0x2E,0xA2,0x35,0x3C,0xE3,0x49,0xE0,0x16,0x77,
    0xA2,0xDC,0x6B,0xB9,0x8D,0x18,0x42,0xB9,0x36,0x96,0x43,0x32,0xC6,0xCB,0x76,0x99,
    0x35,0x36,0xD8,0x56,0xC6,0x98,0x5D,0xC3,0x6F,0xA5,0x7E,0x95,0xC2,0xD5,0x7A,0x0A,
    0x02,0x20,0x66,0x78,0x92,0xF2,0x67,0xA4,0x23,0x0D,0xE8,0x09,0xBD,0xCC,0x21,0x31,
    0x10,0xA0,0xBD,0xBE,0xB5,0xDD,0x4C,0xDD,0x46,0x03,0x99,0x99,
};

/* subject:/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA */
/* issuer :/C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA */
uint8_t _AppleRootCA[1215]={
    0x30,0x82,0x04,0xBB,0x30,0x82,0x03,0xA3,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x02,
    0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,0x05,0x00,0x30,
    0x62,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x13,
    0x30,0x11,0x06,0x03,0x55,0x04,0x0A,0x13,0x0A,0x41,0x70,0x70,0x6C,0x65,0x20,0x49,
    0x6E,0x63,0x2E,0x31,0x26,0x30,0x24,0x06,0x03,0x55,0x04,0x0B,0x13,0x1D,0x41,0x70,
    0x70,0x6C,0x65,0x20,0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x69,0x6F,
    0x6E,0x20,0x41,0x75,0x74,0x68,0x6F,0x72,0x69,0x74,0x79,0x31,0x16,0x30,0x14,0x06,
    0x03,0x55,0x04,0x03,0x13,0x0D,0x41,0x70,0x70,0x6C,0x65,0x20,0x52,0x6F,0x6F,0x74,
    0x20,0x43,0x41,0x30,0x1E,0x17,0x0D,0x30,0x36,0x30,0x34,0x32,0x35,0x32,0x31,0x34,
    0x30,0x33,0x36,0x5A,0x17,0x0D,0x33,0x35,0x30,0x32,0x30,0x39,0x32,0x31,0x34,0x30,
    0x33,0x36,0x5A,0x30,0x62,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,
    0x55,0x53,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x0A,0x13,0x0A,0x41,0x70,0x70,
    0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x31,0x26,0x30,0x24,0x06,0x03,0x55,0x04,0x0B,
    0x13,0x1D,0x41,0x70,0x70,0x6C,0x65,0x20,0x43,0x65,0x72,0x74,0x69,0x66,0x69,0x63,
    0x61,0x74,0x69,0x6F,0x6E,0x20,0x41,0x75,0x74,0x68,0x6F,0x72,0x69,0x74,0x79,0x31,
    0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x03,0x13,0x0D,0x41,0x70,0x70,0x6C,0x65,0x20,
    0x52,0x6F,0x6F,0x74,0x20,0x43,0x41,0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,0x2A,
    0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,0x30,
    0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00,0xE4,0x91,0xA9,0x09,0x1F,0x91,0xDB,0x1E,
    0x47,0x50,0xEB,0x05,0xED,0x5E,0x79,0x84,0x2D,0xEB,0x36,0xA2,0x57,0x4C,0x55,0xEC,
    0x8B,0x19,0x89,0xDE,0xF9,0x4B,0x6C,0xF5,0x07,0xAB,0x22,0x30,0x02,0xE8,0x18,0x3E,
    0xF8,0x50,0x09,0xD3,0x7F,0x41,0xA8,0x98,0xF9,0xD1,0xCA,0x66,0x9C,0x24,0x6B,0x11,
    0xD0,0xA3,0xBB,0xE4,0x1B,0x2A,0xC3,0x1F,0x95,0x9E,0x7A,0x0C,0xA4,0x47,0x8B,0x5B,
    0xD4,0x16,0x37,0x33,0xCB,0xC4,0x0F,0x4D,0xCE,0x14,0x69,0xD1,0xC9,0x19,0x72,0xF5,
    0x5D,0x0E,0xD5,0x7F,0x5F,0x9B,0xF2,0x25,0x03,0xBA,0x55,0x8F,0x4D,0x5D,0x0D,0xF1,
    0x64,0x35,0x23,0x15,0x4B,0x15,0x59,0x1D,0xB3,0x94,0xF7,0xF6,0x9C,0x9E,0xCF,0x50,
    0xBA,0xC1,0x58,0x50,0x67,0x8F,0x08,0xB4,0x20,0xF7,0xCB,0xAC,0x2C,0x20,0x6F,0x70,
    0xB6,0x3F,0x01,0x30,0x8C,0xB7,0x43,0xCF,0x0F,0x9D,0x3D,0xF3,0x2B,0x49,0x28,0x1A,
    0xC8,0xFE,0xCE,0xB5,0xB9,0x0E,0xD9,0x5E,0x1C,0xD6,0xCB,0x3D,0xB5,0x3A,0xAD,0xF4,
    0x0F,0x0E,0x00,0x92,0x0B,0xB1,0x21,0x16,0x2E,0x74,0xD5,0x3C,0x0D,0xDB,0x62,0x16,
    0xAB,0xA3,0x71,0x92,0x47,0x53,0x55,0xC1,0xAF,0x2F,0x41,0xB3,0xF8,0xFB,0xE3,0x70,
    0xCD,0xE6,0xA3,0x4C,0x45,0x7E,0x1F,0x4C,0x6B,0x50,0x96,0x41,0x89,0xC4,0x74,0x62,
    0x0B,0x10,0x83,0x41,0x87,0x33,0x8A,0x81,0xB1,0x30,0x58,0xEC,0x5A,0x04,0x32,0x8C,
    0x68,0xB3,0x8F,0x1D,0xDE,0x65,0x73,0xFF,0x67,0x5E,0x65,0xBC,0x49,0xD8,0x76,0x9F,
    0x33,0x14,0x65,0xA1,0x77,0x94,0xC9,0x2D,0x02,0x03,0x01,0x00,0x01,0xA3,0x82,0x01,
    0x7A,0x30,0x82,0x01,0x76,0x30,0x0E,0x06,0x03,0x55,0x1D,0x0F,0x01,0x01,0xFF,0x04,
    0x04,0x03,0x02,0x01,0x06,0x30,0x0F,0x06,0x03,0x55,0x1D,0x13,0x01,0x01,0xFF,0x04,
    0x05,0x30,0x03,0x01,0x01,0xFF,0x30,0x1D,0x06,0x03,0x55,0x1D,0x0E,0x04,0x16,0x04,
    0x14,0x2B,0xD0,0x69,0x47,0x94,0x76,0x09,0xFE,0xF4,0x6B,0x8D,0x2E,0x40,0xA6,0xF7,
    0x47,0x4D,0x7F,0x08,0x5E,0x30,0x1F,0x06,0x03,0x55,0x1D,0x23,0x04,0x18,0x30,0x16,
    0x80,0x14,0x2B,0xD0,0x69,0x47,0x94,0x76,0x09,0xFE,0xF4,0x6B,0x8D,0x2E,0x40,0xA6,
    0xF7,0x47,0x4D,0x7F,0x08,0x5E,0x30,0x82,0x01,0x11,0x06,0x03,0x55,0x1D,0x20,0x04,
    0x82,0x01,0x08,0x30,0x82,0x01,0x04,0x30,0x82,0x01,0x00,0x06,0x09,0x2A,0x86,0x48,
    0x86,0xF7,0x63,0x64,0x05,0x01,0x30,0x81,0xF2,0x30,0x2A,0x06,0x08,0x2B,0x06,0x01,
    0x05,0x05,0x07,0x02,0x01,0x16,0x1E,0x68,0x74,0x74,0x70,0x73,0x3A,0x2F,0x2F,0x77,
    0x77,0x77,0x2E,0x61,0x70,0x70,0x6C,0x65,0x2E,0x63,0x6F,0x6D,0x2F,0x61,0x70,0x70,
    0x6C,0x65,0x63,0x61,0x2F,0x30,0x81,0xC3,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,
    0x02,0x02,0x30,0x81,0xB6,0x1A,0x81,0xB3,0x52,0x65,0x6C,0x69,0x61,0x6E,0x63,0x65,
    0x20,0x6F,0x6E,0x20,0x74,0x68,0x69,0x73,0x20,0x63,0x65,0x72,0x74,0x69,0x66,0x69,
    0x63,0x61,0x74,0x65,0x20,0x62,0x79,0x20,0x61,0x6E,0x79,0x20,0x70,0x61,0x72,0x74,
    0x79,0x20,0x61,0x73,0x73,0x75,0x6D,0x65,0x73,0x20,0x61,0x63,0x63,0x65,0x70,0x74,
    0x61,0x6E,0x63,0x65,0x20,0x6F,0x66,0x20,0x74,0x68,0x65,0x20,0x74,0x68,0x65,0x6E,
    0x20,0x61,0x70,0x70,0x6C,0x69,0x63,0x61,0x62,0x6C,0x65,0x20,0x73,0x74,0x61,0x6E,
    0x64,0x61,0x72,0x64,0x20,0x74,0x65,0x72,0x6D,0x73,0x20,0x61,0x6E,0x64,0x20,0x63,
    0x6F,0x6E,0x64,0x69,0x74,0x69,0x6F,0x6E,0x73,0x20,0x6F,0x66,0x20,0x75,0x73,0x65,
    0x2C,0x20,0x63,0x65,0x72,0x74,0x69,0x66,0x69,0x63,0x61,0x74,0x65,0x20,0x70,0x6F,
    0x6C,0x69,0x63,0x79,0x20,0x61,0x6E,0x64,0x20,0x63,0x65,0x72,0x74,0x69,0x66,0x69,
    0x63,0x61,0x74,0x69,0x6F,0x6E,0x20,0x70,0x72,0x61,0x63,0x74,0x69,0x63,0x65,0x20,
    0x73,0x74,0x61,0x74,0x65,0x6D,0x65,0x6E,0x74,0x73,0x2E,0x30,0x0D,0x06,0x09,0x2A,
    0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,0x05,0x00,0x03,0x82,0x01,0x01,0x00,0x5C,
    0x36,0x99,0x4C,0x2D,0x78,0xB7,0xED,0x8C,0x9B,0xDC,0xF3,0x77,0x9B,0xF2,0x76,0xD2,
    0x77,0x30,0x4F,0xC1,0x1F,0x85,0x83,0x85,0x1B,0x99,0x3D,0x47,0x37,0xF2,0xA9,0x9B,
    0x40,0x8E,0x2C,0xD4,0xB1,0x90,0x12,0xD8,0xBE,0xF4,0x73,0x9B,0xEE,0xD2,0x64,0x0F,
    0xCB,0x79,0x4F,0x34,0xD8,0xA2,0x3E,0xF9,0x78,0xFF,0x6B,0xC8,0x07,0xEC,0x7D,0x39,
    0x83,0x8B,0x53,0x20,0xD3,0x38,0xC4,0xB1,0xBF,0x9A,0x4F,0x0A,0x6B,0xFF,0x2B,0xFC,
    0x59,0xA7,0x05,0x09,0x7C,0x17,0x40,0x56,0x11,0x1E,0x74,0xD3,0xB7,0x8B,0x23,0x3B,
    0x47,0xA3,0xD5,0x6F,0x24,0xE2,0xEB,0xD1,0xB7,0x70,0xDF,0x0F,0x45,0xE1,0x27,0xCA,
    0xF1,0x6D,0x78,0xED,0xE7,0xB5,0x17,0x17,0xA8,0xDC,0x7E,0x22,0x35,0xCA,0x25,0xD5,
    0xD9,0x0F,0xD6,0x6B,0xD4,0xA2,0x24,0x23,0x11,0xF7,0xA1,0xAC,0x8F,0x73,0x81,0x60,
    0xC6,0x1B,0x5B,0x09,0x2F,0x92,0xB2,0xF8,0x44,0x48,0xF0,0x60,0x38,0x9E,0x15,0xF5,
    0x3D,0x26,0x67,0x20,0x8A,0x33,0x6A,0xF7,0x0D,0x82,0xCF,0xDE,0xEB,0xA3,0x2F,0xF9,
    0x53,0x6A,0x5B,0x64,0xC0,0x63,0x33,0x77,0xF7,0x3A,0x07,0x2C,0x56,0xEB,0xDA,0x0F,
    0x21,0x0E,0xDA,0xBA,0x73,0x19,0x4F,0xB5,0xD9,0x36,0x7F,0xC1,0x87,0x55,0xD9,0xA7,
    0x99,0xB9,0x32,0x42,0xFB,0xD8,0xD5,0x71,0x9E,0x7E,0xA1,0x52,0xB7,0x1B,0xBD,0x93,
    0x42,0x24,0x12,0x2A,0xC7,0x0F,0x1D,0xB6,0x4D,0x9C,0x5E,0x63,0xC8,0x4B,0x80,0x17,
    0x50,0xAA,0x8A,0xD5,0xDA,0xE4,0xFC,0xD0,0x09,0x07,0x37,0xB0,0x75,0x75,0x21,
};


#endif /* _SECURITY_SI_32_SECTRUST_PINNING_REQUIRED_H_ */
