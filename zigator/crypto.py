# Copyright (C) 2020 Dimitrios-Georgios Akestoridis
#
# This file is part of Zigator.
#
# Zigator is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# Zigator is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Zigator. If not, see <https://www.gnu.org/licenses/>.

"""
Cryptographic functions for the zigator package
"""

from Cryptodome.Cipher import AES


# The block size is measured in bytes
ZIGBEE_BLOCK_SIZE = 16


def zigbee_mmo_hash(message):
    # Initial value for the digest of the message
    digest = bytearray.fromhex("00000000000000000000000000000000")

    # Pad the message
    padding = bytearray([0x80])
    while (len(message) + len(padding) + 2) % ZIGBEE_BLOCK_SIZE != 0:
        padding.append(0x00)
    padding.append((8*len(message)) >> 8)
    padding.append((8*len(message)) & 0xff)
    padded_message = message + padding

    # Sanity check
    if len(padded_message) % ZIGBEE_BLOCK_SIZE != 0:
        raise ValueError("The length of the padded message ({}) is "
                         "not a multiple of the block size ({})"
                         "".format(len(padded_message), ZIGBEE_BLOCK_SIZE))

    # Compute the digest of the message
    plaintext = bytearray()
    for i in range(len(padded_message)):
        plaintext.append(padded_message[i])
        if len(plaintext) == ZIGBEE_BLOCK_SIZE:
            cipher = AES.new(key=digest, mode=AES.MODE_ECB)
            ciphertext = cipher.encrypt(plaintext)
            digest = bytearray(ciphertext)
            for j in range(ZIGBEE_BLOCK_SIZE):
                digest[j] ^= plaintext[j]
            plaintext = bytearray()

    return bytes(digest)


def zigbee_hmac(message, key):
    # HMAC uses the following inner and outer pads
    inner_pad = 0x36
    outer_pad = 0x5c

    # Hash the key if it is longer than the block size
    if len(key) > ZIGBEE_BLOCK_SIZE:
        key = bytearray(zigbee_mmo_hash(key))
    else:
        key = bytearray(key)

    # Pad the key with zeros if it is shorter than the block size
    for _ in range(ZIGBEE_BLOCK_SIZE - len(key)):
        key.append(0x00)

    # Sanity check
    if len(key) != ZIGBEE_BLOCK_SIZE:
        raise ValueError("The length of the key ({}) is "
                         "not equal to the block size ({})"
                         "".format(len(key), ZIGBEE_BLOCK_SIZE))

    # Compute the inner and outer keys
    inner_key = bytearray(key)
    outer_key = bytearray(key)
    for i in range(ZIGBEE_BLOCK_SIZE):
        inner_key[i] ^= inner_pad
        outer_key[i] ^= outer_pad

    return zigbee_mmo_hash(outer_key + zigbee_mmo_hash(inner_key + message))


def decrypt_payload(key, source_addr, frame_counter, security_control,
                    header, key_seqnum, encrypted_payload, mic):
    le_srcaddr = source_addr.to_bytes(8, byteorder="little")
    le_framecounter = frame_counter.to_bytes(4, byteorder="little")
    fixed_securitycontrol = (security_control & 0b11111000) | 0b101

    nonce = bytearray(le_srcaddr)
    nonce.extend(le_framecounter)
    nonce.append(fixed_securitycontrol)

    unencrypted_data = bytearray(header)
    unencrypted_data.append(fixed_securitycontrol)
    unencrypted_data.extend(le_framecounter)
    if security_control & 0b00100000:
        unencrypted_data.extend(le_srcaddr)
    if key_seqnum is not None:
        unencrypted_data.append(key_seqnum)

    cipher = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(unencrypted_data)
    decrypted_payload = cipher.decrypt(encrypted_payload)
    try:
        cipher.verify(mic)
        return decrypted_payload, True
    except ValueError:
        return decrypted_payload, False
