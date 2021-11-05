# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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
Cryptographic module for the zigator package
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
        raise ValueError(
            "The length of the padded message "
            + "({}) is not a multiple of ".format(len(padded_message))
            + "the block size ({})".format(ZIGBEE_BLOCK_SIZE),
        )

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
        raise ValueError(
            "The length of the key ({}) ".format(len(key))
            + "is not equal to the block size ({})".format(ZIGBEE_BLOCK_SIZE),
        )

    # Compute the inner and outer keys
    inner_key = bytearray(key)
    outer_key = bytearray(key)
    for i in range(ZIGBEE_BLOCK_SIZE):
        inner_key[i] ^= inner_pad
        outer_key[i] ^= outer_pad

    return zigbee_mmo_hash(outer_key + zigbee_mmo_hash(inner_key + message))


def zigbee_enc_mic(
    key,
    source_addr,
    frame_counter,
    sec_control,
    header,
    key_seqnum,
    dec_payload,
):
    # The fields of the nonce are in little-endian byte order
    le_srcaddr = source_addr.to_bytes(8, byteorder="little")
    le_framecounter = frame_counter.to_bytes(4, byteorder="little")

    # Zigbee devices overwrite the security level field of their packets
    # with zeros after securing them and before transmitting them.
    # We have to restore the security level field in order to
    # to successfully encrypt and authenticate Zigbee packets.
    # The default security level of Zigbee networks utilizes
    # AES-128 in CCM mode with 32-bit message integrity codes.
    fixed_sec_control = (sec_control & 0b11111000) | 0b101

    # Construct the nonce
    nonce = bytearray(le_srcaddr)
    nonce.extend(le_framecounter)
    nonce.append(fixed_sec_control)

    # Gather the unencrypted data that, along with the encrypted data,
    # will be protected by the message integrity code
    auth_data = bytearray(header)
    auth_data.append(fixed_sec_control)
    auth_data.extend(le_framecounter)
    if sec_control & 0b00100000:
        auth_data.extend(le_srcaddr)
    if key_seqnum is not None:
        auth_data.append(key_seqnum)

    # Return the encrypted payload and the message integrity code
    cipher = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(auth_data)
    enc_payload, mic = cipher.encrypt_and_digest(dec_payload)
    return enc_payload, mic


def zigbee_dec_ver(
    key,
    source_addr,
    frame_counter,
    sec_control,
    header,
    key_seqnum,
    enc_payload,
    mic,
):
    # The fields of the nonce are in little-endian byte order
    le_srcaddr = source_addr.to_bytes(8, byteorder="little")
    le_framecounter = frame_counter.to_bytes(4, byteorder="little")

    # Zigbee devices overwrite the security level field of their packets
    # with zeros after securing them and before transmitting them.
    # We have to restore the security level field in order to
    # to successfully decrypt and verify Zigbee packets.
    # The default security level of Zigbee networks utilizes
    # AES-128 in CCM mode with 32-bit message integrity codes.
    fixed_sec_control = (sec_control & 0b11111000) | 0b101

    # Sanity check
    if len(mic) != 4:
        raise ValueError(
            "Expected a 32-bit message integrity code, "
            + "not a {}-bit one".format(8*len(mic)),
        )

    # Construct the nonce
    nonce = bytearray(le_srcaddr)
    nonce.extend(le_framecounter)
    nonce.append(fixed_sec_control)

    # Gather the unencrypted data that, along with the encrypted data,
    # are protected by the message integrity code
    auth_data = bytearray(header)
    auth_data.append(fixed_sec_control)
    auth_data.extend(le_framecounter)
    if sec_control & 0b00100000:
        auth_data.extend(le_srcaddr)
    if key_seqnum is not None:
        auth_data.append(key_seqnum)

    # Return the decrypted payload and a Boolean value that indicates
    # whether the verification process was successful or not
    cipher = AES.new(key=key, mode=AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(auth_data)
    dec_payload = cipher.decrypt(enc_payload)
    try:
        cipher.verify(mic)
        return dec_payload, True
    except ValueError:
        return dec_payload, False
