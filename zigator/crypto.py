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
