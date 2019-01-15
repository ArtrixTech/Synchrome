#! /user/bin/env python3
# -*-coding: utf-8 -*-
from base64 import b64decode
from functools import partial
from json import loads
from os import scandir
from os.path import basename, join, isfile
from struct import unpack
from time import clock

from Crypto.Cipher import AES
from mutagen.flac import Picture, FLAC
from mutagen.id3 import APIC
from mutagen.mp3 import MP3
from numpy import fromstring


class NCMDump:

    def __init__(self):
        self.ncm_header = b'CTENFDAM'
        self.core_key = b'hzHRAmso5kInbaxW'
        self.meta_key = b"#14ljk_!\\]&0U<'("
        self.core_cryptor = AES.new(self.core_key, AES.MODE_ECB)
        self.meta_cryptor = AES.new(self.meta_key, AES.MODE_ECB)
        self.up = partial(unpack, '<I')
        self.range_256 = list(range(256))
        self.indexes = self.range_256[1:] + [0]

    @staticmethod
    def bxor_numpy(b1, b2):
        n_b1 = fromstring(b1, dtype='uint8')
        n_b2 = fromstring(b2, dtype='uint8')
        return (n_b1 ^ n_b2).tostring()

    def aes128_ecb_decrypt(self, ciphertext):
        plaintext = self.core_cryptor.decrypt(ciphertext)
        return plaintext[:- plaintext[-1]]

    def b64_aes128_ecb_decrypt(self, ciphertext):
        plaintext = self.meta_cryptor.decrypt(b64decode(ciphertext))
        return plaintext[:- plaintext[-1]]

    def dump(self, file_path, output_path):
        with open(file_path, 'rb') as f:

            # magic header
            header = f.read(8)
            assert header == self.ncm_header

            # key data
            f.seek(2, 1)
            key_length = f.read(4)
            key_length = self.up(key_length)[0]

            key_data = f.read(key_length)
            key_data = bytes(byte ^ 0x64 for byte in key_data)
            key_data = self.aes128_ecb_decrypt(key_data)[17:]
            key_length = len(key_data)

            # key box
            key_box = bytearray(self.range_256)
            j = 0
            for i in self.range_256:
                j = (key_box[i] + j + key_data[i % key_length]) & 0xff
                key_box[i], key_box[j] = key_box[j], key_box[i]
            modify_keys = bytes(key_box[(
                key_box[i] + key_box[(key_box[i] + i) & 0xff]) & 0xff] for i in self.indexes)

            # meta data
            meta_length = f.read(4)
            meta_length = self.up(meta_length)[0]
            meta_data = f.read(meta_length)
            meta_data = bytes(byte ^ 0x63 for byte in meta_data)[22:]
            meta_data = self.b64_aes128_ecb_decrypt(meta_data).decode()[6:]
            meta_data = loads(meta_data)
            f.seek(9, 1)

            # album cover
            image_size = f.read(4)
            image_size = self.up(image_size)[0]
            image_data = f.read(image_size)

            # media data
            music_name = f'{basename(file_path).rsplit(".",maxsplit=1)[0]}.{meta_data["format"]}'
            output_path = join(output_path, music_name)
            print(music_name, end=' ··· ')
            if isfile(output_path):
                print('文件已存在')
                return
            music_data = f.read()
        l = len(music_data)
        modify_keys = modify_keys * (l // 256) + modify_keys[:l % 256]
        modified_music_data = self.bxor_numpy(modify_keys, music_data)
        with open(output_path, 'wb') as m:
            m.write(modified_music_data)
        if image_data == b'':
            print('没有封面')
        else:
            if image_data.startswith(b'\xFF\xD8\xFF\xE0'):
                mime = 'image/jpeg'
            elif image_data.startswith(b'\x89PNG\r\n\x1a\n'):
                mime = 'image/png'
            if meta_data['format'] == 'mp3':
                mp3 = MP3(output_path)
                mp3.tags.add(
                    APIC(
                        mime=mime,
                        type=3,
                        data=image_data
                    )
                )
                mp3.save(v2_version=3)
            elif meta_data['format'] == 'flac':
                flac = FLAC(output_path)
                cover = Picture()
                cover.data = image_data
                cover.type = 3
                cover.mime = mime
                cover.desc = u'cover'
                flac.add_picture(cover)
                flac.save()
        print('完成')


def walk(path):
    for entry in scandir(path):
        if entry.is_file():
            yield entry
        else:
            yield from walk(entry.path)


def search_and_dump(dir, output_dir):
    ncm_files = [entry.path for entry in walk(
        dir) if entry.name.endswith('.ncm')]
    l = len(ncm_files)
    i = 1
    st = clock()
    for file_path in ncm_files:
        print(f'{i}/{l}', end=' ')
        i += 1
        dump(file_path, output_dir)
    print(f'时间: {clock() - st:.2f}s')
