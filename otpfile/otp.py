import os
import math
import random
import struct
import hashlib
import secrets
import dataclasses



class OTPError(Exception):
    pass


@dataclasses.dataclass
class Header:
    header: bytes
    group_id: bytes
    file_hash: bytes
    file_name: bytes
    file_count: int
    segment_count: int


@dataclasses.dataclass
class Segment:
    signatures: bytes
    body: bytes
    nonce: bytes
    signature: bytes = None


class OTP:
    HEADER = b'OTP1'
    SIGN_SIZE = 32
    SEGMENT_BODY_MAX_SIZE = 128 * 1024
    FILE_MAX_SIZE = 4 * 1024 * 1024 * 1024

    @classmethod
    def _get_hash(cls, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @classmethod
    def encrypt_file(
            cls,
            file_path: str,
            output_folder: str,
            file_count: int = 2,
            nonce_size: int = 32,
    ):
        if not file_path:
            raise OTPError(f'需要合法文件路径')
        if not os.path.isfile(file_path):
            raise OTPError(f'找不到文件{file_path}')
        file_size = os.path.getsize(file_path)
        if file_size > cls.FILE_MAX_SIZE:
            raise OTPError(f'file_path被加密文件过大超过限制')
        if file_size <= 32:
            raise OTPError(f'被加密文件不能小于32字节')
        if 2 > file_count or 100 < file_count:
            raise OTPError(f'file_count分割的文件数量超过限制')
        if 32 > nonce_size or 1024 < nonce_size:
            raise OTPError(f'nonce_size超过限制')
        file_name = os.path.basename(file_path)
        file_name_bytes = file_name.encode('utf8')
        if len(file_name_bytes)  < 1 or len(file_name_bytes) > 1024:
            raise OTPError(f'被加密文件名长度超过限制')
        return cls._encrypt(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            output_folder=output_folder,
            file_count=file_count,
            nonce_size=nonce_size,
        )

    @classmethod
    def _encrypt(
            cls,
            file_path: str,
            file_name: str,
            file_size: int,
            output_folder: str,
            file_count: int,
            nonce_size: int,
    ):
        segment_count = math.ceil(file_size / cls.SEGMENT_BODY_MAX_SIZE)
        header = Header(
            header=cls.HEADER,
            group_id=secrets.token_bytes(64),
            file_hash=secrets.token_bytes(cls.SIGN_SIZE),
            file_name=file_name.encode('utf8'),
            file_count=file_count,
            segment_count=segment_count,
        )
        write_files = list()
        with open(file_path, 'rb') as f:
            try:
                for idx in range(file_count):
                    f_write_path = os.path.join(output_folder, f'{file_name}_{idx:02d}.otp')
                    if os.path.exists(f_write_path) and os.path.getsize(f_write_path) > 0:
                        raise OTPError(f'分割的文件{f_write_path}已存在')
                    f_wb = open(f_write_path, 'wb')
                    write_files.append(f_wb)
                for f_wb in write_files:
                    cls._write_header(f_wb, header)
                rotated_hash = header.group_id
                while plaintext := f.read(cls.SEGMENT_BODY_MAX_SIZE):
                    rotated_hash = cls._get_hash(rotated_hash + plaintext)
                    for f_wb, seg in zip(write_files, cls._build_segment(
                        plaintext=plaintext,
                        group_id=header.group_id,
                        file_count=file_count,
                        nonce_size=nonce_size,
                    )):
                        cls._write_segment(f_wb, file_count, seg)
                header.file_hash = rotated_hash
                for f_wb in write_files:
                    cls._write_header(f_wb, header)
            finally:
                for f_wb in write_files:
                    f_wb.close()

    @classmethod
    def _write_header(
            cls,
            f_wb,
            header: Header,
    ):
        fmt = f'!4s64s{cls.SIGN_SIZE}sI{len(header.file_name)}sII'
        seq = (
            header.header, header.group_id, header.file_hash, len(header.file_name), header.file_name,
            header.file_count, header.segment_count,
        )
        f_wb.seek(0, 0)
        f_wb.write(struct.pack(fmt, *seq))

    @classmethod
    def _write_segment(
            cls,
            f_wb,
            file_count: int,
            segment: Segment,
    ):
        fmt = f'!{file_count * cls.SIGN_SIZE}sI{len(segment.body)}sI{len(segment.nonce)}s{cls.SIGN_SIZE}s'
        seq = (
            segment.signatures,
            len(segment.body), segment.body,
            len(segment.nonce), segment.nonce,
            segment.signature,
        )
        f_wb.write(struct.pack(fmt, *seq))


    @classmethod
    def _build_segment(
            cls,
            plaintext: bytes,
            group_id: bytes,
            file_count: int,
            nonce_size: int,
    ):
        n = len(plaintext)
        m = file_count
        last_turn = plaintext
        raw_ciphertext = None
        segs: list[Segment] = list()
        assert m > 1
        for _ in range(m - 1):
            key = secrets.token_bytes(n)
            raw_ciphertext = ((int.from_bytes(last_turn)) ^ int.from_bytes(key)).to_bytes(n)
            last_turn = raw_ciphertext
            segs.append(
                Segment(
                    signatures=secrets.token_bytes(cls.SIGN_SIZE * m),
                    body=key,
                    nonce=secrets.token_bytes(nonce_size),
                    signature=secrets.token_bytes(cls.SIGN_SIZE),
                )
            )
        segs.append(
            Segment(
                signatures=secrets.token_bytes(cls.SIGN_SIZE * m),
                body=raw_ciphertext,
                nonce=secrets.token_bytes(nonce_size),
                signature=secrets.token_bytes(cls.SIGN_SIZE),
            )
        )
        # fill signatures
        signatures = list()
        for seg in segs:
            signature = cls._get_hash(group_id + seg.body + seg.nonce)
            seg.signature = signature
            signatures.append(signature)
        key_rng = random.Random()
        key_rng.shuffle(signatures)
        signatures = b''.join(signatures)
        for seg in segs:
            seg.signatures = signatures

        key_rng.shuffle(segs)
        return segs

    @classmethod
    def decrypt_file(
            cls,
            files: list[str],
            output_folder: str,
    ):
        files = list(set(files))
        if not os.path.exists(output_folder) or not os.path.isdir(output_folder):
            raise OTPError(f'输出目录{output_folder}不合法')


        size_set = set()
        group_id_set = set()
        file_hash_set = set()
        file_name_set = set()
        segment_count_set = set()

        read_files = list()
        header_files = list()
        f_write = None
        try:
            for file in files:
                if not os.path.isfile(file):
                    raise OTPError(f'文件{file}不存在')
                size_set.add(os.path.getsize(file))
                if len(size_set) > 1:
                    raise OTPError(f'文件的大小不一致')
                read_files.append((file, open(file, 'rb'), ))
            for file_path, fd in read_files:
                header = fd.read(4)
                if header != cls.HEADER:
                    raise OTPError(f'文件{file_path}头格式错误')

                group_id = fd.read(64)
                file_hash = fd.read(cls.SIGN_SIZE)
                file_name_size = struct.unpack('!I', fd.read(4))[0]
                if file_name_size < 1 or file_name_size > 1024:
                    raise OTPError(f'在{file_path}, 还原文件名称长度超过限制')
                file_name = fd.read(file_name_size)
                file_count = struct.unpack('!I', fd.read(4))[0]
                if 2 > file_count or 100 < file_count:
                    raise OTPError(f'在{file_path}, file_count分割的文件数量超过限制')
                segment_count = struct.unpack('!I', fd.read(4))[0]
                if math.ceil(cls.FILE_MAX_SIZE / cls.SEGMENT_BODY_MAX_SIZE) < segment_count:
                    raise OTPError(f'在{file_path}, 段数量超过限制')
                group_id_set.add(group_id)
                file_hash_set.add(file_hash)
                file_name_set.add(file_name)
                segment_count_set.add(segment_count)

                if len(group_id_set) > 1:
                    raise OTPError(f'文件之间有冲突的groupID: {group_id_set}')
                if len(file_hash_set) > 1:
                    raise OTPError(f'文件之间有冲的突原文件签名: {file_hash_set}')
                if len(file_name_set) > 1:
                    raise OTPError(f'文件之间有冲突的还原文件名称: {file_name_set}')
                if len(segment_count_set) > 1:
                    raise OTPError(f'文件之间有冲突的段数量: {segment_count_set}')

                header = Header(
                    header=header,
                    group_id=group_id,
                    file_hash=file_hash,
                    file_name=file_name,
                    file_count=file_count,
                    segment_count=segment_count,
                )
                header_files.append((header, file_path, fd, ))
            group_id = group_id_set.pop()
            rotated_hash = group_id
            file_name = file_name_set.pop().decode('utf8')
            full_path = os.path.join(output_folder, file_name)
            if os.path.exists(full_path) and os.path.getsize(full_path) > 0:
                raise OTPError(f'文件{full_path}已存在, 不能保存解密文件')
            f_write = open(full_path, 'wb')
            for _ in range(segment_count_set.pop()):
                signatures_set = set()
                segments: list[Segment] = list()
                for header, file_path, fd in header_files:
                    segment = cls._read_segment(
                        file_path=file_path,
                        fd=fd,
                        group_id=header.group_id,
                        file_count=header.file_count,
                    )
                    signatures_set.add(segment.signatures)
                    if len(signatures_set) > 1:
                        raise OTPError(f'文件之间的段有冲突的公共签名')
                    segments.append(segment)
                signatures = signatures_set.pop()
                signatures = set(signatures[i:i + cls.SIGN_SIZE] for i in range(0, len(signatures), cls.SIGN_SIZE))
                if set(seg.signature for seg in segments) != signatures:
                    raise OTPError(f'文件之间的段的公共签名不能被所有文件覆盖, 检查是否缺失了部分文件')

                unique_segments = list({seg.signature: seg for seg in segments}.values())
                last_turn = unique_segments[0].body
                for seg in unique_segments[1:]:
                    raw_ciphertext = ((int.from_bytes(last_turn)) ^ int.from_bytes(seg.body)).to_bytes(len(last_turn))
                    last_turn = raw_ciphertext
                f_write.write(last_turn)
                rotated_hash = cls._get_hash(rotated_hash + last_turn)
            if rotated_hash != file_hash_set.pop():
                raise OTPError(f'最终还原的文件签名与预期不符')
        finally:
            for _, f in read_files:
                f.close()
            if f_write:
                f_write.close()

    @classmethod
    def _read_segment(
            cls,
            file_path: str,
            fd,
            group_id: bytes,
            file_count: int,
    ):
        signatures = fd.read(cls.SIGN_SIZE * file_count)
        body_size = struct.unpack('!I', fd.read(4))[0]
        if body_size < 1 or body_size > cls.SEGMENT_BODY_MAX_SIZE:
            raise OTPError(f'在文件{file_path}, 段内数据长度超过限制')
        body = fd.read(body_size)
        nonce_size = struct.unpack('!I', fd.read(4))[0]
        if 32 > nonce_size or 1024 < nonce_size:
            raise OTPError(f'在文件{file_path}, 段内nonce长度超过限制')
        nonce = fd.read(nonce_size)
        signature = fd.read(cls.SIGN_SIZE)
        if not cls._get_hash(group_id + body + nonce) == signature:
            raise OTPError(f'在文件{file_path}, 校验段内签名失败')
        return Segment(
            signatures=signatures,
            body=body,
            nonce=nonce,
            signature=signature,
        )


__all__ = ['OTPError', 'OTP', ]
