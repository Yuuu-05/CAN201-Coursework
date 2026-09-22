from socket import *
import json
import os
from os.path import join, getsize
import hashlib
import argparse
from threading import Thread
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil
import struct  # For data packaging/unpackaging

MAX_PACKET_SIZE = 20480

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

DEFAULT_TOKEN_TTL = 3600
SECRET_SUFFIX = 'kjh20)*(1'

# New feature: Resume from breakpoint
OP_STATUS = 'STATUS'
FIELD_RECEIVED_BLOCKS = 'received_blocks'
FIELD_MISSING_BLOCKS = 'missing_blocks'
FIELD_BLOCK_MD5 = 'block_md5'

logger = logging.getLogger('')

# FIX the error: read file in binary mode to compute correct MD5 for non-text data.
def get_file_md5(filename):
    m = hashlib.md5()
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()


def get_time_based_filename(ext, prefix='', t=None):
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()
    if t > 4102464500:
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))


def set_logger(logger_name):
    logger_ = logging.getLogger(logger_name)
    logger_.setLevel(logging.INFO)

    formatter = logging.Formatter(
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')

    os.makedirs(f'log/{logger_name}', exist_ok=True)
    fh = TimedRotatingFileHandler(filename=f'log/{logger_name}/log', when='D', interval=1, backupCount=1)
    fh.setFormatter(formatter)
    fh.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False
    logger_.addHandler(ch)
    logger_.addHandler(fh)
    return logger_


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', required=False, dest="ip",
                       help="Bind IP. Default bind all IPs.")
    parse.add_argument("--port", default='1379', required=False, dest="port",
                       help="Listen port. Default 1379.")
    # New token timestamp
    parse.add_argument("--token-ttl", default=None, required=False, dest="token_ttl",
                       help="Token TTL seconds. Default 3600 (or env STEP_TOKEN_TTL).")
    return parse.parse_args()


def make_packet(json_data, bin_data=None):
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        # Fix the error: Import the struct package.
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def make_response_packet(operation, status_code, data_type, status_msg, json_data, bin_data=None):
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_RESPONSE
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)


def get_tcp_packet(conn):
    bin_data = b''
    # Fix the error: Just 8 bytes of header
    while len(bin_data) < 8:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


#  （DATA / FILE）processing
def data_process(username, request_operation, json_data, connection_socket):
    global logger

    # Modification: Explicitly reject the use of STATUS in the DATA type.
    if request_operation == OP_STATUS:
        logger.error(f'<-- STATUS operation is not supported for TYPE_DATA.')
        connection_socket.send(
            make_response_packet(
                OP_STATUS,
                409,
                TYPE_DATA,
                'STATUS operation is only supported for TYPE_FILE.',
                {}
            )
        )
        return
    

    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'<-- Get data without key.')
            logger.error(f'<-- Field "key" is missing for DATA GET.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_DATA, f'Field "key" is missing for DATA GET.', {}))
            return
        logger.info(f'--> Get data {json_data[FIELD_KEY]}')
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_DATA, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            return
        try:
            with open(join('data', username, json_data[FIELD_KEY]), 'r') as fid:
                data_from_file = json.load(fid)
                logger.info(f'<-- Find the data and return to client.')
                connection_socket.send(
                    make_response_packet(OP_GET, 200, TYPE_DATA, f'OK', data_from_file))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')

    if request_operation == OP_SAVE:
        key = str(uuid.uuid4())
        if FIELD_KEY in json_data.keys():
            key = json_data[FIELD_KEY]
        logger.info(f'--> Save data with key "{key}"')
        if os.path.exists(join('data', username, key)) is True:
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_DATA, f'This key "{key}" is existing.', {}))
            return
        try:
            with open(join('data', username, key), 'w') as fid:
                json.dump(json_data, fid)
                # Fix the error：logger.error(f'<-- Data is saved with key "{key}"')
                logger.info(f'<-- Data is saved with key "{key}"')
                connection_socket.send(
                    make_response_packet(OP_SAVE, 200, TYPE_DATA, f'Data is saved with key "{key}"', {FIELD_KEY: key}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')

    # Fix the error: Capitalization error
    if request_operation == OP_DELETE:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Delete data without any key.')
            logger.error(f'<-- Field "key" is missing for DATA delete.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 410, TYPE_DATA, f'Field "key" is missing for DATA delete.', {}))
            return
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False:
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 404, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is not existing.',
                                     {}))
            return
        try:
            os.remove(join('data', username, json_data[FIELD_KEY]))
            # Fix the error：logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            logger.info(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 200, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is deleted.',
                                     {FIELD_KEY: json_data[FIELD_KEY]}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')


def file_process(username, request_operation, json_data, bin_data, connection_socket):
    global logger
    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Plan to download file without key.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE GET.', {}))
            return
        logger.info(f'--> Plan to download file with "key" {json_data[FIELD_KEY]}')
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is False:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            return

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is True:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE,
                                     f'The key {json_data[FIELD_KEY]} is not completely uploaded.', {}))
            return

        file_path = join('file', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        md5 = get_file_md5(file_path)
        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_SIZE: file_size,
            FIELD_TOTAL_BLOCK: total_block,
            FIELD_BLOCK_SIZE: block_size,
            FIELD_MD5: md5
        }
        # Fix the error：What should be printed is the actual number "total_block"
        logger.info(f'<-- Plan: file size {file_size}, total block number {total_block}.')
        connection_socket.send(
            make_response_packet(OP_GET, 200, TYPE_FILE, f'OK. This is the download plan.', rval))
        return

    if request_operation == OP_SAVE:
        key = str(uuid.uuid4())
        if FIELD_KEY in json_data.keys():
            key = json_data[FIELD_KEY]
        logger.info(f'--> Plan to save/upload a file with key "{key}"')
        if os.path.exists(join('file', username, key)) is True:
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_FILE, f'This "key" {key} is existing.', {}))
            return
        if FIELD_SIZE not in json_data.keys():
            logger.error(f'<-- This file "size" has to be included.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 402, TYPE_FILE, f'This file "size" has to be included', {}))
            return
        file_size = json_data[FIELD_SIZE]
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        try:
            rval = {
                FIELD_KEY: key,
                FIELD_SIZE: file_size,
                FIELD_TOTAL_BLOCK: total_block,
                FIELD_BLOCK_SIZE: block_size,
            }
            # Pre-build tmp files and logs
            with open(join('tmp', username, key), 'wb+') as fid:
                fid.seek(file_size - 1)
                fid.write(b'\0')
            fid = open(join('tmp', username, key + '.log'), 'w')
            fid.close()

            # Fix the error：logger.error(f'<-- Upload plan: key {key}, total block number {total_block}, block size {block_size}.')
            logger.info(f'<-- Upload plan: key {key}, total block number {total_block}, block size {block_size}.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 200, TYPE_FILE, f'This is the upload plan.', rval))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')


    if request_operation == OP_DELETE:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Delete file without any key.')
            logger.error(f'<-- Field "key" is missing for FILE delete.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 410, TYPE_FILE, f'Field "key" is missing for FILE delete.', {}))
            return

        key = json_data[FIELD_KEY]
        file_path = join('file', username, key)
        tmp_path = join('tmp', username, key)
        log_path = tmp_path + '.log'

        # Situation A: The final product file exists
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                # Fix the error：logger.error(f'<-- The "key" {key} is deleted.')
                logger.info(f'<-- The "key" {key} is deleted.')
                connection_socket.send(
                    make_response_packet(OP_DELETE, 200, TYPE_FILE, f'The "key" {key} is deleted.',
                                         {FIELD_KEY: key}))
            except Exception as ex:
                logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')
                connection_socket.send(
                    make_response_packet(OP_DELETE, 500, TYPE_FILE, f'Failed to delete "{key}": {str(ex)}', {}))
            return

        # Situation B: The finished product does not exist, but there is tmp (not yet fully uploaded)
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
                if os.path.exists(log_path):
                    os.remove(log_path)
                logger.error(
                    f'<-- The "key" {key} is not completely uploaded. The tmp files are deleted.')
                connection_socket.send(
                    make_response_packet(OP_DELETE, 404, TYPE_FILE,
                                         f'The "key" {key} is not completely uploaded. The tmp files are deleted.',
                                         {}))
            except Exception as ex:
                logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')
                connection_socket.send(
                    make_response_packet(OP_DELETE, 500, TYPE_FILE, f'Failed to delete tmp for "{key}": {str(ex)}', {}))
            return

        # Situation C: There are neither finished products nor tmp.
        logger.error(f'<-- The "key" {key} is not existing.')
        connection_socket.send(
            make_response_packet(OP_DELETE, 404, TYPE_FILE, f'The "key" {key} is not existing.', {}))
        return


    if request_operation == OP_UPLOAD:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Upload file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'Field "key" is missing for FILE uploading.', {}))
            return
        logger.info(f'--> Upload file/block of "key" {json_data[FIELD_KEY]}.')

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is True:
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is completely uploaded.', {}))
            return

        if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is False:
            logger.error(
                f'<-- The "key" {json_data[FIELD_KEY]} is not accepted for uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE,
                                     f'The "key" {json_data[FIELD_KEY]} is not accepted for uploading.',
                                     {}))
            return

        if FIELD_BLOCK_INDEX not in json_data.keys():
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('tmp', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 405, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            return
        if block_index == total_block - 1 and len(bin_data) != file_size - block_size * block_index:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        if block_index != total_block - 1 and len(bin_data) != block_size:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        
        # MD5 checksum
        cli_md5 = json_data.get(FIELD_BLOCK_MD5)
        if cli_md5:
            real_md5 = hashlib.md5(bin_data).hexdigest()

            if len(cli_md5) != 32 or any(c not in '0123456789abcdefABCDEF' for c in cli_md5):
                connection_socket.send(
                    make_response_packet(OP_UPLOAD, 406, TYPE_FILE, 'Block md5 format invalid.', {}))
                return
            if real_md5.lower() != cli_md5.lower():
                connection_socket.send(
                    make_response_packet(OP_UPLOAD, 406, TYPE_FILE, 'Block md5 mismatch.', {}))
                return


        with open(file_path, 'rb+') as fid:
            fid.seek(block_size * block_index)
            fid.write(bin_data)
        with open(file_path + '.log', 'a') as fid:
            fid.write(f'{block_index}\n')
        fid = open(file_path + '.log', 'r')
        lines = fid.readlines()
        fid.close()
        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_BLOCK_INDEX: block_index
        }
        if len(set(lines)) == total_block:
            md5 = get_file_md5(file_path)
            rval[FIELD_MD5] = md5
            os.remove(file_path + '.log')
            final_path = join('file', username, json_data[FIELD_KEY])
            shutil.move(file_path, final_path)
            logger.info(f'<-- File {json_data[FIELD_KEY]} uploaded completely. MD5: {md5}')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 200, TYPE_FILE,
                                     f'All blocks uploaded. File saved successfully.',
                                     {FIELD_KEY: json_data[FIELD_KEY], FIELD_MD5: md5}))
        else:
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 200, TYPE_FILE,
                                     f'The block {block_index} is uploaded.', rval))
        return
    
    # Add the OP_STATUS branch
    if request_operation == OP_STATUS:
        if FIELD_KEY not in json_data.keys():
            connection_socket.send(
                make_response_packet(OP_STATUS, 410, TYPE_FILE, 'Field "key" is missing for FILE status.', {}))
            return
    
        key = json_data[FIELD_KEY]
        tmp_path = join('tmp', username, key)
        fin_path = join('file', username, key)

        if os.path.exists(fin_path):
            file_size = getsize(fin_path)
            block_size = MAX_PACKET_SIZE
            total_block = math.ceil(file_size / block_size)
            md5 = get_file_md5(fin_path)
            rval = {
                FIELD_KEY: key,
                FIELD_SIZE: file_size,
                FIELD_TOTAL_BLOCK: total_block,
                FIELD_BLOCK_SIZE: block_size,
                FIELD_MD5: md5,
                FIELD_RECEIVED_BLOCKS: list(range(total_block)),
                FIELD_MISSING_BLOCKS: []
            }
            connection_socket.send(
                make_response_packet(OP_STATUS, 200, TYPE_FILE, 'Upload complete.', rval))
            return

        if not os.path.exists(tmp_path):
            connection_socket.send(
                make_response_packet(OP_STATUS, 404, TYPE_FILE, 'No upload in progress for this key.', {}))
            return

        file_size = getsize(tmp_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)

        received = set()
        log_path = tmp_path + '.log'
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                for line in f:
                    s = line.strip()
                    if s.isdigit():
                        received.add(int(s))
    
        all_blocks = set(range(total_block))
        missing = sorted(list(all_blocks - received))
        rval = {
            FIELD_KEY: key,
            FIELD_SIZE: file_size,
            FIELD_TOTAL_BLOCK: total_block,
            FIELD_BLOCK_SIZE: block_size,
            FIELD_RECEIVED_BLOCKS: sorted(list(received)),
            FIELD_MISSING_BLOCKS: missing
        }
        connection_socket.send(
            make_response_packet(OP_STATUS, 200, TYPE_FILE, 'Partial upload status.', rval))
        return


    if request_operation == OP_DOWNLOAD:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Download file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block downloading.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE downloading.', {}))
            return
        logger.info(f'--> Download file/block of "key" {json_data[FIELD_KEY]}.')

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False:
            if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is True:
                logger.error(
                    f'<-- The "key" {json_data[FIELD_KEY]} is not completely uploaded. Please upload it first.')
                connection_socket.send(
                    make_response_packet(OP_GET, 404, TYPE_FILE,
                                         f'The "key" {json_data[FIELD_KEY]} is not completely uploaded. '
                                         f'Please upload it first',
                                         {}))
                return
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is not existing.', {}))
            return

        if FIELD_BLOCK_INDEX not in json_data.keys():
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('file', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            return

        with open(file_path, 'rb') as fid:
            fid.seek(block_size * block_index)
            if block_size * (block_index + 1) < file_size:
                bin_data = fid.read(block_size)
            else:
                bin_data = fid.read(file_size - block_size * block_index)

            rval = {
                FIELD_BLOCK_INDEX: block_index,
                FIELD_KEY: json_data[FIELD_KEY],
                FIELD_SIZE: len(bin_data),
                FIELD_BLOCK_MD5: hashlib.md5(bin_data).hexdigest()
            }
            logger.info(f'<-- Return block {block_index}({len(bin_data)}bytes) of "key" {json_data[FIELD_KEY]} >= 0.')

            connection_socket.send(make_response_packet(OP_DOWNLOAD, 200, TYPE_FILE,
                                                        'An available block.', rval, bin_data))



#  Token generation/verification
def issue_token(username, ttl_seconds):
    username_safe = username.replace('.', '_')
    issued = int(time.time())
    exp = issued + int(ttl_seconds)
    user_str = f'{username_safe}.{issued}.{exp}'
    sig = hashlib.md5(f'{user_str}{SECRET_SUFFIX}'.encode()).hexdigest()
    token_plain = f'{user_str}.{sig}'
    return base64.b64encode(token_plain.encode()).decode(), exp

def validate_token(raw_token):
    try:
        token_plain = base64.b64decode(raw_token).decode()
    except Exception:
        return False, "Token base64 decode error.", None

    parts = token_plain.split('.')
    if len(parts) != 4:
        return False, "Token format is wrong.", None

    username, issued_str, exp_str, sig = parts
    user_str = f'{username}.{issued_str}.{exp_str}'
    expect_sig = hashlib.md5(f'{user_str}{SECRET_SUFFIX}'.encode()).hexdigest()
    if expect_sig.lower() != sig.lower():
        return False, "Token is wrong.", None

    try:
        exp = int(exp_str)
    except ValueError:
        return False, "Token exp invalid.", None

    now = int(time.time())
    if now >= exp:
        return False, "Token expired.", None

    return True, "OK", username

def STEP_service(connection_socket, addr, token_ttl_seconds):
    global logger
    while True:
        json_data, bin_data = get_tcp_packet(connection_socket)
        if json_data is None:
            logger.warning('Connection is closed by client.')
            break

        if FIELD_DIRECTION in json_data and json_data[FIELD_DIRECTION] == DIR_EARTH:
            connection_socket.send(
                make_response_packet('3BODY', 333, 'DANGEROUS', f'DO NOT ANSWER! DO NOT ANSWER! DO NOT ANSWER!', {}))
            continue

        compulsory_fields = [FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE]
        check_ok = True
        for _compulsory_fields in compulsory_fields:
            if _compulsory_fields not in list(json_data.keys()):
                connection_socket.send(
                    make_response_packet(OP_ERROR, 400, 'ERROR', f'Compulsory field {_compulsory_fields} is missing.',
                                         {}))
                check_ok = False
                break
        if check_ok is False:
            continue

        request_type = json_data[FIELD_TYPE]
        request_operation = json_data[FIELD_OPERATION]
        request_direction = json_data[FIELD_DIRECTION]

        if request_direction != DIR_REQUEST:
            connection_socket.send(
                make_response_packet(OP_ERROR, 407, 'ERROR', f'Wrong direction. Should be "REQUEST"', {}))
            continue

        if request_operation not in [OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_STATUS]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 408, 'ERROR', f'Operation {request_operation} is not allowed', {}))
            continue

        if request_type not in [TYPE_FILE, TYPE_DATA, TYPE_AUTH]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 409, 'ERROR', f'Type {request_type} is not allowed', {}))
            continue

        # Login: Issue token
        if request_operation == OP_LOGIN:
            if request_type != TYPE_AUTH:
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 409, TYPE_AUTH, f'Type of LOGIN has to be AUTH.', {}))
                continue
            if FIELD_USERNAME not in json_data.keys():
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"username" has to be a field for LOGIN', {}))
                continue
            if FIELD_PASSWORD not in json_data.keys():
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"password" has to be a field for LOGIN', {}))
                continue

            if hashlib.md5(json_data[FIELD_USERNAME].encode()).hexdigest().lower() != json_data['password'].lower():
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 401, TYPE_AUTH, f'Password error for login.', {}))
                continue
            else:
                token, exp = issue_token(json_data[FIELD_USERNAME], token_ttl_seconds)
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 200, TYPE_AUTH, f'Login successfully', {
                        FIELD_TOKEN: token,
                        'token_ttl': int(token_ttl_seconds),
                        'expires_at': int(exp),
                    }))
                continue

        # Not logged in: Verify token
        if FIELD_TOKEN not in json_data.keys():
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'No token.', {}))
            continue

        ok, msg, username = validate_token(json_data[FIELD_TOKEN])
        if not ok:
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, msg, {}))
            continue
        

        os.makedirs(join('data', username), exist_ok=True)
        os.makedirs(join('file', username), exist_ok=True)
        os.makedirs(join('tmp', username), exist_ok=True)

        if request_type == TYPE_DATA:
            data_process(username, request_operation, json_data, connection_socket)
            continue

        if request_type == TYPE_FILE:
            file_process(username, request_operation, json_data, bin_data, connection_socket)
            continue

    connection_socket.close()
    logger.info(f'Connection close. {addr}')

def tcp_listener(server_ip, server_port, token_ttl_seconds):
    global logger
    # FIX the error: use a TCP (SOCK_STREAM) listener; UDP sockets cannot listen/accept.
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind((server_ip, int(server_port)))
    server_socket.listen(20)
    logger.info('Server is ready!')
    logger.info(
        f'Start the TCP service, listing {server_port} on IP {"All available" if server_ip == "" else server_ip}')
    while True:
        try:
            connection_socket, addr = server_socket.accept()
            logger.info(f'--> New connection from {addr[0]} on {addr[1]}')
            th = Thread(target=STEP_service, args=(connection_socket, addr, token_ttl_seconds))
            th.daemon = True
            th.start()
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno if ex.__traceback__ else "unknown"}')


def main():
    global logger
    logger = set_logger('STEP')
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port

    token_ttl_seconds = int(
        parser.token_ttl or os.getenv('STEP_TOKEN_TTL') or DEFAULT_TOKEN_TTL
    )

    os.makedirs('data', exist_ok=True)
    os.makedirs('file', exist_ok=True)

    # FIX the error: read exactly 8-byte header (2x uint32 big-endian) before body parsing.
    tcp_listener(server_ip, server_port, token_ttl_seconds)


if __name__ == '__main__':
    main()
