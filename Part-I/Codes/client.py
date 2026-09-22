import argparse
import hashlib
import json
import os
import socket
import struct
import threading
import time
import numpy as np
import gzip
import zlib
import shutil

from tqdm import tqdm

DIR_REQUEST = 'REQUEST'
TYPE_FILE, TYPE_DATA, TYPE_AUTH = 'FILE', 'DATA', 'AUTH'
OP_SAVE, OP_UPLOAD, OP_LOGIN, OP_DELETE= 'SAVE', 'UPLOAD', 'LOGIN', 'DELETE'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = (
    'operation', 'direction', 'type', 'username', 'password', 'token'
)
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = (
    'key', 'size', 'total_block', 'md5', 'block_size'
)
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'

PARALLELISM = 16
PACKET_LENGTH = 20480
RE_TRANSMISSION_TIME = 15
TOTAL_BLOCK = 0
SEMAPHORE = threading.Semaphore(PARALLELISM)
# Log in first and then implement mutual exclusion.
REAUTH_LOCK = threading.Lock()

STUDENT_ID, TOKEN = None, None
SERVER_IP, SERVER_PORT = None, 1379
FILE_PATH, FILE_NAME, FILE_SIZE = '', '', 0
# The current uploaded file's MD5 is used to compare with the MD5 of the server.
LOCAL_MD5 = None

# Socket and mutex lock
UPLOAD_SOCKET = None
UPLOAD_LOCK = threading.Lock()

MAX_RETRY = 3
TOKEN_EXPIRED_REPORTED = False

# Record performance
upload_times = []
bandwidth_usage = []

# Operation / Field
OP_STATUS = 'STATUS'
FIELD_RECEIVED_BLOCKS = 'received_blocks'
FIELD_MISSING_BLOCKS = 'missing_blocks'
FIELD_BLOCK_MD5 = 'block_md5'

# Progress bar monitoring
PBAR = None
SHOW_PER_BLOCK_LOG = False
# Exponential moving average
AVG_BW_EMA = 0.0
EMA_ALPHA = 2.0 / 21.0

# 400–410 User-friendly error message
_ERROR_MAP = {
    400: "Missing required fields or invalid request format (Bad Request).",
    401: "Login failed: incorrect username or password (Unauthorized).",
    402: "Resource already exists or incomplete parameters (Already Exists / Unprocessable).",
    403: "Unauthorized: invalid or expired token, or insufficient permissions (Forbidden).",
    404: "Not found: target resource does not exist or upload not completed (Not Found).",
    405: "Parameter out of range: e.g., block_index exceeds limit (Method Not Allowed / Out of Range).",
    406: "Parameter/content mismatch: block size or block MD5 verification failed (Not Acceptable).",
    407: "Request direction error: direction must be REQUEST (Proxy/Auth Direction Error).",
    408: "Operation not allowed or conflict: e.g., file already complete or SAVE not performed first (Conflict / Request Timeout).",
    409: "Type or operation conflict: Type not allowed or inconsistent with current operation (Conflict).",
    410: "Missing or invalid parameters: e.g., missing key or block_index (Gone / Invalid Argument).",
}

# Record the version number of the uploaded file
VERSION_FILE = 'file_versions.json'


def load_version_data():
    """Load file version information"""
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_version_data(version_data):
    """Save file version information"""
    with open(VERSION_FILE, 'w') as f:
        json.dump(version_data, f, indent=4)


def generate_file_version(file_name):
    """Generate version numbers for each file"""
    version_data = load_version_data()
    if file_name not in version_data:
        version_data[file_name] = 1
    else:
        version_data[file_name] += 1
    save_version_data(version_data)
    return version_data[file_name]


def compress_file(file_path, compression_method='gzip'):
    """Compressed file, supporting gzip and zlib"""
    if compression_method == 'gzip':
        output_path = file_path + '.gz'
        with open(file_path, 'rb') as f_in:
            with gzip.open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return output_path
    elif compression_method == 'zlib':
        output_path = file_path + '.zlib'
        with open(file_path, 'rb') as f_in:
            compressed_data = zlib.compress(f_in.read())
            with open(output_path, 'wb') as f_out:
                f_out.write(compressed_data)
        return output_path
    else:
        raise ValueError("Unsupported compression method")


def decompress_file(compressed_file_path, compression_method='gzip'):
    """Extract the compressed file"""
    if compression_method == 'gzip':
        output_path = compressed_file_path.rstrip('.gz')
        with gzip.open(compressed_file_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        return output_path
    elif compression_method == 'zlib':
        output_path = compressed_file_path.rstrip('.zlib')
        with open(compressed_file_path, 'rb') as f_in:
            compressed_data = f_in.read()
            decompressed_data = zlib.decompress(compressed_data)
            with open(output_path, 'wb') as f_out:
                f_out.write(decompressed_data)
        return output_path
    else:
        raise ValueError("Unsupported compression method")


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="STEP client uploader (with token auto refresh)")
    parser.add_argument("--server_ip", required=True, help="Server IP")
    parser.add_argument("--id", required=True, help="Student ID")
    parser.add_argument("--f", dest="file_path", required=True, help="Path to file")
    args = parser.parse_args()
    return args.server_ip, args.id, args.file_path


def socket_setup():
    """Create and configure a TCP connection with the server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(RE_TRANSMISSION_TIME)
    sock.connect((SERVER_IP, SERVER_PORT))
    return sock


def _recv_exact(sock, n: int) -> bytes:
    """Precisely receive n bytes"""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading")
        buf += chunk
    return buf


def create_step_head(operation, data_type, json_data, bin_length=0):
    """Construct the header of the STEP protocol (JSON length + BIN length + JSON body)"""
    global TOKEN
    j = dict(json_data)
    if TOKEN:
        j[FIELD_TOKEN] = TOKEN
    j[FIELD_DIRECTION] = DIR_REQUEST
    j[FIELD_OPERATION] = operation
    j[FIELD_TYPE] = data_type
    jb = json.dumps(j, ensure_ascii=False).encode()
    return struct.pack('!II', len(jb), bin_length) + jb


def get_step_data(sock):
    """Read a frame of STEP data from the socket"""
    header = _recv_exact(sock, 8)
    j_len, b_len = struct.unpack('!II', header)
    jb = _recv_exact(sock, j_len)
    j = json.loads(jb.decode())
    blob = _recv_exact(sock, b_len) if b_len > 0 else b''
    return j, blob


def get_status_code(json_data):
    return json_data.get(FIELD_STATUS, -1)


def friendly_error(j: dict) -> str:
    """Convert the JSON returned by the server into a readable error message; retain the original status_msg for additional information."""
    code = j.get('status', -1)
    base = _ERROR_MAP.get(code, f"Unknown error (status={code}).")
    extra = str(j.get('status_msg', '')).strip()
    return f"{base} {extra}" if extra else base

def compute_file_md5(path, chunk_size=2048):
    """Calculate the MD5 of the local file (for end-to-end integrity verification)"""
    m = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            m.update(data)
    return m.hexdigest()


def record_transfer_metrics(filename, file_size, total_time, avg_block_time=None, tag="simple"):
    """
    Record the overall transmission performance in the log file:
    - total_time: The total upload time (in seconds)
    - avg_block_time: Optional, the average time per block (in seconds)
    - tag: The tag indicating whether it is simple_upload or enhanced_upload
    """
    os.makedirs("performance_logs", exist_ok=True)
    log_file = "performance_logs/transfer_metrics.log"

    # file does not exist
    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write(
                "Timestamp,Mode,Filename,File Size (MB),Total Time (s),"
                "Transfer Speed (MB/s),Avg Block Time (ms)\n"
            )

    size_mb = file_size / (1024 * 1024)
    transfer_speed = size_mb / total_time if total_time > 0 else 0.0
    avg_block_ms = avg_block_time * 1000 if avg_block_time is not None else None

    # Format the time into a string
    if avg_block_ms is not None:
        avg_block_ms_str = f"{avg_block_ms:.2f}"
    else:
        avg_block_ms_str = "N/A"

    with open(log_file, "a") as f:
        f.write(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')},"
            f"{tag},"
            f"{filename},"
            f"{size_mb:.2f},"
            f"{total_time:.2f},"
            f"{transfer_speed:.2f},"
            f"{avg_block_ms_str}\n"
        )


def _block_size_bytes(block_index: int) -> int:
    """Return the number of bytes in the block indexed by block_index"""
    if block_index < TOTAL_BLOCK - 1:
        return PACKET_LENGTH
    return FILE_SIZE - PACKET_LENGTH * (TOTAL_BLOCK - 1)


def _send_packet(operation, data_type, payload, blob=b''):
    """Send a STEP request frame and return the response in JSON format along with binary data."""
    sock = socket_setup()
    try:
        head = create_step_head(operation, data_type, payload, len(blob))
        sock.sendall(head + blob)
        j, b = get_step_data(sock)
        return j, b
    finally:
        sock.close()


def _send_packet_on_upload_socket(operation, data_type, payload, blob=b''):
    """
    Send a frame of STEP request on the shared upload socket:
    -  No longer create/close TCP for each block, but reuse the global UPLOAD_SOCKET
    - Use UPLOAD_LOCK to ensure serial access to the socket by multiple threads
    """
    global UPLOAD_SOCKET
    if UPLOAD_SOCKET is None:
        raise RuntimeError("UPLOAD_SOCKET is not initialized")

    head = create_step_head(operation, data_type, payload, len(blob))
    with UPLOAD_LOCK:
        UPLOAD_SOCKET.sendall(head + blob)
        j, b = get_step_data(UPLOAD_SOCKET)
    return j, b


def step_login_operation(student_id):
    """Log in to obtain the TOKEN; for the outer concurrent scenario, use reauth() to wrap it up"""
    global TOKEN
    payload = {
        FIELD_USERNAME: student_id,
        FIELD_PASSWORD: hashlib.md5(student_id.encode()).hexdigest()
    }
    j, _ = _send_packet(OP_LOGIN, TYPE_AUTH, payload, b'')
    if FIELD_TOKEN in j and j.get('status') == 200:
        TOKEN = j[FIELD_TOKEN]
        ttl = j.get('token_ttl')
        exp = j.get('expires_at')
        print(f"Token: {TOKEN}")
        print(f"Login OK. Token acquired. ttl={ttl}s, exp={exp}")
    else:
        raise SystemExit(f"Login failed: {friendly_error(j)}  Original response: {j}")


def step_status_operation(file_name):
    """Query the upload status of a certain key (supporting resume from where it left off)"""
    payload = {FIELD_KEY: file_name}
    j, _ = _send_packet(OP_STATUS, TYPE_FILE, payload, b'')
    return j


def reauth():
    """Re-login under multi-threading: Only allow one thread to perform the login, while other threads wait."""
    global STUDENT_ID
    with REAUTH_LOCK:
        print("Re-authenticating due to token issue...")
        step_login_operation(STUDENT_ID)


def step_save_operation(file_name, file_size):
    """SAVE: Create upload plan (without version number), support automatic retry once after token expiration"""
    global TOTAL_BLOCK, PACKET_LENGTH
    payload = {FIELD_KEY: file_name, FIELD_SIZE: file_size}

    # Encapsulate it as an internal function to facilitate retrying.
    def _do_save():
        return _send_packet(OP_SAVE, TYPE_FILE, payload, b'')

    # First try
    plan, _ = _do_save()
    code = get_status_code(plan)

    if code == 200:
        PACKET_LENGTH = int(plan[FIELD_BLOCK_SIZE])
        TOTAL_BLOCK = int(plan[FIELD_TOTAL_BLOCK])
        print(f"Plan OK: total_block={TOTAL_BLOCK}, block_size={PACKET_LENGTH}")
        return

    # If the token has expired, automatically re-login and try again.
    if code == 403 and 'expired' in str(plan.get('status_msg', '')).lower():
        print("Token expired during SAVE. Re-authenticating and retrying SAVE...")
        reauth()
        plan, _ = _do_save()
        code = get_status_code(plan)
        if code == 200:
            PACKET_LENGTH = int(plan[FIELD_BLOCK_SIZE])
            TOTAL_BLOCK = int(plan[FIELD_TOTAL_BLOCK])
            print(f"Plan OK after re-login: total_block={TOTAL_BLOCK}, block_size={PACKET_LENGTH}")
            return

    # SAVE FAILED COMPLETELY
    raise SystemExit(f"SAVE failed: {friendly_error(plan)}  Original response: {plan}")


def step_save_operation_with_version(file_name, file_size):
    """SAVE: With version control, automatically generates a new version number for the file key."""
    global TOKEN_EXPIRED_REPORTED, TOTAL_BLOCK, PACKET_LENGTH
    version = generate_file_version(file_name)
    print(f"Uploading file {file_name} (Version {version})...")
    payload = {FIELD_KEY: file_name, FIELD_SIZE: file_size, 'version': version}

    plan, _ = _send_packet(OP_SAVE, TYPE_FILE, payload, b'')
    if get_status_code(plan) == 200:
        PACKET_LENGTH = int(plan[FIELD_BLOCK_SIZE])
        TOTAL_BLOCK = int(plan[FIELD_TOTAL_BLOCK])
        print(f"Plan OK: total_block={TOTAL_BLOCK}, block_size={PACKET_LENGTH}")
        return

    if get_status_code(plan) == 403 and 'expired' in str(plan.get('status_msg', '')).lower():
        if not TOKEN_EXPIRED_REPORTED:
            print("Token expired. Please log in again.")
            print("Hint:", _ERROR_MAP[403])
            TOKEN_EXPIRED_REPORTED = True
        return

    raise SystemExit(f"SAVE failed: {friendly_error(plan)}  Original response: {plan}")


def step_upload_operation(block_index, compression_method=None):
    """
    Upload a single block:
    - Use the current file pointed to by FILE_PATH (it could be the original file or a compressed temporary file)
    - Calculate the MD5 for each block and include FIELD_BLOCK_MD5
    - Automatically re-login and retry if the token expires
    - Perform end-to-end MD5 verification when the server returns the MD5 of the entire file
    """
    global TOKEN_EXPIRED_REPORTED, AVG_BW_EMA, LOCAL_MD5
    offset = block_index * PACKET_LENGTH

    # Use the current FILE_PATH
    with open(FILE_PATH, 'rb') as f:
        f.seek(offset)
        size_this = PACKET_LENGTH if block_index < TOTAL_BLOCK - 1 else FILE_SIZE - PACKET_LENGTH * (TOTAL_BLOCK - 1)
        chunk = f.read(size_this)

    start_time = time.time()

    attempt = 0
    while attempt < MAX_RETRY:
        attempt += 1
        try:
            blk_md5 = hashlib.md5(chunk).hexdigest()
            payload = {
                FIELD_KEY: FILE_NAME,
                FIELD_BLOCK_INDEX: block_index,
                FIELD_BLOCK_MD5: blk_md5,
            }
            if UPLOAD_SOCKET is not None:
                # Simple upload scenario: Multiple threads sharing a TCP connection
                j, _ = _send_packet_on_upload_socket(OP_UPLOAD, TYPE_FILE, payload, chunk)
            else:
                # Other scenarios (enhanced_upload / cli_main) maintain the original style of creating a new connection for each block.
                j, _ = _send_packet(OP_UPLOAD, TYPE_FILE, payload, chunk)

            code = get_status_code(j)

            if code in (200, 201):
                # Calculate performance indicators and update the progress bar
                end_time = time.time()
                upload_time = end_time - start_time
                upload_times.append(upload_time)

                bandwidth = size_this / upload_time if upload_time > 0 else 0.0
                bandwidth_usage.append(bandwidth)

                if AVG_BW_EMA <= 0.0:
                    AVG_BW_EMA = bandwidth
                else:
                    AVG_BW_EMA = EMA_ALPHA * bandwidth + (1.0 - EMA_ALPHA) * AVG_BW_EMA

                if PBAR is not None:
                    PBAR.update(size_this)
                    PBAR.set_postfix({
                        'cur': f'{bandwidth / (1024 * 1024):.2f} MB/s',
                        'avg~20': f'{AVG_BW_EMA / (1024 * 1024):.2f} MB/s'
                    })
                if SHOW_PER_BLOCK_LOG:
                    print(f"[block {block_index}] upload time: {upload_time:.2f}s, "
                          f"bandwidth: {bandwidth / (1024 * 1024):.2f} MB/s")

                server_md5 = j.get(FIELD_MD5)
                if server_md5:
                    if LOCAL_MD5:
                        client_md5 = LOCAL_MD5
                    else:
                        client_md5 = compute_file_md5(FILE_PATH)

                    if client_md5 == server_md5:
                        print(f"[block {block_index}] upload complete. MD5 match: {client_md5}")
                    else:
                        print(
                            f"[block {block_index}] upload complete. MD5 MISMATCH! "
                            f"client={client_md5}, server={server_md5}"
                        )

                return

            # Token has expired
            if code == 403 and 'expired' in str(j.get('status_msg', '')).lower():
                print(f"[block {block_index}] token expired, attempting re-login (attempt {attempt})...")
                reauth()
                # Reissue the current block
                continue

            # Other errors: Print the specific reasons
            print(f"[block {block_index}] failed: {friendly_error(j)}  Original response: {j}")

        except (socket.timeout, ConnectionError) as e:
            print(f"[block {block_index}] timeout/retry ({attempt}/{MAX_RETRY}): {e}")

    # Failed after attempting MAX_RETRY times
    raise RuntimeError(f"block {block_index} failed after {MAX_RETRY} attempts")



def concurrent_uploader(block_index):
    """Multi-threaded upload task wrapper, automatically releasing the semaphore"""
    try:
        step_upload_operation(block_index)
    finally:
        SEMAPHORE.release()


def concurrent_uploader_with_version_and_compression(block_index, compression_method=None):
    """Upload task wrapper in the scenario with compression/version control"""
    try:
        step_upload_operation(block_index, compression_method)
    finally:
        SEMAPHORE.release()


def _start_upload_threads(missing_blocks, use_enhanced=False, compression_method=None):
    """Internal tool: Start multi-threaded upload based on the list of missing blocks"""
    threads = []
    for i in missing_blocks:
        SEMAPHORE.acquire()
        if use_enhanced:
            t = threading.Thread(
                target=concurrent_uploader_with_version_and_compression,
                args=(i, compression_method)
            )
        else:
            t = threading.Thread(target=concurrent_uploader, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


def simple_upload(server_ip, student_id, file_path):
    """
    Simple upload entry (without parsing command line):
    - Input the specific server_ip / student_id / file_path
    - No version control or compression enabled
    - Supports STATUS for resume of interrupted uploads
    - Uses a single long connection UPLOAD_SOCKET + multi-threaded upload
    """
    global FILE_PATH, FILE_NAME, FILE_SIZE, RE_TRANSMISSION_TIME
    global STUDENT_ID, SERVER_IP, TOTAL_BLOCK, PBAR, LOCAL_MD5, UPLOAD_SOCKET

    # Clear performance statistics
    global upload_times, bandwidth_usage, AVG_BW_EMA
    upload_times.clear()
    bandwidth_usage.clear()
    AVG_BW_EMA = 0.0

    # Set global variables using parameters
    SERVER_IP = server_ip
    STUDENT_ID = student_id
    FILE_PATH = file_path

    FILE_NAME = os.path.basename(FILE_PATH)
    FILE_SIZE = os.path.getsize(FILE_PATH)

    # Pre-compute the MD5 of local files
    LOCAL_MD5 = compute_file_md5(FILE_PATH)
    print(f"Local file MD5: {LOCAL_MD5}")

    # Login (short)
    step_login_operation(STUDENT_ID)

    # Establish a long connection for subsequent multi-threaded uploads
    UPLOAD_SOCKET = socket_setup()

    try:
        # 1. STATUS: Decide whether to continue the ongoing project or start a new one
        st = step_status_operation(FILE_NAME)
        code = get_status_code(st)

        if code == 200:
            global PACKET_LENGTH
            if FIELD_BLOCK_SIZE in st:
                PACKET_LENGTH = int(st[FIELD_BLOCK_SIZE])
            if FIELD_TOTAL_BLOCK in st:
                TOTAL_BLOCK = int(st[FIELD_TOTAL_BLOCK])
            received = set(st.get(FIELD_RECEIVED_BLOCKS, []))
            all_blocks = set(range(TOTAL_BLOCK))
            missing_blocks = sorted(list(all_blocks - received))
            if not missing_blocks:
                print(f"Already completed on server. MD5={st.get(FIELD_MD5)}")
                return
            print(
                f"Resume plan from STATUS: total={TOTAL_BLOCK}, "
                f"block_size={PACKET_LENGTH}, missing={len(missing_blocks)}"
            )
        elif code in (404, 408):
            step_save_operation(FILE_NAME, FILE_SIZE)
            missing_blocks = list(range(TOTAL_BLOCK))
        else:
            raise SystemExit(f"STATUS failed: {friendly_error(st)}  Original response: {st}")

        # 2. Initialize progress bar
        total_bytes_to_upload = sum(_block_size_bytes(i) for i in missing_blocks)
        PBAR = tqdm(
            total=total_bytes_to_upload,
            unit='B',
            unit_scale=True,
            desc='Uploading',
            dynamic_ncols=True,
            position=0,
            leave=True,
            mininterval=0.2
        )

        # 3. Dynamic adjustment of timeout time
        total_threads = (FILE_SIZE + PACKET_LENGTH - 1) // PACKET_LENGTH
        globals()['RE_TRANSMISSION_TIME'] = RE_TRANSMISSION_TIME + max(0, total_threads // 1000)

        # 4. Start multi-threaded upload
        upload_start = time.time()
        _start_upload_threads(missing_blocks, use_enhanced=False)
        upload_end = time.time()
        total_upload_time = upload_end - upload_start

        if PBAR is not None:
            PBAR.close()

        # Total time consumed + Average time per block
        print(f"\nUpload completed in {total_upload_time:.2f} seconds")
        if TOTAL_BLOCK > 0:
            avg_block_time = total_upload_time / TOTAL_BLOCK
            avg_block_time_ms = avg_block_time * 1000.0
            print(f"Average time per block: {avg_block_time_ms:.2f} ms")
        else:
            avg_block_time = None

        # Output performance statistics
        if upload_times:
            avg_upload_time = np.mean(upload_times)
            avg_bandwidth = np.mean(bandwidth_usage)
        else:
            avg_upload_time = 0.0
            avg_bandwidth = 0.0
            print("No performance data collected - all blocks may have been uploaded on first attempt")

        print(f"\nOverall upload performance:")
        print(f"Average upload time per block: {avg_upload_time:.2f} seconds")
        print(f"Average bandwidth: {avg_bandwidth / (1024 * 1024):.2f} MB/s")
        print("All blocks uploaded.")

        # Record in the performance log file
        record_transfer_metrics(
            filename=FILE_NAME,
            file_size=FILE_SIZE,
            total_time=total_upload_time,
            avg_block_time=avg_block_time,
            tag="simple"
        )

    finally:
        # 5. Regardless of normal/early departure/abnormal situations, all long connections will be closed uniformly.
        if UPLOAD_SOCKET is not None:
            try:
                UPLOAD_SOCKET.close()
            except Exception as e:
                print(f"Warning: failed to close UPLOAD_SOCKET: {e}")
            UPLOAD_SOCKET = None


def main():
    """
    python client.py --server_ip ... --id ... --f ...
    """
    server_ip, student_id, file_path = parse_command_line_args()
    simple_upload(server_ip, student_id, file_path)


# Download / Status / Delete


def step_download_operation(file_key, save_path):
    """Multithreaded chunked file downloading"""
    global PBAR

    # Initialize the download plan
    payload = {FIELD_KEY: file_key}
    j, _ = _send_packet('GET', TYPE_FILE, payload, b'')
    if get_status_code(j) != 200:
        print(f"Download init failed: {friendly_error(j)}  Original: {j}")
        return

    # Parse download parameters
    block_size = int(j[FIELD_BLOCK_SIZE])
    total_block = int(j[FIELD_TOTAL_BLOCK])
    file_size = int(j[FIELD_SIZE])
    server_md5 = j.get(FIELD_MD5)

    # Pre-create files and allocate space
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    with open(save_path, 'wb+') as f:
        if file_size > 0:
            f.seek(file_size - 1)
            f.write(b'\0')

    def download_block(idx):
        """Download a single file block"""
        try:
            payload = {FIELD_KEY: file_key, FIELD_BLOCK_INDEX: idx}
            j2, blob = _send_packet('DOWNLOAD', TYPE_FILE, payload, b'')
            if get_status_code(j2) == 200:
                with open(save_path, 'rb+') as f_out:
                    f_out.seek(block_size * idx)
                    f_out.write(blob)
                if PBAR:
                    PBAR.update(len(blob))
            else:
                print(f"[download block {idx}] failed: {friendly_error(j2)}")
        finally:
            SEMAPHORE.release()

    # Start multi-threaded download
    PBAR = tqdm(total=file_size, unit='B', unit_scale=True, desc='Downloading', dynamic_ncols=True)
    threads = []
    for i in range(total_block):
        SEMAPHORE.acquire()
        t = threading.Thread(target=download_block, args=(i,))
        threads.append(t)
        t.start()

    # Waiting
    for t in threads:
        t.join()
    PBAR.close()
    print(f"Download complete: {save_path}")

    if server_md5:
        local_md5 = compute_file_md5(save_path)
        if local_md5 == server_md5:
            print(f"Download MD5 match: {local_md5}")
        else:
            print(f"Download MD5 MISMATCH! client={local_md5}, server={server_md5}")


def step_status_check(file_key):
    """Query the status of file upload/download"""
    st = step_status_operation(file_key)
    if get_status_code(st) == 200:
        print(json.dumps(st, indent=4))
    else:
        print(f"STATUS failed: {friendly_error(st)}  Original response: {st}")
#delete
def step_delete_operation(file_key, data_type='FILE'):
    """
    Minimize DELETE: Delete FILE or DATA.
    Construct only one frame of STEP request and print the server response, without altering other processes.
    """
    if data_type not in ('FILE', 'DATA'):
        raise SystemExit("Error: --type must be FILE or DATA")
    payload = {FIELD_KEY: file_key}
    j, _ = _send_packet(OP_DELETE, data_type, payload, b'')
    code = get_status_code(j)
    if code == 200:
        print(f"DELETE OK: {j.get('status_msg', '') or file_key}")
    else:
        print(f"DELETE failed: {friendly_error(j)}  Original: {j}")
# Enhanced upload

def enhanced_upload(compression_method=None, use_version_control=False):
    """
    Enhanced upload:
    - Optional: Compress the entire file at once and upload it in chunks
    - Optional: Enable version control when creating an upload plan
    - Still supports STATUS resume from where it left off
    """
    global FILE_PATH, FILE_NAME, FILE_SIZE, RE_TRANSMISSION_TIME, STUDENT_ID, SERVER_IP, TOTAL_BLOCK, PBAR

    global upload_times, bandwidth_usage, AVG_BW_EMA
    upload_times.clear()
    bandwidth_usage.clear()
    AVG_BW_EMA = 0.0


    original_file_path = FILE_PATH
    compressed_file = None

    # If compression is enabled, compress the entire file first.
    if compression_method:
        try:
            print(f"Compressing entire file with {compression_method}...")
            compressed_file = compress_file(FILE_PATH, compression_method)
            FILE_PATH = compressed_file
            FILE_SIZE = os.path.getsize(FILE_PATH)
            print(f"File compressed: {original_file_path} -> {FILE_PATH} ({FILE_SIZE} bytes)")
        except Exception as e:
            print(f"Compression failed: {e}, using original file")
            FILE_PATH = original_file_path
            compression_method = None

    # Directly check STATUS
    st = step_status_operation(FILE_NAME)
    code = get_status_code(st)

    # Based on the status, determine the upload strategy
    if code == 200:
        global PACKET_LENGTH
        if FIELD_BLOCK_SIZE in st:
            PACKET_LENGTH = int(st[FIELD_BLOCK_SIZE])
        if FIELD_TOTAL_BLOCK in st:
            TOTAL_BLOCK = int(st[FIELD_TOTAL_BLOCK])
        received = set(st.get(FIELD_RECEIVED_BLOCKS, []))
        all_blocks = set(range(TOTAL_BLOCK))
        missing_blocks = sorted(list(all_blocks - received))
        if not missing_blocks:
            print(f"Already completed on server. MD5={st.get(FIELD_MD5)}")
            # Delete the compressed file
            if compressed_file and os.path.exists(compressed_file):
                os.remove(compressed_file)
                FILE_PATH = original_file_path
            return
        print(f"Resume plan from STATUS: total={TOTAL_BLOCK}, block_size={PACKET_LENGTH}, "
              f"missing={len(missing_blocks)}")
    elif code in (404, 408):
        # First upload
        if use_version_control:
            step_save_operation_with_version(FILE_NAME, FILE_SIZE)
        else:
            step_save_operation(FILE_NAME, FILE_SIZE)
        missing_blocks = list(range(TOTAL_BLOCK))
    else:
        if compressed_file and os.path.exists(compressed_file):
            os.remove(compressed_file)
            FILE_PATH = original_file_path
        raise SystemExit(f"STATUS failed: {friendly_error(st)}  Original response: {st}")

    # Initialize progress bar
    total_bytes_to_upload = sum(_block_size_bytes(i) for i in missing_blocks)
    PBAR = tqdm(
        total=total_bytes_to_upload,
        unit='B',
        unit_scale=True,
        desc='Uploading',
        dynamic_ncols=True,
        position=0,
        leave=True,
        mininterval=0.2
    )

    # Dynamic adjustment of timeout time
    total_threads = (FILE_SIZE + PACKET_LENGTH - 1) // PACKET_LENGTH
    globals()['RE_TRANSMISSION_TIME'] = RE_TRANSMISSION_TIME + max(0, total_threads // 1000)

    # Start multi-threaded upload and calculate the total elapsed time
    upload_start = time.time()
    _start_upload_threads(missing_blocks, use_enhanced=True, compression_method=compression_method)
    upload_end = time.time()
    total_upload_time = upload_end - upload_start


    if PBAR is not None:
        PBAR.close()

    print(f"\nUpload completed in {total_upload_time:.2f} seconds")
    if TOTAL_BLOCK > 0:
        avg_block_time = total_upload_time / TOTAL_BLOCK      # 秒
        avg_block_time_ms = avg_block_time * 1000.0
        print(f"Average time per block: {avg_block_time_ms:.2f} ms")
    else:
        avg_block_time = None


    # Restore the original file path and clean up the compressed file
    if compressed_file and os.path.exists(compressed_file):
        FILE_PATH = original_file_path
        try:
            os.remove(compressed_file)
            print(f"Cleaned up temporary compressed file: {compressed_file}")
        except Exception as e:
            print(f"Warning: Failed to clean up compressed file: {e}")

    # Output performance statistics
    if upload_times:
        avg_upload_time = np.mean(upload_times)
        avg_bandwidth = np.mean(bandwidth_usage)
    else:
        avg_upload_time = 0
        avg_bandwidth = 0
        print("No performance data collected - all blocks may have been uploaded on first attempt")

    print(f"\nOverall upload performance:")
    print(f"Average upload time per block: {avg_upload_time:.2f} seconds")
    print(f"Average bandwidth: {avg_bandwidth / (1024 * 1024):.2f} MB/s")
    print("All blocks uploaded.")

    # Record in the performance log file
    record_transfer_metrics(
        filename=FILE_NAME,
        file_size=FILE_SIZE,
        total_time=total_upload_time,
        avg_block_time=avg_block_time,
        tag="enhanced"
    )



# CLI multi-op entrance

def cli_main():
    """
    CLI multiple operation entry:
    --op upload   : Upload
    --op download : Download
    --op status   : Query status
    """
    global FILE_PATH, FILE_NAME, FILE_SIZE, STUDENT_ID, SERVER_IP

    parser = argparse.ArgumentParser(description="STEP client CLI upload/download/status")
    parser.add_argument("--op", choices=["upload", "download", "status", "delete"], required=True,
                        help="Operation type: upload/download/status/delete")
    parser.add_argument("--server_ip", required=True, help="Server IP address")
    parser.add_argument("--id", required=True, help="User ID for authentication")
    parser.add_argument("--f", dest="file_path",
                        help="Local file path (for upload: source; for download: destination)")
    parser.add_argument("--type", choices=["FILE", "DATA"], default="FILE",
                        help="DELETE target type: FILE or DATA (default: FILE)")#delete用的type
    parser.add_argument("--key", dest="file_key",
                        help="File key on server (required for download/status)")
    parser.add_argument("--compress", choices=["gzip", "zlib", "none"], default="none",
                        help="Compression method for upload (gzip/zlib/none)")
    parser.add_argument("--version-control", action="store_true",
                        help="Enable version control for upload")
    args = parser.parse_args()

    # Initialize connection parameters
    SERVER_IP = args.server_ip
    STUDENT_ID = args.id
    step_login_operation(STUDENT_ID)

    # Distribute tasks according to the operation type
    if args.op == "upload":
        if not args.file_path:
            raise SystemExit("Error: --f (file path) is required for upload")
        FILE_PATH = args.file_path
        FILE_NAME = os.path.basename(FILE_PATH)
        FILE_SIZE = os.path.getsize(FILE_PATH)

        # Compression settings
        compression_method = None if args.compress == "none" else args.compress
        if compression_method:
            print(f"Using {compression_method} compression for upload...")
        if args.version_control:
            print("Version control enabled for this upload.")
        if args.version_control or compression_method:
            enhanced_upload(compression_method=compression_method,
                            use_version_control=args.version_control)
        else:
            simple_upload(SERVER_IP, STUDENT_ID, FILE_PATH)

    elif args.op == "download":
        if not all([args.file_key, args.file_path]):
            raise SystemExit("Error: --key (file key) and --f (save path) are required for download")
        step_download_operation(args.file_key, args.file_path)

    elif args.op == "status":
        if not args.file_key:
            raise SystemExit("Error: --key (file key) is required for status check")
        step_status_check(args.file_key)
    #Delete
    elif args.op == "delete":
        if not args.file_key:
            raise SystemExit("Error: --key (file key) is required for delete")
        step_delete_operation(args.file_key, args.type)


# __main__

if __name__ == '__main__':
    import sys
    if '--op' in sys.argv:
        cli_main()
    else:
        main()
