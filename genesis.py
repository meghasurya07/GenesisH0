import codecs
import hashlib
import struct
import time
import sys
import optparse

from construct import Struct, Bytes, Byte, this

try:
    from construct import Int32ul, Int64ul
except ImportError:
    # fallback for older construct versions
    # Define Int32ul and Int64ul manually if not available
    from construct import Int32ul as Int32ul  # May fail, just pass
    from construct import Int64ul as Int64ul

def main():
    options = get_args()

    algorithm = get_algorithm(options)

    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)

    # hash merkle root is the double sha256 hash of the transaction(s)
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()

    print_block_info(options, hash_merkle_root)

    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)

    announce_found_genesis(genesis_hash, nonce)


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time", dest="time", default=int(time.time()),
                      type="int", help="the (unix) time when the genesisblock is created")
    parser.add_option("-z", "--timestamp", dest="timestamp",
                      default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
                      type="string", help="the pszTimestamp found in the coinbase of the genesisblock")
    parser.add_option("-n", "--nonce", dest="nonce", default=0,
                      type="int", help="the first value of the nonce that will be incremented when searching the genesis hash")
    parser.add_option("-a", "--algorithm", dest="algorithm", default="SHA256",
                      help="the PoW algorithm: [SHA256|scrypt|X11|X13|X15]")
    parser.add_option("-p", "--pubkey", dest="pubkey",
                      default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
                      type="string", help="the pubkey found in the output script")
    parser.add_option("-v", "--value", dest="value", default=5000000000,
                      type="int", help="the value in coins for the output, full value (e.g. 5000000000 for 50 BTC)")
    parser.add_option("-b", "--bits", dest="bits",
                      type="int", help="the target in compact representation, associated to a difficulty of 1")

    (options, args) = parser.parse_args()
    if not options.bits:
        if options.algorithm in ["scrypt", "X11", "X13", "X15"]:
            options.bits = 0x1e0ffff0
        else:
            options.bits = 0x1d00ffff
    return options


def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15"]
    if options.algorithm in supported_algorithms:
        return options.algorithm
    else:
        sys.exit("Error: Given algorithm must be one of: " + str(supported_algorithms))


def create_input_script(psz_timestamp):
    psz_prefix = ""
    # Use OP_PUSHDATA1 if required (timestamp longer than 76 bytes)
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'

    length_hex = format(len(psz_timestamp), '02x')
    script_prefix = '04ffff001d0104' + psz_prefix + length_hex
    full_script_hex = script_prefix + psz_timestamp.encode().hex()

    print("Input Script (hex):", full_script_hex)
    return bytes.fromhex(full_script_hex)


def create_output_script(pubkey):
    script_len = '41'  # 65 bytes length of uncompressed pubkey
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey + OP_CHECKSIG)


def create_transaction(input_script, output_script, options):
    # Fallback: define 4-byte little endian unsigned ints with Struct format manually:
    version = struct.pack("<I", 1)
    num_inputs = struct.pack("<B", 1)
    prev_output = b'\x00' * 32
    prev_out_idx = struct.pack("<I", 0xFFFFFFFF)
    input_script_len = struct.pack("<B", len(input_script))
    sequence = struct.pack("<I", 0xFFFFFFFF)
    num_outputs = struct.pack("<B", 1)
    out_value = struct.pack("<Q", options.value)
    output_script_len = struct.pack("<B", len(output_script))
    locktime = struct.pack("<I", 0)

    tx = (
        version + num_inputs + prev_output + prev_out_idx + input_script_len +
        input_script + sequence + num_outputs + out_value + output_script_len +
        output_script + locktime
    )
    return tx


def create_block_header(hash_merkle_root, time_val, bits, nonce):
    version = struct.pack("<I", 1)
    prev_block = b'\x00' * 32
    merkle_root = hash_merkle_root
    time_bytes = struct.pack("<I", time_val)
    bits_bytes = struct.pack("<I", bits)
    nonce_bytes = struct.pack("<I", nonce)
    return version + prev_block + merkle_root + time_bytes + bits_bytes + nonce_bytes


def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash...')
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
        header_hash = sha256_hash  # Only SHA256 supported here

        last_updated = calculate_hashrate(nonce, last_updated)

        if int(codecs.encode(header_hash, 'hex'), 16) < target:
            return (header_hash, nonce)

        nonce += 1

        if nonce > 0xFFFFFFFF:
            nonce = 0
            print("Nonce limit reached, incrementing timestamp...")
            block = bytearray(data_block)
            timestamp = struct.unpack('<I', block[68:72])[0]
            timestamp += 1
            block[68:72] = struct.pack('<I', timestamp)
            data_block = bytes(block)

        data_block = data_block[:76] + struct.pack("<I", nonce)


def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write("\r%s hash/s, estimate: %s h" % (str(hashrate), str(generation_time)))
        sys.stdout.flush()
        return now
    else:
        return last_updated


def print_block_info(options, hash_merkle_root):
    print("algorithm: " + options.algorithm)
    print("merkle hash: " + codecs.encode(hash_merkle_root[::-1], 'hex').decode())
    print("pszTimestamp: " + options.timestamp)
    print("pubkey: " + options.pubkey)
    print("time: " + str(options.time))
    print("bits: " + hex(options.bits))


def announce_found_genesis(genesis_hash, nonce):
    print("\ngenesis hash: " + genesis_hash.hex())
    print("nonce: " + str(nonce))


if __name__ == "__main__":
    main()
