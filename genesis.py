
#!/usr/bin/env python3

import hashlib, binascii, struct, time, sys, optparse
import scrypt
from construct import Struct, Bytes, Byte, Int32ul, Int64ul

def main():
    options = get_args()
    algorithm = get_algorithm(options)

    input_script = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print_block_info(options, hash_merkle_root)

    block_header = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time", dest="time", default=int(time.time()), type="int")
    parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks", type="string")
    parser.add_option("-n", "--nonce", dest="nonce", default=0, type="int")
    parser.add_option("-a", "--algorithm", dest="algorithm", default="SHA256")
    parser.add_option("-p", "--pubkey", dest="pubkey", default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f", type="string")
    parser.add_option("-v", "--value", dest="value", default=5000000000, type="int")
    parser.add_option("-b", "--bits", dest="bits", type="int")

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
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'
    length_hex = format(len(psz_timestamp), 'x')
    script_prefix = '04ffff001d0104' + psz_prefix + length_hex
    script = script_prefix + binascii.hexlify(psz_timestamp.encode()).decode()
    print(script)
    return binascii.unhexlify(script)

def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    script = script_len + pubkey + OP_CHECKSIG
    return binascii.unhexlify(script)

def create_transaction(input_script, output_script, options):
    tx = (
        struct.pack("<L", 1) +                          # version
        b"\x01" +                                      # number of inputs
        b"\x00" * 32 +                                 # previous output (null)
        struct.pack("<L", 0xFFFFFFFF) +                 # index
        bytes([len(input_script)]) +                    # script length
        input_script +                                  # script
        struct.pack("<L", 0xFFFFFFFF) +                 # sequence
        b"\x01" +                                      # number of outputs
        struct.pack("<Q", options.value) +             # output value
        bytes([len(output_script)]) +                   # script length
        output_script +                                 # script
        struct.pack("<L", 0)                            # locktime
    )
    return tx

def create_block_header(hash_merkle_root, time_val, bits, nonce):
    header = (
        struct.pack("<L", 1) +                         # version
        b"\x00" * 32 +                                # prev block hash
        hash_merkle_root +                             # merkle root
        struct.pack("<L", time_val) +                 # time
        struct.pack("<L", bits) +                     # bits
        struct.pack("<L", nonce)                      # nonce
    )
    return header

def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash..')
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            return (sha256_hash, nonce)
        else:
            nonce += 1
            data_block = data_block[:-4] + struct.pack('<L', nonce)

def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = b''
    if algorithm == 'scrypt':
        header_hash = scrypt.hash(data_block, data_block, 1024, 1, 1, 32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = sha256_hash
    return sha256_hash, header_hash

def is_genesis_hash(header_hash, target):
    return int.from_bytes(header_hash, byteorder='big') < target

def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write("\r{} hash/s, estimate: {} h".format(hashrate, generation_time))
        sys.stdout.flush()
        return now
    else:
        return last_updated

def print_block_info(options, hash_merkle_root):
    print("algorithm:", options.algorithm)
    print("merkle hash:", binascii.hexlify(hash_merkle_root[::-1]).decode())
    print("pszTimestamp:", options.timestamp)
    print("pubkey:", options.pubkey)
    print("time:", options.time)
    print("bits:", hex(options.bits))

def announce_found_genesis(genesis_hash, nonce):
    print("\nGenesis hash found!")
    print("Nonce:", nonce)
    print("Genesis hash:", binascii.hexlify(genesis_hash).decode())

if __name__ == "__main__":
    main()
