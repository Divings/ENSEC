#!/usr/bin/env python3
import sys
import lzma
import json
import datetime

BLOCKCHAIN_HEADER = b'BLOCKCHAIN_DATA_START\n'

def main():
    if len(sys.argv) < 2:
        print("ファイルを指定してください", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]

    with lzma.open(file_path, 'rb') as f:
        data = f.read()

    split_index = data.index(BLOCKCHAIN_HEADER)
    chain_bytes = data[split_index + len(BLOCKCHAIN_HEADER):]
    chain_json_str = chain_bytes.decode('utf-8', errors='ignore').strip()

    parsed = json.loads(chain_json_str)

    parsed.sort(
        key=lambda b: datetime.datetime.strptime(
            b['timestamp'],
            '%Y-%m-%d %H:%M:%S.%f%z'
        )
    )

    print(json.dumps(parsed, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()