import json
import struct


def serialize_json(message):
    # serialize
    json_serialized = json.dumps(message)

    # get the length of serialized JSON
    json_len = len(json_serialized)

    # pack the length as a 4-byte unsigned integer in network byte standard order
    header = struct.pack('!I', json_len)

    # concatenate header and serialized JSON
    payload = header + json_serialized.encode('utf-8')

    return payload
