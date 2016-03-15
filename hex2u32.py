import os
import sys
import re
import itertools

# for testing only
import io
os.stdin = io.StringIO("""\
0000   XX XX 02 01 01 04 06 70 75 62 6c 69 63""")

def convert_byte(b):
    if re.match(r'^[0-9a-f]{2}$', b.lower()):
        return int(b, 16)
    else:
        return b

def format_pattern(pattern):
    for sign in pattern:
        if type(sign) == int:
            yield '%02X' % sign
        else:
            yield sign

def create_match(pattern, skip_ip=True, skip_protocol_header=True, check_protocol_header='UDP', ipv6=False, prefix="", offset=0):
    if ipv6:
        raise Exception('IPv6 is not yet implemented')
    #"Start&Mask=Range"
    # start = 0x4
    # 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D ...
    #             |..........|
    # mask:                FF:
    #             00 00 00 07 
    if check_protocol_header == 'UDP':
         yield '6&0xFF=0x11'
    elif check_protocol_header == 'TCP':
        yield '6&0xFF=0x06'
    elif check_protocol_header == 'ICMP':
        yield '6&0xFF=1'
    else:
        raise Exception('Unknown protocol: %s' % protocol)

    if skip_ip:
        prefix += '0>>22&0x3C@' # ip header offset

    if skip_protocol_header:
        if check_protocol_header == 'UDP':
            offset += 0x8
#            prefix += "0x08@"

    parts = list(pattern)
    n = 0
    while len(parts) > 0:
        for i in range(3, -1, -1):
            length = i + 1
            if len(parts) >= length:
                if all([ type(x) == int for x in parts[:length]]):
                    l = parts[:length]
                    shift = 0
                    if length < 4:
                        mask = '&0x' + ('FF' * length) + ('00' * (4 - length))
                    else:
                        mask = ''
                    m = "%s0x%02X%s=0x%s" % (prefix, offset, mask, ''.join(map(lambda x: '%02X' % x, l)) + ('00' * (4-length)))
                    yield m
                    offset += length
                    parts = parts[length:]
                    break
                elif all([ type(x) == str for x in parts[:length]]):
                    if all([ x == "XX" for x in parts[:length]]):
                        offset += length
                        parts = parts[length:]
                        break
                    elif length == 1:
                        # check if the field is a range expression: 0:10000 or 0x1:0xFF
                        p = parts[:length][0]
                        parts = parts[length:]
                        m = re.match(r'^(?P<start>(0x)?[\da-z]+):(?P<end>(0x)?[\da-z]+)', p.lower())
                        if m:
                            mask = '0xFF'
                            start, end = m.group('start'), m.group('end')

                            if 'x' in start:
                                start = int(start, 16)
                            else:
                                start = int(start)

                            if start > 0xFF:
                                raise Exception("Invalid start value: %x" % x)

                            if 'x' in end:
                                end = int(end, 16)
                            else:
                                end = int(end)

                            if end > 0xFF or end < start or end == start:
                                raise Exception("Invalid end value  or start above end.")

                            m = "%s0x%02X&%s=0x%02X:0x%02X" % (prefix, offset, mask, start, end)
                            offset += 1
                            yield m

                        break


def main():
    inp = os.stdin

    # read all lines from input
    data = [ line for line in inp ]

    if len(data) == 0:
        print ("no input given.")
        sys.exit(1)

    # parse input format
    # example:
    #
    # 0000 30 22 02 01 01 04 06 70 75 62 6c 69 63 a1 15 02
    # 0010 04 46 36 22 fe 02 01 00 02 01 00 30 07 30 05 06
    # 0020 01 01 05 00
    # and so on

    # get start address from first line, increment from there on by "byte" read

    start_address_match = re.match('^(\d+)\s', data[0])
    start_address = int(start_address_match.group(0), 16)

    print ("start_address: 0x%02x == %i" % (start_address, start_address))

    # strip out address from each of the lines and read remaining data
    cleaned_data = ( re.sub(r'^\d+\s+', '', line.strip()) for line in data )
    splitted_data = itertools.chain(*( re.split(r'\s+', d) for d in cleaned_data ))

    data = [ convert_byte(val) for val in splitted_data ]

    #print (data)

    print ("data length: %i" % len(data))

    # print out data
    #print (' '.join(format_pattern(data)))

    # format u32 match
    
    print ('iptables -A OUTPUT -m u32 --u32 "%s"' % '&&'.join(create_match(data, offset=start_address)))


if __name__ == "__main__":
    main()
