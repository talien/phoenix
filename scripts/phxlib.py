import struct

def phx_client_unpack(sformat, data):
    i = 0
    amount = 0
    pd = 0
    t = ()
    while i < len(sformat):
        needpack = True
        if ( sformat[i] == 'S' ):
            (slen,) = struct.unpack("<I", data[pd:pd+4])
            pd += 4
            gvar = struct.unpack("%ds" % slen, data[pd:pd+slen])
            pd += slen
        elif ( sformat[i] == 'I' ):
            gvar = struct.unpack("<I", data[pd:pd+4])
            pd += 4
        elif( sformat[i] <= '9' and sformat[i] >= '0'):
            amount = amount*10 + (ord(sformat[i]) - 48);
            needpack = False
        elif ( sformat[i] == 's'):
            gvar = struct.unpack("%ds" % amount, data[pd:pd+amount])
            pd += amount;
        if needpack:
            t = t + gvar
            amount = 0
        i += 1
    return (pd,t)

def phx_client_pack(sformat, data):
    i = 0
    amount = 0
    pd = 0
    result = ""
    while i < len(sformat):
        needpack = True
        if ( sformat[i] == 'S' ):
            result += struct.pack("<I", len(data[pd]))
            result += struct.pack("%ds" % len(data[pd]), data[pd])
            pd += 1
        elif ( sformat[i] == 'I' ):
            result += struct.pack("<I", data[pd])
            pd += 1
        elif( sformat[i] <= '9' and sformat[i] >= '0'):
            amount = amount*10 + (ord(sformat[i]) - 48);
            needpack = False
        elif ( sformat[i] == 's'):
            result += struct.pack("%ds" % amount, data[pd])
            pd += 1;
        if needpack:
            amount = 0
        i += 1
    return result

