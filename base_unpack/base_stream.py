#coding=utf-8
'''
Create on 2015-01-08

@author: coolyi
'''
import re
import os
import struct

def read_unicode_str(string, offset):
    """ from offset read an utf16-LE str, until \x00\x00 read. """
    #(?s)表示 DOT_MATCH_ALL, 否则遇到0x0A就会断, (..)表示两个字符, ?)表示最小匹配
    unicode_re = re.compile('(?s)((..)*?)\x00\x00')
    m = unicode_re.search(string, offset)
    if not m: raise Exception('无法读取unicode字符串从位置' + str(offset))
    found = m.group(1)
    #because we can't use greed search, so the last \x00 will not included
    found = len(found) % 2 == 0 and found or found + '\x00'
    try:
        return found.decode('UTF-16LE')
    except UnicodeDecodeError as e:
        return ''


class Stream:
    def __init__(self):
        """
        @param global_offset: pointer's global offset.
        """
        if self.__class__ is Stream:
            raise NotImplementedError(str(Stream) + ' is abstract.')

    def __len__(self):
        pass

    def find_onlyone_pos(self, key):
        pass

    def get_position(self):
        pass

    def set_position(self, pos):
        pass

    def read_bytes(self, count):
        pass

    def skip(self, count):
        pass

    def read_int(self):
        pass

    def read_short(self):
        pass

    def read_byte(self):
        pass

    def read_long(self):
        pass

    def read_float(self):
        pass

    def read_pointer(self):
        v = self.read_int()
        return v  if v != 0 else 0

    def read_ptr_unicode(self):
        pass

    def read_str(self, length):
        pass

    def has_more(self):
        pass

    def read_unsigned_leb128(self):
        result = 0
        for i in xrange(5):
            t = self.read_byte()
            result = result  | ((t & 0x7f) << i*7)
            if t < 0x7f:
                break
        return result
    
    def skip_unsigned_leb128(self, count=1):
        if count > 0:
            for _ in xrange(count):
                self.read_unsigned_leb128()


class FileStream(Stream):
    def __init__(self, filename):
        Stream.__init__(self)
        if os.path.exists( filename ):
            self.len  = os.path.getsize(filename)
            self.file = open(filename, 'wrb')
        else:
            self.len = 0
            self.file = open(filename, 'wrb')

    def __len__(self):
        old_pos = self.get_position()
        self.file.seek(0, 2)
        self.len = self.file.tell()
        self.file.seek(old_pos, 0)
        return self.len

    def __piece(self, count):
        return self.file.read(count)

    def get_position(self):
        return self.file.tell()

    def set_position(self, pos):
        if pos >= self.__len__():
            raise Exception("set position at " + str(hex(pos)) + " but file len is only " + str(hex(self.len)))
        else:
            return self.file.seek(pos)

    def skip(self, count):
        self.file.seek(count, 1)

    def has_more(self):
        return self.file.tell() < self.__len__()

    def read_bytes(self, count):
        return self.__piece(count)

    def read_int(self):
        return struct.unpack('<I', self.__piece(4))[0]

    def read_long(self):
        return struct.unpack('<Q', self.__piece(8))[0]

    def read_short(self):
        return struct.unpack('<H', self.__piece(2))[0]

    def read_float(self):
        return struct.unpack('<f', self.__piece(4))[0]

    def read_byte(self):
        return struct.unpack('<B', self.__piece(1))[0]

    def read_ptr_unicode(self):
        addr = self.read_pointer()
        return read_unicode_str(self.data, addr) if addr != 0 else None

    def read_str(self, length):
        return struct.unpack('<'+str(length)+'s', self.__piece(length))[0]

    def write_bytes(self, data):
        if not isinstance(data, str):
            data = struct.pack('B',data)
        self.file.write(data)
        self.file.flush()

    def write_unsigned_leb128(self, num, pos=0):
        if pos != 0:
            self.set_position(pos)
        for _ in xrange(5):
            out = num & 0x7f
            if out != num:
                out |= 0x80
                num = num >> 7
                self.write_bytes(out)
            else:
                self.write_bytes(out)
                break
    '''
    def write_bytes(self, data, pos):
        self.set_position(pos)
        self.file.write(data)
    '''


## StringStream

class StringStream(Stream):
    def __init__(self, data):
        Stream.__init__(self)
        if isinstance(data, str):
            self.data = data
        else:
            print type(data)
            self.data = str(data)
        self.len = len(data)
        self.pos = 0

    def __piece(self, count):
        self.pos += count
        return  self.data[self.pos - count: self.pos]

    def __len__(self):
        return self.len

    def find_onlyone_pos(self, key):
        ret = self.data.find(key)

        if ret == -1:
            raise Exception('can not find onlyone pos for key ' + repr(key) )
        elif self.data.find(key, ret+len(key)) != -1:
            raise Exception('there are many pos of key ' + repr(key) )

        return ret 

    def get_data(self):
        return self.data

    def get_position(self):
        return self.pos

    def set_position(self, pos):
        old = self.pos
        self.pos = pos
        return old

    def skip(self, count):
        self.pos += count

    def has_more(self):
        return self.pos < len(self.data)

    def read_bytes(self, count):
        return self.__piece(count)

    def read_int(self):
        return struct.unpack('<I', self.__piece(4))[0]

    def read_long(self):
        return struct.unpack('<Q', self.__piece(8))[0]

    def read_short(self):
        return struct.unpack('<H', self.__piece(2))[0]

    def read_float(self):
        return struct.unpack('<f', self.__piece(4))[0]

    def read_byte(self):
        return struct.unpack('<B', self.__piece(1))[0]

    def read_ptr_unicode(self):
        addr = self.read_pointer()
        return read_unicode_str(self.data, addr) if addr != 0 else None

    def read_str(self, length):
        tmp = self.__piece(length)
        ret = ''
        try:
            ret = struct.unpack('<'+str(length)+'s', tmp)[0]
        except:
            print type(tmp), repr(tmp), len(tmp)
            return tmp

        return ret
        

if __name__ == '__main__':
    f = FileStream('./test.txt')
    f.write_unsigned_leb128(0x10001)
        