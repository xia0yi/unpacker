#coding=utf-8
'''
Create on 2015-03-26

@author: coolyi
'''

import os
import hashlib
from base_stream import *
from collections import defaultdict
from time import time
from zipfile import ZipFile

def keep_old_position(f):
    ''' just use for Tencent class '''
    def wrapper(self, index):
        old_positon = self.classes_dex.get_position()
        ret = f(self, index)
        self.classes_dex.set_position(old_positon)
        return ret
    return wrapper

class Tencent(ZipFile):
    def __init__(self, apk, outdir=None, outname=None):
        ZipFile.__init__(self, apk)

        with open(apk, 'rb') as f:
            sha1obj = hashlib.sha1()
            sha1obj.update(f.read())
            self.sha1 = sha1obj.hexdigest()

        self.outdir = outdir if outdir != None else os.path.join(os.path.dirname(self.filename))
        self.outname = outname if outname else 'tencent_%s.dex' % (self.sha1) 

        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

        self.__total = 0
        self.sections = defaultdict(dict)
        self.classes_dex = StringStream( self.read('classes.dex') )
        self.new_classes_dex = FileStream(os.path.join(self.outdir, self.outname))
        self.new_classes_dex.write_bytes(self.classes_dex.get_data())

        add_attr = lambda pos, attr : (self.classes_dex.set_position(pos), setattr(self, attr, self.classes_dex.read_int()))

        add_attr(56, 'string_ids_size')
        add_attr(60, 'string_ids_off')
        add_attr(68, 'type_ids_off')
        add_attr(84, 'field_ids_off')
        add_attr(92, 'method_ids_off')
        add_attr(76, 'proto_ids_off')
        add_attr(100, 'class_defs_off')
        add_attr(48, 'link_off')
        add_attr(32, 'file_size')
        add_attr(104, 'data_size')
        add_attr(108, 'data_off')

        self.__read_encode_sections()

    def decrypt(self):
        print 'begin to unpack %s ...' % self.sha1, 
        begin = time()

        for class_defs_idx, methods in self.sections.iteritems():
            class_def = self.__get_class_data_by_index(class_defs_idx)

            ''' skip fields '''
            self.classes_dex.set_position(class_def['class_data_off'])
            class_data = self.__get_class_data()
            self.classes_dex.skip_unsigned_leb128(class_data['static_field_size'] * 2)
            self.classes_dex.skip_unsigned_leb128(class_data['instance_field_size'] * 2)

            ''' check and fix method '''
            self.__check_method_to_fix(class_data['direct_method_size'], methods)
            self.__check_method_to_fix(class_data['virtual_method_size'], methods)

        print ' [OK] %.2fms, total %s methos fix' % ((time()-begin)*1000, self.__total)

    def __check_method_to_fix(self,size, methods):
        method_idx = 0
        for i in xrange(size):
            if len(methods) == 0:
                break
            method = self.__get_class_method()
            method_idx += method['method_idx_diff']
            if method_idx in methods:
                method_id = self.__get_method_id_by_index(method_idx)
                if method_id['proto_idx'] in methods[method_idx]:
                    self.__fix_method(method['method_fix_off'], methods[method_idx][method_id['proto_idx']])
                    self.__total += 1
                    del(methods[method_idx])

    def __fix_method(self, pos, method):
        self.new_classes_dex.set_position(pos)
        self.new_classes_dex.write_unsigned_leb128(method['method_access_flags'])
        self.new_classes_dex.write_unsigned_leb128(method['method_code_off'])

    @keep_old_position
    def __get_method_id_by_index(self, index):
        ret = {}
        self.classes_dex.set_position(self.method_ids_off + index*8)
        ret['class_idx'] = self.classes_dex.read_short()
        ret['proto_idx'] = self.classes_dex.read_short()
        ret['name_idx'] = self.classes_dex.read_int()
        return ret

    def __get_string_by_method_idx(self, index):
        name_idx = self.__get_method_id_by_index(index)['name_idx']
        return self.__get_string_by_index(name_idx)
    
    def show_strings(self):
        for index in xrange(self.string_ids_size):
            print self.__get_string_by_index(index)

    def __get_class_method(self):
        method = {}
        method['method_idx_diff'] = self.classes_dex.read_unsigned_leb128()
        method['method_fix_off'] = self.classes_dex.get_position()
        method['access_flags'] = self.classes_dex.read_unsigned_leb128()
        method['code_off'] = self.classes_dex.read_unsigned_leb128()
        return method

    def __get_class_data(self):
        item = {}
        item['static_field_size'] = self.classes_dex.read_unsigned_leb128()
        item['instance_field_size'] = self.classes_dex.read_unsigned_leb128()
        item['direct_method_size'] = self.classes_dex.read_unsigned_leb128()
        item['virtual_method_size'] = self.classes_dex.read_unsigned_leb128()
        return item

    def __get_class_data_by_index(self, index):
        self.classes_dex.set_position(self.class_defs_off + index*0x20)

        ret = {}
        ret['class_idx'] = self.classes_dex.read_int()
        self.classes_dex.skip(20)
        ret['class_data_off'] = self.classes_dex.read_int()
        return ret

    @keep_old_position
    def __get_string_by_type_idx(self, index):
        self.classes_dex.set_position(self.type_ids_off + index*4)
        return self.__get_string_by_index(self.classes_dex.read_int())

    #@keep_old_position
    def __get_string_by_index(self, index):
        self.classes_dex.set_position(self.string_ids_off + index*4)
        string_data_off = self.classes_dex.read_int()
        self.classes_dex.set_position(string_data_off)
        string_len = self.classes_dex.read_unsigned_leb128()
        return self.classes_dex.read_str(string_len)

    def __read_encode_sections(self):
        pos = self.data_off + self.data_size
        self.classes_dex.set_position(pos)
        total = (self.file_size - pos) / 0x12
        for _ in xrange(total):
            class_defs_idx = self.classes_dex.read_int()
            method_ids_idx = self.classes_dex.read_int()
            method_access_flags = self.classes_dex.read_int()
            method_code_off = self.classes_dex.read_int()
            proto_idx = self.classes_dex.read_short()
            if method_ids_idx not in self.sections[class_defs_idx]:
                self.sections[class_defs_idx][method_ids_idx] = defaultdict(dict)
            self.sections[class_defs_idx][method_ids_idx][proto_idx] = {'method_access_flags' : method_access_flags,
                    'method_code_off' : method_code_off}

    def show_sections(self):
        for cls, methods in self.sections.iteritems():
            for method_idx, protos in methods.iteritems():
                for proto_idx, value in protos.iteritems():
                    print ('%s --- %s --- %d --- %s') % (self.__get_string_by_type_idx(cls),
                        self.__get_string_by_method_idx(method_idx), proto_idx, str(value))
            print '-------------------------------------------------------------------------------------------'
    
    def print_init_info(self):
        self.show_sections()

if __name__ == '__main__':
    t = Tencent('./tencent.apk')
    t.decrypt()
    #t.show_sections()
    #t.show_strings()
