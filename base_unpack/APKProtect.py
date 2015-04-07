#coding=utf-8
'''
Create on 2015-01-08

@author: coolyi
'''

import os
import hashlib
from base_stream import *
from zipfile import ZipFile

class APKProtect(ZipFile):
    '''
    give me a apk file 
    '''
    def __init__(self, apk, outdir=None, outname=None):
        ZipFile.__init__(self, apk)

        f = open(apk, 'rb')
        sha1obj = hashlib.sha1()
        sha1obj.update(f.read())
        self.sha1 = sha1obj.hexdigest()
        f.close()

        self.outdir = outdir if outdir != None else os.path.join(os.path.dirname(self.filename))
        self.outname = outname if outname else 'apkprotect_%s.dex' % (self.sha1) 

        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

        self.classes_dex = StringStream( self.read('classes.dex') )
        self.libAPKProtect_so = StringStream( self.read('lib/armeabi/libAPKProtect.so') )
        self.sections = []

        self.new_classes_dex = FileStream( os.path.join( self.outdir, self.outname ) )

    def check_real_protect(self):
        if len(self.libAPKProtect_so) == 0x41c0:
            self.new_classes_dex.write_bytes( self.read('classes.dex') )
            return False
        return True

    def read_decrypt_section(self):
        '''
        read decrypt structure in so for dectypting
        '''
        section_offet = 0x4028
        self.libAPKProtect_so.set_position(section_offet)

        while True:
            sec = {}
            sec['decrypt_dex_offset'] = self.libAPKProtect_so.read_int()
            sec['decrypt_dex_size'] = self.libAPKProtect_so.read_int();
            '''
            here make key to be a StringSream is just easy for read when decrypt
            '''
            sec['decrypt_key'] = StringStream(self.libAPKProtect_so.read_str(16))

            if sec['decrypt_dex_offset'] == 0:
                break

            self.sections.append(sec)

    def decrypt_dex(self):
        self.classes_dex.set_position( 0 )

        for sec in self.sections:
            data = self.classes_dex.read_bytes( sec['decrypt_dex_offset'] - self.classes_dex.get_position() - 12 )
            self.new_classes_dex.write_bytes( data )
            self.new_classes_dex.write_bytes( '\0' * 12 )
            self.classes_dex.skip( 12 )

            keys = sec['decrypt_key']

            for count in range( sec['decrypt_dex_size'] ):
                keys.set_position( count & 0x0f )
                try:
                    self.new_classes_dex.write_bytes( '%c' % ( self.classes_dex.read_byte() ^ keys.read_byte()) )
                except:
                    raise Exception('size %d, %d, pos %d, %d' % ( len(self.classes_dex), len(self.new_classes_dex), self.classes_dex.get_position(), self.new_classes_dex.get_position() ) )

            self.new_classes_dex.skip( -12 )
            self.new_classes_dex.write_bytes( '\0' * 12 )

        data = self.classes_dex.read_bytes( len( self.classes_dex ) - self.classes_dex.get_position() )
        self.new_classes_dex.write_bytes( data )

    def decrypt(self):
        if self.check_real_protect():
            self.read_decrypt_section()
            self.decrypt_dex();

    def print_init_info(self):
        if len(self.sections) == 0:
            print ('%s has no real protect') % (self.filename)
            return 

        print 'sha1: %s' % ( self.sha1 )
        print 'libAPKProtect_so: 0x%x bytes' % ( len(self.libAPKProtect_so) )
        print 'classes.dex: 0x%x bytes' % ( len(self.classes_dex) )
        print 'section_offet = 0x4028(default)'
        print 'decrypt sections: %s' % ( len(self.sections) )

        for sec in self.sections:
            sec['decrypt_key'].set_position(0)
            print ('\tdecrypt_dex_offset: 0x%x\tdecrypt_size: 0x%x\tdecrypt_key: %s') % ( sec['decrypt_dex_offset'], \
                    sec['decrypt_dex_size'], repr(sec['decrypt_key'].read_bytes(16)) )




if __name__ == '__main__':
    '''
    apk = APKProtect('nani.apk')
    apk.decrypt()
    apk.print_init_info()
    '''

