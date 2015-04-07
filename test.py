
import os
from base_unpack import * 

if __name__ == '__main__':

    shell = 'tencent'
    input_dir = '%s_test/input' % shell
    output_dir = '%s_test/output' % shell
    crash_file = '%s_test/crash.txt' % shell

    debug = False
    for root, dir, files in os.walk(input_dir):
        crash = open(crash_file, 'w')
        apk = None
        for name in files:
            if not name.endswith( '.apk' ):
                continue
            try:
                apk = Tencent( os.path.join( root, name), output_dir)
                apk.decrypt()
            except Exception as e:
                crash.write(name + '\n')
                print ' [ERROR] %s' % str(e)
                
