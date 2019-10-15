# -*- coding: utf-8 -*-
import pkg_resources
import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from supervisor.compat import as_string
import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
def main(out=sys.stdout):
    config = pkg_resources.resource_string(__name__, 'skel/sample.conf')
    out.write(as_string(config))

# main()
