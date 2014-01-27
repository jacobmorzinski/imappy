#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

__author__ = 'Jacob Morzinski'
__email__ = 'jmorzins@mit.edu'
__version__ = '0.1.0'

import os
import getpass
try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
from imapclient.config import parse_config_file, create_client_from_config

class Message(object):
    """
    A Message that knows where it came from and what it is doing.
    """

    def __init__(self, server='', folder='',
                 uidvalidity='', uid='',
                 message=None):
        """Create a Message that knows where it came from."""
        self.server = server
        self.folder = folder
        self.uidvalidity = uidvalidity
        self.uid = uid
        self.message = message

    def __repr__(self):
        return repr((self.server,
                     self.folder,
                     self.uidvalidity,
                     self.uid,
                     self.message
                     ))

    def __str__(self):
        fmt = "Server: {}\nFolder: {}\nuidvalidity: {}\nuid: {}\n\n"
        temp = fmt.format(self.server, self.folder, self.uidvalidity, self.uid)
        temp += str(self.message)
        return(temp[:1000])

def get_conf(conf_file='~/.imappy.ini'):
    global config
    conf_file = os.path.expanduser(conf_file)
    config = SafeConfigParser()
    config.read(conf_file)
    section = 'main'
    username = config.get(section,'username')
    if (config.has_option(section,'password')):
        password = config.get(section,'password')
    else:
        password = getpass.getpass("Password for {} : ".format(username))
        config.set(section,'password',password)
    section = 'main'
    host = config.get(section,'host')
    ssl = config.get(section,'ssl')
    return (dict(host=host, ssl=ssl),
            dict(username=username, password=password))
    
def find_candidates(uids,conn,folder=''):
    global candidates
    candidates = {}
    # possibly do this 50 uids at a time
    while (uids):
        print(".", end="")
        uidlist = uids[:50]
        del(uids[:50])
        data = conn.fetch(uidlist,['BODY','INTERNALDATE'])
        for _,k in enumerate(data):
            candidates[k] = data[k]
    print("Got bodystructs")



# if __name__ == '__main__':
#     main()
"""
Usage:

import imapclient
import imappy
h,u = imappy.get_conf( '~/Private/.imappy-exchange.ini' )
###(possibly enter password)
c = imapclient.IMAPClient(**h)
c.login(**u)
folders = [f[2] for f in c.list_folders()]
f_src = 'test-from-outlook'
folderinfo = c.select_folder(f_src)

### start finding canditates
uids = c.search()

imappy.find_candidates(uids)

"""
