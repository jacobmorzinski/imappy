#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

__author__ = 'Jacob Morzinski'
__email__ = 'jmorzins@mit.edu'
__version__ = '0.1.0'

import os
import sys
import getpass
import imapclient
import imapclient.six as six
import copy
import email
import base64
import re

try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
from imapclient.config import parse_config_file, create_client_from_config

import HTMLParser


class MyHTMLParser(HTMLParser.HTMLParser):
    def __init__(self):
        self.reset()
        self.mydata = ""
        self.mytags = []
    def handle_starttag(self, tag, attrs):
        self.mytags.append(tag)
    def handle_data(self, data):
        # remove runs of whitespace, and at start+end
        data = re.sub(r'\s+', ' ', data)
        data = data.strip()
        self.mydata += data
    def clean(self):
        self.mydata = ""
        self.mytags = []


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
    


class IMAPPYClient(imapclient.IMAPClient):

    def select_folder(self, folder, readonly=False):
        self.folderdata = \
            super(IMAPPYClient,self).select_folder(folder, readonly)
        self.foldername = folder
        return self.folderdata
        

    def get_bodies(self,uids):
        """Fragile if the folder changes while we work on it."""
        self.bodies = {}
        # Do this in small batches of uids, using a scratch copy
        # of the list which is deleted to track progress.
        uids = copy.copy(uids)
        print("Getting %d body data." % len(uids), end="", file=sys.stderr)
        while (uids):
            print(".", end="", file=sys.stderr)
            uidlist = uids[:50]
            del(uids[:50])
            data = self.fetch(uidlist,['BODY','INTERNALDATE'])
            for _,k in enumerate(data):
                self.bodies[k] = data[k]
        print(".ok", file=sys.stderr)
        print("Got %d bodies." % len(self.bodies), file=sys.stderr)


    def analyze_bodies(self,uids=None):
        if (uids is not None):
            self.get_bodies(uids)
        self.candidates = {}
        print("Checking %d bodies." % len(self.bodies),
              end="", file=sys.stderr)
        for i,k in enumerate(self.bodies):
            if (i % 50 == 0):
                print(".", end="", file=sys.stderr)
            
            b = self.bodies[k]['BODY']

            if has_smimep7m(b):
                self.candidates[k] = self.bodies[k]
                # Fetch and merge envelope data (for UID number k)
                # It's fine to overwrite duplcate keys (like SEQ)
                env = self.fetch(k,'ENVELOPE')
                for key in env[k].keys():
                    self.candidates[k][key] = env[k][key]
                
        print(".ok", file=sys.stderr)
        print("Found %d smime.p7m candidates." % len(self.candidates),
              file=sys.stderr)


    def print_candidate_summary(self, uid):
        """Print a summary of a candidate,
        indexed by uid (its key in the dict of candidates)."""
        envelope = self.candidates[uid]['ENVELOPE']
        d = envelope[0]
        s = envelope[1]
        f = "{0} <{2}@{3}>".format( *(envelope[2][0][0:4]))
        t = "{0} <{2}@{3}>".format( *(envelope[5][0][0:4]))
        print("Date: {}\nSubject: {}\nFrom: {}\nTo: {}".format(d,s,f,t))

    # DANGER DANGER doesn't have enough error handling
    # Don't call it from wrong folder, without proper preparation, etc.
    # Whoah wait I don't want to store hundreds of messages in-memory.
    def fetch_rfc822(self, uids):
        """Fetches RFC822 data for messages in self.candidates"""
        self.rfc822 = {}
        total = 0
        count = len(self.candidates)
        print("Downloading %d full messages." % count,
              end="", file=sys.stderr)
        for _,k in enumerate(self.candidates):
            print(".", end="", file=sys.stderr)
            d = self.fetch(k,'RFC822')[k]['RFC822']
            msg = email.message_from_string(d)
            self.rfc822[k] = msg
            total += len(d)
        print(".ok", file=sys.stderr)
        print("Downloaded a total of %d bytes." % total,
              file=sys.stderr)

def doit(c, auid, upload=None, trash=None):
    '''Given a UID, fetch it from the selected folder, convert it,
    upload it to a folder, possibly trash it (copy to trash and flag \Deleted)

    Inputs:
    upload = name of upload folder
    trash = name of trash folder'''

    internaldate = c.candidates[auid]['INTERNALDATE']
    c.fetch_rfc822(auid)
    c.msg = c.rfc822[auid]
    c.msg_new = convert_smimep7m_to_new_email(c.msg)
    
    if upload is not None:
        print("Uploading..", end="",
              file=sys.stderr)
        c.append(upload,c.msg_new.as_string(),msg_time=internaldate)
        print(".done", file=sys.stderr)

    if trash is not None:
        print("Copying to trash.", end="", file=sys.stderr)
        c.copy(auid, trash)
        c.add_flags(auid, r'\Deleted')
        print("..and flagged as deleted, ready for expunge.")

    # ...free memory
    c.rfc822 = {}
    c.msg = ""
    c.msg_new = ""
    return None



#end class IMAPPYClient


def has_smimep7m(b):
    """Simplistic check for smime.p7m attachment.
    Input: a tuple representing a BODY fetch result from imapclient.
    Returns: Boolean true/false."""

    # This is madness!
    # I need a proper parser!
    if (isinstance(b, (tuple,list))
        and isinstance(b[-1], six.string_types)
        and b[-1].lower() == 'mixed'
        and isinstance(b[0], (tuple,list))
        # Ignore other details of first part b[0]
        and isinstance(b[1], (tuple,list))
        and len(b[1]) >= 7
        and isinstance(b[1][0], six.string_types)
        and b[1][0].lower() == 'application'
        and isinstance(b[1][1], six.string_types)
        and b[1][1].lower() == 'octet-stream'
        and isinstance(b[1][2], (tuple,list))
        and isinstance(b[1][2][0], six.string_types)
        and b[1][2][0].lower() == 'name'
        and isinstance(b[1][2][1], six.string_types)
        and b[1][2][1].lower() == 'smime.p7m'
        and isinstance(b[1][5], six.string_types)
        and b[1][5].lower() == 'base64'
        ):
        return True
    else:
        return False



def convert_smimep7m_to_new_email(msg):
    """Input: a mmessage of type <email.message.Message>
    Output: a new <email.message.Message>,
            constructed from the smime.p7m attachment of the input message"""

    # Paranoia checks.  Prior stages should already have assured these.
    if not msg.is_multipart():
        raise Exception("message was not multipart")

    p = msg.get_payload(1)        # second part (0-based array index)
    ct = p.get_content_type()
    if (ct.lower() != 'application/octet-stream'):
        raise Exception("attachment was not application/octet-stream")

    name = p.get_param('name')
    if (name.lower() != 'smime.p7m'):
        raise Exception("attachment was not named smime.p7m")
    
    smime_p7m = p.get_payload()
    converted = base64.b64decode(smime_p7m)

    # The converted data will be the payload of a new Message,
    # with the headers copied from the original message.

    msg_new = email.message_from_string(converted)

    saved_content_type = msg_new['Content-Type']

    # delete converted headers (if any)
    for _,(k,v) in enumerate(msg_new.items()):
        del(msg_new[k])

    # copy in original headers
    for _,(k,v) in enumerate(msg.items()):
        msg_new[k] = v

    if saved_content_type is not None:
        msg_new.replace_header('Content-Type',saved_content_type)

    # If we wanted to be awesome,
    # we would get some text/* payloads from msg_new
    # and compare to the first text/* payload from msg
    # to see if they are related or of we just unpacked dud.

    return msg_new




h = {}                          # host dict
u = {}                          # user dict
c = None                        # connection
folders = []
folder_del = 'Deleted Items'
folder_src = ''
folder_dest = ''

def do_login(conf_file="~/Private/.imappy-exchange.ini"):
    global h
    global u
    global c
    global folders
    h,u = get_conf(conf_file)
    c = IMAPPYClient(**h)
    c.login(**u)
    folders = [f[2] for f in c.list_folders()]
    return c
    


    
def main():
    """
Usage:
import imappy
import email

h,u = imappy.get_conf( '~/Private/.imappy-exchange.ini' )
###(possibly enter password)
c = imappy.IMAPPYClient(**h)
c.login(**u)
folders = [f[2] for f in c.list_folders()]
folder_del = 'Deleted Items'
folder_src = 'test-from-outlook'
folder_dest = 'new-upload'
c.select_folder(folder_src)

### start finding canditates
uids = c.search('all')
c.get_bodies(uids)              # result in c.bodies
c.analyze_bodies()              # result in c.candidates

cuids = c.candidates.keys()

first = cuids[0:1]

for auid in first:
    imappy.doit(c, auid, upload=folder_dest, trash=folder_del)


#mostly done

#to see what will be expunged
c.search('deleted')

c.expunge()


############################################################

# could check structure with   email.iterators._structure(msg_new)

msg.get_payload(0).get_payload()
msg_new.get_payload(0).get_payload(0).get_payload()
msg_new.get_payload(0).get_payload(1).get_payload(0).get_payload()

p = msg.get_payload(0)

(mt,st) = (p.get_content_maintype() , p.get_content_subtype())
for subpart in email.iterators.typed_subpart_iterator(msg, mt, st):
    pl = subpart.get_payload(decode=True)
    break

for subpart in email.iterators.typed_subpart_iterator(msg_new,mt,st):
    pl_new = subpart.get_payload(decode=True)
    break

if text/html:
parser = imappy.MyHTMLParser()
parser.feed(pl)
pl_text = parser.mydata
pl_tags = parser.mytags
parser.clean()
parser.feed(pl_new)
pl_text_new = parser.mydata
pl_tags_new = parser.mytags
parser.clean()
pl_tags == pl_tags_new
pl_text == pl_text_new


############################## 

"""
    print ("hi")


if __name__ == '__main__':
    main()




#!/usr/bin/env python
# -*- coding: utf-8 -*-

# # Body types
# 
# body            = "(" (body-type-1part / body-type-mpart) ")"
# 
# body-type-1part = (body-type-basic / body-type-msg / body-type-text)
#                   [SP body-ext-1part]
# body-type-mpart = 1*body SP media-subtype
#                   [SP body-ext-mpart]
# 
# body-type-basic = media-basic SP body-fields
#                     ; MESSAGE subtype MUST NOT be "RFC822"
# body-type-msg   = media-message SP body-fields SP envelope
#                   SP body SP body-fld-lines
# body-type-text  = media-text SP body-fields SP body-fld-lines
# 
# body-fields     = body-fld-param SP body-fld-id SP body-fld-desc SP
#                   body-fld-enc SP body-fld-octets
# 
# media-basic     = ((DQUOTE ("APPLICATION" / "AUDIO" / "IMAGE" /
#                   "MESSAGE" / "VIDEO") DQUOTE) / string) SP
#                   media-subtype
# media-message   = DQUOTE "MESSAGE" DQUOTE SP DQUOTE "RFC822" DQUOTE
# media-text      = DQUOTE "TEXT" DQUOTE SP media-subtype
# media-subtype   = string
# 
# #recognize body-type-basic:
# tuple[0] is string, tuple[1] is string, tuple[23456] is body-fields
# #recognize body-type-msg:
# tuple[0] is "message", tuple[1] is "rfc822", tuple[23456] is body-fields, tuple[7] is enveope(tuple), tuple[8] is body(tuple), tuple[9] is number
# # recognize body-type-text:
# tuple[0] is "text", tuple[1] is string, tuple[23456] is body-fields, tuple[7] is number
# 
# # recognize body-type-mpart
# tuple[0] is body(tuple), tuple[..etc..] is body(tuple), tuple[..finally..] is string

