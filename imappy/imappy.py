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

