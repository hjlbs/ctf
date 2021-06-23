import random
import os
import struct

## uid, ## note text

adj = [b'faint', b'satisfying', b'reminiscent', b'equable', b'knowing', b'new', b'fancy', b'temporary', b'divergent', b'few', b'painful', b'smiling', b'normal', b'melted', b'billowy', b'quirky', b'grey', b'evanescent', b'needy', b'lovely', b'godly', b'different', b'loving', b'educated', b'seemly', b'agonizing', b'helpless', b'yellow', b'spurious', b'fierce', b'inquisitive', b'demonic', b'flagrant', b'level', b'exuberant', b'gruesome']

nouns = [b'door', b'locket', b'wealth', b'basket', b'pocket', b'account', b'governor', b'oatmeal', b'system', b'kitty', b'record', b'roof', b'cast', b'robin', b'tank', b'actor', b'cap', b'achiever', b'writing', b'bee', b'love', b'approval', b'pizza', b'work', b'flock', b'heat', b'stretch', b'hill', b'meat', b'quiet']

verbs = [b'excused', b'attempted', b'bared', b'subtracted', b'fastened', b'chocked', b'programmed', b'hoped', b'attached', b'tamed', b'whirled', b'dared', b'educated', b'muddled', b'touched', b'faced', b'injected', b'entertained', b'wriggled', b'replaced', b'lied', b'filled', b'knocked', b'prevented', b'shocked', b'entered', b'amused', b'explained', b'united', b'ruined']

data = b''

uid = int(os.getuid())

for i in range(100):
    ## add uid
    data += struct.pack('I', uid) + b'\n'

    ## create message
    msg = b'The ' + random.choice(adj) + b' ' + random.choice(nouns) + b' ' + random.choice(verbs) + b' the ' + random.choice(adj) + b' ' + random.choice(nouns) + b'.\n'

    data += msg
    print(msg)

f = open('notes', 'wb')
f.write(data)
f.close()
