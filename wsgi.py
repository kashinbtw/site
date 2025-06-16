import sys
path = '/home/txshnxtv/mysite'
if path not in sys.path:
    sys.path.append(path)

from main import app as application 