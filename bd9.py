import os, re
root = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(root, 'blockchain.py'), encoding='utf-8').read()
# find top-level class/def start lines
pat = re.compile(r'^((?:class|def) .+)\n', re.M)
for m in pat.finditer(src):
    ln = src[:m.start()].count('\n') + 1
    if 2700 <= ln <= 2950:
        print(f'{ln:5} {m.group(1)[:60]}')
