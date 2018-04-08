import bs4
import mistletoe
from git import Repo, InvalidGitRepositoryError
from tqdm import tqdm
from colorama import init, Fore
init(autoreset=True)

import pathlib
import os
import sys
import subprocess
import re

def code_occurences_in_file(f):
    with open(f, 'r') as f:
        rendered = mistletoe.markdown(f)
    parsed = bs4.BeautifulSoup(rendered, 'html.parser')
    for c in parsed.find_all('code'):
        if 'class' in c.attrs and 'lang-sc' in c.attrs['class']:
            contents = list(c.children)[0]
            yield '\n'.join(l + '       ' for l in contents.splitlines())

def tracked_files_in_repo(r):
    repo = Repo(str(r))
    tracked_files = [e[0] for e in repo.index.entries]
    for f in child.rglob('*'):
        if str(f.relative_to(child)) in tracked_files:
            yield f

def search_file_for_contents(haystack, needle):
    searchable_haystack = re.sub(chopper, '', haystack)
    searchable_needle = re.sub(chopper, '', needle)
    return searchable_needle in searchable_haystack

chopper = re.compile(r'(^\s+)|(\s+$)', re.MULTILINE)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: %s <angr root> <file paths>' % sys.argv[0])
        sys.exit(1)

    angr_root = pathlib.Path(sys.argv[1])
    files = sys.argv[2:]

    needles = []
    needle_file_map = {}
    for f in files:
        file_needles = list(code_occurences_in_file(f))
        for i, n in enumerate(file_needles):
            if n not in needle_file_map:
                needle_file_map[n] = []
            needle_file_map[n].append((f, i))
        needles.extend(file_needles)

    if len(needles) == 0:
        print('No code found.')
        sys.exit(0)

    needle_status = {n : False for n in needles}

    for child in tqdm(list(angr_root.iterdir())):
        if child.is_dir():
            try:
                for f in tracked_files_in_repo(child):
                    try:
                        haystack = f.open().read()
                    except UnicodeDecodeError:
                        continue
                    for needle, is_found in needle_status.items():
                        if not is_found:
                            needle_status[needle] = search_file_for_contents(haystack, needle)
            except InvalidGitRepositoryError:
                continue

    error_found = False
    for needle, was_found in needle_status.items():
        if not was_found:
            bad_files = needle_file_map[needle]
            for f, occurence in bad_files:
                print(Fore.RED + 'Out of date code at %dth code excerpt in file %s' % (occurence+1, f))
                error_found = True


    if not error_found:
        print(Fore.GREEN + 'No out of date code found!')
    else:
        sys.exit(1)
