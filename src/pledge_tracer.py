import subprocess
import sys
import re
from collections import defaultdict
import argparse
import os
import fnmatch

from queue import Queue

access_legend = {
    'read': 'R',
    'write': 'W',
    'mmap': 'P',
    'mmapsh': 'S',
    'getdents64': 'D',
    'stat': 'M',
    'create': 'C',
    'enoent': 'E',
    'exec': 'X',
}

cwd = None
indent_block = "    "

# given a list of filenames, return a glob pattern that matches all of them
def inverse_glob(names, force_single_asterisk=None):
    glob_strings = []
    
    # group common substrings
    match_groups = []
    while len(names):
        n = names.pop(0)
        n_matches = [n]
        for match in names.copy():
            common = ''
            for i, c in enumerate(n):
                if i < len(match) and c == match[i]:
                    common += c
                else:
                    break
            if common:
                n_matches.append(match)
                names.remove(match)
        match_groups.append(n_matches)

    for names in match_groups:
        def adjust_name(pp, diff):
            if len(pp) == 2:
                return pp[0][:-diff] + '?'*(diff+1) + '.' + pp[1]
            else:
                return pp[0][:-diff] + '?' * (diff + 1)

        glob_string = names.pop(0)

        while len(names):
            f1 = glob_string
            f2 = names.pop(0)
            l1 = len(f1); l2 = len(f2)
            if l1 > l2:
                f2 = adjust_name(f2.split('.'), l1-l2)
            elif l2 > l1:
                f1 = adjust_name(f1.split('.'), l2-l1)

            result = ['?' for n in range(len(f1))]
            for i, c in enumerate(f1):
                if len(f2) <= i:
                    break
                if c == f2[i]:
                    result[i] = c

            result = ''.join(result)
            
            if fnmatch.fnmatch(f2, glob_string):
                continue
            
            glob_string = re.sub(r'\?{2,}', '*', result)
            #glob_string = re.sub(r'\*.+\*', '*', glob_string)
        glob_strings.append(glob_string)
    return glob_strings

class FileAccessNode:
    def __init__(self, filename):
        self.filename = filename
        self.modes = set()
        self.read_offsets = []
        self.write_offsets = []
        self.mmap_access = []
        self.getdents = False
        self.num_accesses = 0
        self.total_bytes_read = 0 
        self.st_size = 0
        self.num_opens = 0
        self.num_reads = 0
        self.num_writes = 0
        self.num_stats = 0
        self.num_mmaps = 0
        self.num_mmapsh = 0
        self.num_getdents = 0
        self.num_creates = 0
        self.num_enoent = 0
        self.num_exec = 0
        self.read_perm = False
        self.write_perm = False
        self.exec_args = []


    def add_access(self, mode, offset=None, length=None):
        self.modes.add(mode)
        self.num_accesses += 1
        if mode == 'read':
            if offset is not None:
                self.read_offsets.append((offset, length))
            if length is not None:
                self.total_bytes_read += length  
            self.num_reads += 1
        elif mode == 'write' and offset is not None:
            self.write_offsets.append((offset, length))
            self.num_writes += 1
        elif mode == 'mmap' and offset is not None:
            self.mmap_access.append((offset, length))
        elif mode == 'getdents64':
            self.getdents = True
        elif mode == 'stat':
            self.num_stats += 1
        elif mode == 'enoent':
            self.num_enoent += 1
        elif mode == 'mmap':
            self.num_mmaps += 1
        elif mode == 'mmapsh':
            self.num_mmapsh += 1
        elif mode == 'exec':
            self.num_exec += 1
        elif mode == 'create':
            self.num_creates += 1

    def access_pattern(self):
        patterns = []
        if self.read_offsets:
            offsets = [o for o, l in self.read_offsets]
            if self.is_sequential(offsets):
                patterns.append('sequential read')
            else:
                patterns.append('random read')
        if self.write_offsets:
            offsets = [o for o, l in self.write_offsets]
            if self.is_sequential(offsets):
                patterns.append('sequential write')
            else:
                patterns.append('random write')
        if self.mmap_access:
            patterns.append('mmap')
        if self.getdents:
            patterns.append('directory listing')
        return patterns

    @staticmethod
    def is_sequential(offsets):
        if len(offsets) < 2:
            return True
        return all(b == a + 1 for a, b in zip(offsets, offsets[1:]))

def run_strace(pid_or_cmd):
    # if pid_or_cmd.isdigit():
    #     cmd = ['strace', '-f', '-y', '--trace=file,read,write,mmap,getdents64,lseek', '-p', pid_or_cmd]
    # else:
    #     cmd = ['strace', '-f', '-y', '--trace=file,read,write,mmap,getdents64,lseek'] + pid_or_cmd.split()

    # strace -f -y --trace=file,read,write,mmap,getdents64,lseek,clone 

    cmd = ['strace', '-f', '-y', '-v', '--trace=file,read,write,mmap,getdents64,lseek,clone'] + pid_or_cmd[0].split(' ')
    print("Running command:", ' '.join(pid_or_cmd))
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    return proc

def parse_strace_output(strace_lines):

    pid_tree = defaultdict(lambda: defaultdict(FileAccessNode))
    pid_dependence_tree = {}
    fd_to_file = {}
    fd_offsets = defaultdict(int)

    open_re = re.compile(
        r'open(?:at)?\([^,]*, "?([^"]+)"?, ([^,)]+)(?:, [^)]*)?\).*?= (\d+)<([^>]+)>'
    )
    read_re = re.compile(r'read\((\d+)<([^>]+)>,.*?, (\d+)\) = (\d+)')
    write_re = re.compile(r'write\((\d+)<([^>]+)>,.*?, (\d+)\) = (\d+)')
    mmap_re = re.compile(r'mmap\((?:.*), (?:.*), (?:.*), (.*), .*<(.*)>, (?:.*)\)')
    getdents_re = re.compile(r'getdents64\((\d+),')
    fd_file_re = re.compile(r'fd (\d+) is ([^ ]+)')
    lseek_re = re.compile(r'lseek\((\d+), (\d+), ([^)]*)\) *= *(\d+)')
    exec_re = re.compile(r'execve\("([^"]+)", \[([^\]]+)\].*= *(?:-?\d+)')
    # 1962296 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3e278aa710) = 1962358

    clone_re = re.compile(r'clone\([^)]*\)\s*=\s*(\d+)')
    clone_partial_re = re.compile(r'clone\(.*strace: Process (\d+) attached')
    
    newfstatat_wsize_re = re.compile(
        r'newfstatat\((?:AT_FDCWD|.?)<(.*)>,.?\"(.*)\"(?:(?:.*)|(?:st_size=(.*)),.*)= -?[0-9]'
    )

    stat_or_lstat = re.compile(
        r'l?stat\(\"(.*)\"(?:(?:.*)|(?:st_size=(.*)),.*)='

    )

    strace_output = open('strace_output.log', 'w')

    incomplete_lines = Queue()
    for line in strace_lines:
        strace_output.write(line)
        # 2677224 mkdirat(AT_FDCWD</tmp/worker-241627-2677224>, "/tmp/worker-241627-2677224", 0777 <unfinished ...>
        # 2677224 <... mkdirat resumed> ) = 0

        pid = line.split(' ')[0]
        if 'pid' in pid:
            # pid = [pid 1234]
            pid = line.split(' ')[1].strip('[]')
        elif not pid.isdigit():
            # For lines without PID prefix, try to find the first PID in the line
            pid_match = re.search(r'^(\d+)', line)
            if pid_match:
                pid = pid_match.group(1)
            else:
                pid = '0'  # fallback for lines without any PID
        
        # Ensure PID is always a string
        pid = str(pid)

        file_tree = pid_tree[pid]  # for single process tracing
        
        if pid not in pid_dependence_tree.keys():
            pid_dependence_tree[pid] = {}


        reconstructed = False

        if ' <unfinished ...>' in line:
            # store the unfinished line and continue
            incomplete_lines.put(line)
            continue
        elif ' <... ' in line:
            # construct the full line
            line_begin = incomplete_lines.get()
            line_end = ''.join(line.split(' resumed>')[1:])
            line = line_begin.replace(' <unfinished ...>', line_end)
            reconstructed = True
            #print("Reconstructed line:", line)

        m = open_re.search(line)
        if m:
            #print("openat")
            requested, flags, fd, filename = m.groups()
            fd_to_file[fd] = filename
            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)

            if 'AT_FDCWD' in line:
                global cwd
                cwd_re = re.search(r'AT_FDCWD<([^>]+)>', line)
                if cwd_re:
                    global cwd
                    if cwd == None:
                        cwd = cwd_re.group(1)

            if 'ENOENT' in line:
                file_tree[filename].add_access('enoent')
                continue
            # Parse access mode from flags
            if 'O_RDONLY' in line:
                file_tree[filename].add_access('read')
                file_tree[filename].read_perm = True
            elif 'O_WRONLY' in line:
                file_tree[filename].add_access('write')
                file_tree[filename].write_perm = True
            elif 'O_RDWR' in line:
                file_tree[filename].add_access('read')
                file_tree[filename].add_access('write')
                file_tree[filename].read_perm = True
                file_tree[filename].write_perm = True
            if 'O_CREAT' in line:
                file_tree[filename].add_access('create')
                    
            continue

        m = fd_file_re.search(line)
        if m:
            #print("fdinfo")
            fd, filename = m.groups()
            fd_to_file[fd] = filename
            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)
            continue

        m = lseek_re.search(line)
        if m:
            #print("lseek")
            fd, offset, _, result = m.groups()
            fd_offsets[fd] = int(result)
            continue

        m = read_re.search(line)
        if m:
            #print("read")
            fd, filename, requested, length = m.groups()
            offset = fd_offsets.get(fd, 0)
            try:
                file_tree[filename].add_access('read', offset, int(length))
                file_tree[filename].total_bytes_read += int(length)
                fd_offsets[fd] = offset + int(length)
            except:
                print(f"Warning: read from unknown file descriptor {fd} ({filename})")
                file_tree[filename] = FileAccessNode(filename)
                file_tree[filename].add_access('read', offset, int(length))
                file_tree[filename].total_bytes_read += int(length)
                fd_offsets[fd] = offset + int(length)
            continue

        m = write_re.search(line)
        if m:
            #print("write")
            fd, filename, requested, length = m.groups()
            offset = fd_offsets.get(fd, 0)
            try:
                file_tree[filename].add_access('write', offset, int(length))
            except:
                #print(f"Warning: write to unknown file descriptor {fd} ({filename})")
                file_tree[filename] = FileAccessNode(filename)
                file_tree[filename].add_access('write', offset, int(length))
            continue

        m = mmap_re.search(line)
        if m:
            #print("mmap")
            #print(m.groups())
            flags, filename = m.groups()
            
            if not filename.startswith('/'):
                # ignore anonymous mappings
                continue
            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)

            if 'MAP_SHARED' in flags:
                file_tree[filename].add_access('mmapsh')
            elif 'MAP_PRIVATE' in flags:
                file_tree[filename].add_access('mmap')

            continue

        m = getdents_re.search(line)
        if m:
            print("getdents64")
            fd = m.group(1)
            filename = fd_to_file.get(fd)
            if filename:
                file_tree[filename].add_access('getdents64')
            continue

        m = newfstatat_wsize_re.search(line)
        if m:
            #print("newfstatat_size")
            #print(line)
            if len(m.groups()) != 3:
                print("Warning: unexpected newfstatat match groups:", m.groups())
                continue

            # depending on the strace version the first or second group may be None
            at_fdcwd, filename, st_size = m.groups() if m.groups()[0] is not None else (m.groups()[1], None, m.groups()[2])
            #print(filename)
            #print(line)

            #if reconstructed:
                #print("Reconstructed line:", line)

            #AT_EMPTY_PATH
            if filename is None:
                continue

            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)
            
            if 'ENOENT' in line:
                file_tree[filename].add_access('enoent')
                #print("enoent")
                #print(filename)
                continue

            #print(filename)
            file_tree[filename].add_access('stat')
            if st_size is not None:
                file_tree[filename].st_size = int(st_size)
            continue

        m = stat_or_lstat.search(line)
        if m:
            #print("stat or lstat")
            #print(line)
       
            if len(m.groups()) != 2:
                print("Warning: unexpected stat or lstat match groups:", m.groups())
                continue

            # depending on the strace version the first or second group may be None
            filename, st_size = m.groups() 
            #print(filename)
            #print(line)

            #AT_EMPTY_PATH
            if filename is None:
                continue

            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)
            
            if 'ENOENT' in line:
                file_tree[filename].add_access('enoent')
                continue
         
            file_tree[filename].add_access('stat')
            if st_size is not None:
                file_tree[filename].st_size = int(st_size)
            continue

        m = exec_re.search(line)
        if m:
            #print("execve")
            filename = m.groups()[0]
            args = list((p.strip('"') for p in m.groups()[1].split(', ')))
            if filename not in file_tree:
                file_tree[filename] = FileAccessNode(filename)
            
            if 'ENOENT' in line:
                file_tree[filename].add_access('enoent')
            else:
                file_tree[filename].add_access('exec')

            file_tree[filename].exec_args = args
            continue

        # newpid = [pid x]
        # oldpid = 

        # Handle clone system calls for tracking process parent-child relationships
        m = clone_re.search(line)
        if m:
            newpid = m.groups()[0]
            if pid not in pid_dependence_tree:
                pid_dependence_tree[pid] = {}
            pid_dependence_tree[pid][newpid] = {}
            #print(f"Clone: parent {pid} -> child {newpid}")
            continue
            
        # Handle partial clone calls with strace process attachment
        m = clone_partial_re.search(line)
        if m:
            newpid = m.groups()[0]
            if pid not in pid_dependence_tree:
                pid_dependence_tree[pid] = {}
            pid_dependence_tree[pid][newpid] = {}
            #print(f"Clone (partial): parent {pid} -> child {newpid}")
            continue

    
    strace_output.close()

    return pid_tree, pid_dependence_tree



def find_parent_pid(pid, pid_dep):
    for parent, children in pid_dep.items():
        if pid in children:
            return parent
    return None

def build_process_tree(pid_dep):
    # Find root processes (those that don't appear as children)
    all_children = set()
    for children in pid_dep.values():
        all_children.update(children.keys())
    
    roots = [pid for pid in pid_dep.keys() if pid not in all_children]
    
    # may reach max recursion depth
    def build_subtree(pid, level=0):
        tree = [(pid, level)]
        if pid in pid_dep:
            for child in sorted(pid_dep[pid].keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
                tree.extend(build_subtree(child, level + 1))
        return tree
    
    full_tree = []
    for root in sorted(roots, key=lambda x: int(x) if str(x).isdigit() else 0):
        full_tree.extend(build_subtree(root))
    
    return full_tree

def print_process_tree(pid_tree, pid_dep):
    """Print a visual representation of the process tree."""
    if not pid_dep:
        return
        
    print("\n#Process Tree:")
    process_tree = build_process_tree(pid_dep)
    
    for pid, level in process_tree:
        if pid in pid_tree and pid_tree[pid]:  # Only show processes that accessed files
            indent = indent_block * level
            # print the executable if available
            executable = []
            for filename, node in pid_tree[pid].items():
                if node.num_exec > 0:
                    executable.append(filename)
            if executable:
                if level == 0:
                    print(f"{indent}├─ PID {pid} (root) [{', '.join(executable)}]")
                    print_file_tree_by_pid(pid, pid_tree, pid_dep, no_pid=False, skip_base_dirs=True, indent_level=level+4)
                else:
                    print(f"{indent}├─ PID {pid} (child) [{', '.join(executable)}]")
                    print_file_tree_by_pid(pid, pid_tree, pid_dep, no_pid=False, skip_base_dirs=True, indent_level=level+4)

    print("CWD: ", cwd)

def print_file_tree(pid_tree, pid_dep, no_pid=False, skip_base_dirs=True, indent_level=0):

    #sort pid dep tree
    # Reorganize pid_dep to handle subprocess relationships
    # pids = list(pid_dep.keys())
    # pid_dep_copy = {}
    # for pid in pids:
    #     for subprocess_pid in pid_dep[pid].keys():
    #         if subprocess_pid in pid_dep:
    #             # Move the subprocess pid entry into the parent's value dict
    #             if pid not in pid_dep_copy:
    #                 pid_dep_copy[pid] = {}
    #             pid_dep_copy[pid][subprocess_pid] = pid_dep[subprocess_pid]


    if no_pid:
        # Merge all pid trees into a single tree under pid '0'
        merged_tree = defaultdict(FileAccessNode)
        for pid in pid_tree:
            file_tree = pid_tree[pid]
            for filename, node in file_tree.items():
                if filename not in merged_tree:
                    merged_tree[filename] = node
                else:
                    # merge access modes and counts
                    existing_node = merged_tree[filename]
                    existing_node.modes.update(node.modes)
                    existing_node.read_offsets.extend(node.read_offsets)
                    existing_node.write_offsets.extend(node.write_offsets)
                    existing_node.mmap_access.extend(node.mmap_access)
                    existing_node.getdents = existing_node.getdents or node.getdents
                    existing_node.total_bytes_read += node.total_bytes_read
                    existing_node.num_reads += node.num_reads
                    existing_node.num_writes += node.num_writes
                    existing_node.num_stats += node.num_stats
                    existing_node.num_mmaps += node.num_mmaps
                    existing_node.num_getdents += node.num_getdents
                    existing_node.num_creates += node.num_creates
                    existing_node.num_enoent += node.num_enoent
                    existing_node.num_mmapsh += node.num_mmapsh
                    existing_node.num_exec += node.num_exec
        # Replace pid_tree with merged tree under pid '0'
        pid_tree = { '0': merged_tree }

    # if there is no exec in a pid merge it with the parent
    if False:  
        pids_to_remove = []
        for pid in pid_tree:
            file_tree = pid_tree[pid]
            has_exec = any(node.num_exec > 0 for node in file_tree.values())
            if not has_exec:
                # find parent pid
                parent_pid = None
                for ppid, children in pid_dep.items():
                    if pid in children:
                        parent_pid = ppid
                        break
                if parent_pid and parent_pid in pid_tree:
                    parent_tree = pid_tree[parent_pid]
                    for filename, node in file_tree.items():
                        if filename not in parent_tree:
                            parent_tree[filename] = node
                        else:
                            # merge access modes and counts
                            parent_node = parent_tree[filename]
                            parent_node.modes.update(node.modes)
                            parent_node.read_offsets.extend(node.read_offsets)
                            parent_node.write_offsets.extend(node.write_offsets)
                            parent_node.mmap_access.extend(node.mmap_access)
                            parent_node.getdents = parent_node.getdents or node.getdents
                            parent_node.total_bytes_read += node.total_bytes_read
                            parent_node.num_reads += node.num_reads
                            parent_node.num_writes += node.num_writes
                            parent_node.num_stats += node.num_stats
                            parent_node.num_mmaps += node.num_mmaps
                            parent_node.num_getdents += node.num_getdents
                            parent_node.num_creates += node.num_creates
                            parent_node.num_enoent += node.num_enoent
                            parent_node.num_mmapsh += node.num_mmapsh
                            parent_node.num_exec += node.num_exec
                    pids_to_remove.append(pid)
        for pid in pids_to_remove:
            pid_tree.pop(pid)

 
    # # Build a directory tree: {dirpath: {filename: node}}
    # # First show the process tree if we have multiple processes
    # if len(pid_tree) > 1 and not no_pid:
    #     print_process_tree(pid_tree, pid_dep)
    
    #print(f"{' ' * indent_level}Access       <Directory>    Count")
    for pid in pid_tree:
        
        file_tree = pid_tree[pid]

        #print(file_tree)

        if not file_tree:
            continue
        
        # if the file tree only contains pipe, anon_inode etc...
        if all('anon_inode' in filename for filename in file_tree.keys()):
            continue


        parent_pid = find_parent_pid(pid, pid_dep)
        # if parent_pid:
        #     print(f"\n#Process ID: {pid} (child of {parent_pid})")
        # else:
        #     print(f"\n#Process ID: {pid} (root process)")
        dir_tree = defaultdict(dict)

        # keep track of number of specific filenames accessed to identify searching patterns
        files_repeat = defaultdict(int)
        rw_mismatch_files = []

        for filename, node in file_tree.items():
            file = filename.split('/')[-1]
            if node.num_enoent > 0:
                files_repeat[file] = files_repeat[file] + 1

            if node.read_perm and node.num_reads == 0:
                rw_mismatch_files.append(filename)
            elif node.write_perm and node.num_writes == 0:
                rw_mismatch_files.append(filename)

            dirpath = os.path.dirname(filename)
            dir_tree[dirpath][filename] = node

        base_list = ['', 'dev', 'proc', 'sys', 'run', 'usr', 'etc', 'common', 'var']

        mid_list = ['miniconda3']
        #mid_list = []

        # Group paths by their root directory
        root_groups = defaultdict(lambda: defaultdict(dict))
        for dirpath, files in dir_tree.items():
            root = dirpath.split('/')[1] if dirpath.startswith('/') else dirpath.split('/')[0]
            if root in base_list:
                root_groups[root][dirpath] = files

        # First handle base_list paths
        for root in sorted(root_groups.keys()):
            total_files = 0
            mode_counts = defaultdict(int)
            access_patterns = defaultdict(int)
            exec_files = []

            for dirpath, files in root_groups[root].items():
                total_files += len(files)
                for fname, node in files.items():
                    #mode_counts['open'] += node.num_opens
                    mode_counts['read'] += node.num_reads
                    mode_counts['write'] += node.num_writes
                    mode_counts['stat'] += node.num_stats
                    mode_counts['mmap'] += node.num_mmaps
                    mode_counts['getdents64'] += node.num_getdents
                    mode_counts['create'] += node.num_creates
                    mode_counts['enoent'] += node.num_enoent
                    mode_counts['mmapsh'] += node.num_mmapsh
                    if node.num_exec > 0:
                        mode_counts['exec'] += node.num_exec
                        exec_files.append(node)
                    for access_pattern in node.access_pattern():
                        access_patterns[access_pattern] += 1
                dir_tree.pop(dirpath)  # Remove printed paths from tree
            if total_files > 0:
                if skip_base_dirs and not exec_files:
                    continue

                # if there are only enoent accesses, skip
                if all(value == 0 for mode, value in mode_counts.items() if mode != 'enoent'):
                    continue

                mode_summary = ', '.join(f"{mode}: {count}" for mode, count in sorted(mode_counts.items()) if count > 0) #+ ', ' + ', '.join(f"{pattern}: {count}" for pattern, count in sorted(access_patterns.items()))
                indent = indent_block * indent_level
                access_chars = ''.join(access_legend[mode] for mode, count in mode_counts.items() if count > 0)
                print(f"{indent}{access_chars} </{root}> ({total_files} files) [{mode_summary}]")
                if exec_files:
                    in_this_subpath = [f for f in exec_files if f.filename.startswith(f'/{root}/')]
                    if in_this_subpath:
                        arg_lists = [f.exec_args for f in in_this_subpath]
                        for args in arg_lists:
                            print(f"{indent*2}#\tExecutable: {' '.join(args)}")

        # Then handle mid_list paths
        for mid in mid_list:
            mid_paths = {dirpath: files for dirpath, files in dir_tree.items() if f'/{mid}' in dirpath}
            if mid_paths:
                total_files = 0
                mode_counts = defaultdict(int)
                access_patterns = defaultdict(int)
                exec_files = []
                mid_abs = f'/{mid}'
                for dirpath, files in mid_paths.items():
                    total_files += len(files)
                    mid_abs = dirpath.split(f'/{mid}')[0] + f'/{mid}'
                    for fname, node in files.items():
                        for mode in node.modes:
                            mode_counts[mode] += 1
                        #mode_counts['open'] += node.num_opens
                        mode_counts['read'] += node.num_reads
                        mode_counts['write'] += node.num_writes
                        mode_counts['stat'] += node.num_stats
                        mode_counts['mmap'] += node.num_mmaps
                        mode_counts['getdents64'] += node.num_getdents
                        mode_counts['create'] += node.num_creates
                        mode_counts['enoent'] += node.num_enoent
                        mode_counts['mmapsh'] += node.num_mmapsh
                        if node.num_exec > 0: 
                                path_modes['exec'] += node.num_exec
                                exec_files.append(node) if node not in exec_files else None
                        for access_pattern in node.access_pattern():
                            access_patterns[access_pattern] += 1

                # if there are only enoent accesses, skip
                if all(value == 0 for mode, value in mode_counts.items() if mode != 'enoent'):
                    continue
                mode_summary = ', '.join(f"{mode}: {count}" for mode, count in sorted(mode_counts.items()) if count > 0) #+ ', ' + ', '.join(f"{pattern}: {count}" for pattern, count in sorted(access_patterns.items()))
                indent = indent_block * indent_level
                access_chars = ''.join(access_legend[mode] for mode, count in mode_counts.items() if count > 0)
                print(f"{indent}{access_chars} <{mid_abs}> ({total_files} files) [{mode_summary}]")
                if exec_files:
                    in_this_subpath = [f for f in exec_files if f.filename.startswith(f'/{mid}/')]
                    if in_this_subpath:
                        arg_lists = [f.exec_args for f in in_this_subpath]
                        for args in arg_lists:
                            print(f"{indent*2}#\tExecutable: {' '.join(args)}")

                # Remove printed paths from tree
                for dirpath in mid_paths.keys():
                    dir_tree.pop(dirpath)

        # Handle remaining paths
        # if a directory is a local reference, find the absolute path in the tree and combine them
        local_refs = {dirpath: files for dirpath, files in dir_tree.items() if not dirpath.startswith('/')}

        #print(local_refs)
        for dirpath, files in local_refs.items():
            # try to find absolute path using cwd from openat calls
            abs_path = os.path.abspath(os.path.join(cwd if cwd else '/', dirpath))
            if abs_path in dir_tree:
                parent_files = dir_tree[abs_path]
                for fname, node in files.items():
                    if fname not in parent_files:
                        parent_files[fname] = node
                    else:
                        # merge access modes and counts
                        parent_node = parent_files[fname]
                        parent_node.modes.update(node.modes)
                        parent_node.read_offsets.extend(node.read_offsets)
                        parent_node.write_offsets.extend(node.write_offsets)
                        parent_node.mmap_access.extend(node.mmap_access)
                        parent_node.getdents = parent_node.getdents or node.getdents
                        parent_node.total_bytes_read += node.total_bytes_read
                        parent_node.num_reads += node.num_reads
                        parent_node.num_writes += node.num_writes
                        parent_node.num_stats += node.num_stats
                        parent_node.num_mmaps += node.num_mmaps
                        parent_node.num_getdents += node.num_getdents
                        parent_node.num_creates += node.num_creates
                        parent_node.num_enoent += node.num_enoent
                        parent_node.num_mmapsh += node.num_mmapsh
                        parent_node.num_exec += node.num_exec
                # Remove local ref from tree
                dir_tree.pop(dirpath)

        
        
        # Group remaining paths by common root
        remaining_groups = defaultdict(lambda: {
            'total_files': 0,
            'mode_counts': defaultdict(int),
            'dirpaths': set()
        })

       
        write_files = []
        read_files = []
        exec_files = []

        # find a description level which isolates access modes per root directory
        for dirpath, files in dir_tree.items():
            if not dirpath:  # Handle root directory case
                root = '/'
                parts = []
            else:
                parts = dirpath.strip('/').split('/')
                root = parts[0]

            # Try different path depths until we find one with ≤2 access modes
            for depth in range(len(parts) + 1):
                current_path = '/' + '/'.join(parts[:depth]) if depth > 0 else '/'
                
                # Only process files under this path
                if not any(dirpath.startswith(current_path) for dirpath in dir_tree.keys()):
                    continue

                # Count access modes at this path level
                path_modes = defaultdict(int)
                path_files = 0
                for check_path, path_files_data in dir_tree.items():
                    if check_path == current_path:
                        path_files += len(path_files_data)
                        for _, node in path_files_data.items():
                            #if node.num_opens > 0: path_modes['open'] += node.num_opens
                            if node.num_reads > 0: 
                                path_modes['read'] += node.num_reads
                                if node.filename not in read_files:
                                    read_files.append(node.filename)
                            if node.num_writes > 0:
                                path_modes['write'] += node.num_writes
                                if node.filename not in write_files:
                                    write_files.append(node.filename)
                            if node.num_creates > 0:
                                if node.filename + '*' not in write_files:
                                    write_files.append(node.filename + '*')
                            # if node.num_stats > 0: path_modes['stat'] += node.num_stats
                            # if node.num_mmaps > 0: path_modes['mmap'] += node.num_mmaps
                            # if node.num_getdents > 0: path_modes['getdents64'] += node.num_getdents
                            # if node.num_creates > 0: path_modes['create'] += node.num_creates
                            # if node.num_enoent > 0: path_modes['enoent'] += node.num_enoent
                            if node.num_exec > 0: 
                                path_modes['exec'] += node.num_exec
                                exec_files.append(node) if node not in exec_files else None

                            #if node.num_mmapsh > 0: path_modes['mmapsh'] += node.num_mmapsh

                # If we have ≤2 access modes at this level or we reached the full depth, group the paths here
                # if len([m for m,c in path_modes.items() if c > 0]) <= 2 or depth == len(parts):
                #     group = remaining_groups[current_path]
                #     group['total_files'] = path_files
                #     group['dirpaths'].add(current_path)
                #     group['mode_counts'] = path_modes
                #     break

                if depth == len(parts):
                    group = remaining_groups[current_path]
                    group['total_files'] = path_files
                    group['dirpaths'].add(current_path)
                    group['mode_counts'] = path_modes
                    break

        # Print the grouped remaining paths
        for path, group_data in sorted(remaining_groups.items()):
            total_files = group_data['total_files']
            mode_counts = group_data['mode_counts']

            if total_files > 0:
                # if there are only enoent accesses, skip
                if all(value == 0 for mode, value in mode_counts.items() if mode != 'enoent'):
                    continue
                mode_summary = ', '.join(f"{mode}: {count}" for mode, count in sorted(mode_counts.items()) if count > 0)
                dir_summary = f"<{path}>"
                access_chars = ''.join(access_legend[mode] for mode, count in sorted(mode_counts.items()) if count > 0)
                indent = "  " * indent_level
                print(f"{indent}{access_chars} {dir_summary} ({total_files} files) [{mode_summary}]")
                if 'X' in access_chars and exec_files:
                    in_this_subpath = [f for f in exec_files if f.filename.startswith(f'{path}/')]
                    if in_this_subpath:
                        arg_lists = [f.exec_args for f in in_this_subpath]
                        for args in arg_lists:
                            print(f"{indent*2}#\tExecutable: {' '.join(args)}")
                if 'W' in access_chars and write_files:
                    # get the base filename or the disjoint part of the path string
                    in_this_subpath = [f.replace(f'{path}/', '') for f in write_files if f.startswith(f'{path}/') and f.count('/') == (path.count('/')+1)]
                    #if len(in_this_subpath) < 5:
                    if True:
                        print(f"{indent*2}#\tWritable files: {', '.join(in_this_subpath)}")
                    else:
                        # reduce the number of files to a glob pattern
                        glob_string = inverse_glob(in_this_subpath.copy())
                        print(f"{indent*2}#\tWritable files (glob): {glob_string}")
                if 'R' in access_chars and read_files:
                    # only show files in the same directory
                    in_this_subpath = [f.replace(f'{path}/', '') for f in read_files if f.startswith(f'{path}/') and f.count('/') == (path.count('/')+1)]
                    #if len(in_this_subpath) < 5:
                    if True:
                        print(f"{indent*2}#\tReadable files: {', '.join(in_this_subpath)}")
                    else:
                        # reduce the number of files to a glob pattern
                        glob_string = inverse_glob(in_this_subpath.copy())
                        print(f"{indent*2}#\tReadable files (glob): {glob_string}")

        # search_files = []
        # for file, count in files_repeat.items():
        #     if count > 3:
        #         search_files.append(file)
        # if search_files:
        #     indent = "  " * indent_level
        #     print(f"{indent}#Searching for: " + ', '.join(search_files))

        # if rw_mismatch_files:
        #     print(f"{indent*2}#Read/Write permission mismatches (requested but not performed):")
        #     print(f"{indent*2}#" + ''.join(rw_mismatch_files))


def print_file_tree_by_pid(pid, pid_tree, pid_dep, no_pid=False, skip_base_dirs=True, indent_level=0):
    if pid not in pid_tree:
        print(f"No data for PID {pid}")
        return
    single_pid_tree = {pid: pid_tree[pid]}
    print_file_tree(single_pid_tree, pid_dep, no_pid=no_pid, skip_base_dirs=skip_base_dirs, indent_level=indent_level)

def main():

    parser = argparse.ArgumentParser(description='Trace file access patterns using strace or parse a strace output file.')
    parser.add_argument('target', nargs='*', help='Path to executable')
    parser.add_argument('--file', '-f', dest='strace_file', help='Parse strace output from file instead of running strace')
    parser.add_argument('--nopid', '-p', dest='no_pid', help='Do not separate output by PID', action='store_true')
    #parser.add_argument('--tree', '-t', dest='print_tree', help='Print the trace output in a reduced tree format', action='store_true')
    args = parser.parse_args()

    print(args.target)

    if args.strace_file:
        with open(args.strace_file, 'r') as f:
            strace_lines = f.readlines()
        pid_tree, pid_dep = parse_strace_output(strace_lines)
        output_file = args.strace_file + '.contract'
        with open(output_file, 'w+') as f:
            sys.stdout = f
            #print_file_tree(pid_tree, pid_dep, no_pid=args.no_pid)
            print_process_tree(pid_tree, pid_dep)
            sys.stdout = sys.__stdout__
    elif args.target:
        proc = run_strace(args.target)
        try:
            pid_tree, pid_dep = parse_strace_output(proc.stderr)
            output_file = str(args.target[0].strip('./')) + '.contract'
            with open(output_file, 'w+') as f:
                sys.stdout = f
                #print_file_tree(pid_tree, pid_dep, no_pid=args.no_pid)
                print_process_tree(pid_tree, pid_dep)
                sys.stdout = sys.__stdout__
        except KeyboardInterrupt:
            proc.terminate()
    else:
        print('Usage: python pledge_tracer.py <pid|command> [--file <strace_output_file>]')
        sys.exit(1)

if __name__ == '__main__':
    main()
