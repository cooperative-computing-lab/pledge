#!/usr/bin/env python3

import re
import sys
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
import os
import json

name_comprehension = False
dag_prune = True

@dataclass
class ProcessInfo:
    pid: str
    executable: Optional[str] = None
    level: int = 0
    arguments: List[str] = field(default_factory=list)
    written_files: List[str] = field(default_factory=list)
    readable_files: List[str] = field(default_factory=list)
    input_directories: Set[str] = field(default_factory=set)
    output_directories: Set[str] = field(default_factory=set)
    total_reads: int = 0
    total_writes: int = 0
    file_dependencies: Set[str] = field(default_factory=set)
    file_outputs: Set[str] = field(default_factory=set)
    exec_parent: "ProcessInfo" = None
    at_fdcwd: Optional[str] = None

class ContractParser:    
    def __init__(self):
        self.processes: Dict[str, ProcessInfo] = {}
        self.cwd: Optional[str] = None
        
    def parse_contract_file(self, file_path: str) -> bool:
        #try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        self._parse_processes(content)
        self._parse_cwd(content)
        return True
    
    def _parse_processes(self, content: str) -> None:
        lines = content.split('\n')
        current_pid = None
        current_directory = None
        parent_process = None
        task_process = None
        
        for line in lines:
            pid_match = re.search(r'[├└]─ PID (\d+) (\d+) \[([^\]]+)\]', line)
            if pid_match:
                pid, level, executable = pid_match.groups()
                current_pid = pid
                current_level = int(level)

                self.processes[pid] = ProcessInfo(
                    pid=pid,
                    executable=executable,
                    level = current_level
                )

                # if we are at level 0 we are a root process
                if current_level == 0:
                    parent_process = self.processes[pid]
                    # we have a new root, reset task process
                    task_process = None
                # level 1 processes are to become tasks
                if current_level == 1:
                    task_process = self.processes[pid]
                # if we are at level > 1, we inherit from the last level 1 process
                if current_level > 1:
                    self.processes[pid].exec_parent = task_process

                continue
            
            if current_pid and current_pid in self.processes:
                inheritance = False

                # if we are a root or task process we add to our own info
                if current_pid == parent_process.pid or current_pid == task_process.pid:
                    process = self.processes[current_pid]
                # if we are a child process we inherit from the parent
                else:
                    process = task_process
                    inheritance = True
                
                dir_match = re.match(r'\s+([RWXMPDSCE]+)\s+<([^>]+)>\s+\(\d+\s+files?\)\s+\[([^\]]+)\]', line)
                if dir_match:
                    access_types, directory, stats_str = dir_match.groups()
                    stats = self._parse_stats(stats_str)
                    print(directory)

                    if 'E' not in access_types:
                        current_directory = directory
                    
                    if 'R' in access_types or 'M' in access_types:
                        process.input_directories.add(directory)
                        process.total_reads += stats.get('read', 0) + stats.get('stat', 0)
                    
                    if 'W' in access_types or 'C' in access_types:
                        process.output_directories.add(directory)
                        process.total_writes += stats.get('write', 0) + stats.get('create', 0)
                
                writable_match = re.search(r'#\s+Writable files(?:\s+\(glob\))?\s*:\s*(.+)', line)
                if writable_match:
                    files_str = writable_match.group(1)
                    files = self._parse_file_list(files_str, current_directory)
                    process.written_files.extend(files)
                    for file_path in files:
                        if '*' in file_path:
                            # this file was created in addition to being written
                            process.file_outputs.add(file_path.strip('*'))
                
                if not inheritance:
                    executable_match = re.search(r'#\s+Executable:\s*(.+)  (?:ATFDCWD:(.+))', line)
                    if executable_match:
                        exec_line = executable_match.group(1).strip()
                        parts = exec_line.split()
                        if parts:
                            process.arguments = parts[1:] if len(parts) > 1 else []

                        if len(executable_match.groups()) > 1:
                            process.at_fdcwd = executable_match.group(2).strip(',\\"\'')
                
                readable_match = re.search(r'#\s+Readable files(?:\s+\(glob\))?\s*:\s*(.+)', line)
                if readable_match:
                    files_str = readable_match.group(1)
                    files = self._parse_file_list(files_str, current_directory)
                    process.readable_files.extend(files)
                    for file_path in files:
                        # This would create a circular dependency but might point out a flaw in the program
                        if not file_path in process.file_outputs:# and not file_path.split('/')[-1] == process.executable.split('/')[-1]:
                            process.file_dependencies.add(file_path)
                
            # Parse CWD line
            cwd_match = re.search(r'^CWD:\s*(.+)$', line)
            if cwd_match:
                self.cwd = cwd_match.group(1).strip()
    
    def _parse_stats(self, stats_str: str) -> Dict[str, int]:
        stats = {}
        for part in stats_str.split(', '):
            if ':' in part:
                key, value = part.split(':', 1)
                try:
                    stats[key.strip()] = int(value.strip())
                except ValueError:
                    pass
        return stats
    
    def _parse_file_list(self, files_str: str, current_directory: str) -> List[str]:
        files = []
        if files_str.strip().startswith('[') and files_str.strip().endswith(']'):
            inner = files_str.strip()[1:-1]
            files = [f.strip().strip("'\"") for f in inner.split(',') if f.strip()]
        else:
            files = [f.strip() for f in files_str.split(',') if f.strip()]

        # Prepend current directory if relative paths are used
        if current_directory:
            normalized_files = []
            for f in files:
                if not f.startswith('/') and not f.startswith('*'):
                    normalized_files.append(f"{current_directory}/{f}")
                else:
                    normalized_files.append(f)
            files = normalized_files
        
        return files
    
    def _parse_cwd(self, content: str) -> None:
        """Extract the current working directory from the contract file"""
        lines = content.split('\n')
        for line in lines:
            cwd_match = re.match(r'CWD:\s*(.+)', line.strip())
            if cwd_match:
                self.cwd = cwd_match.group(1).strip()
                break
    
    def _normalize_path(self, file_path: str) -> str:
        """Remove CWD prefix from file path if present"""
        if not self.cwd or not file_path:
            return file_path
        
        # Remove CWD substring if part of file path
        # example CWD = /home/user/project
        # file_path = project/src/main.c
        # result = src/main.c
        # example CWD = /home/user/project/data/scripts/
        # file_path = project/data/scripts/slurm/jobs/
        # relative parts = project/data/scripts/
        # cwd[-len(relative parts):] = relative parts
        # result = slurm/jobs

        # example CWD = /home/user/project
        # file_path = /home/user/data/image.png
        # result = ../data/image.png

        cwd_groups = self.cwd.split('/')
        file_groups = file_path.split('/')

        # a problem when CWD and a different path shares the same named subdirectories
        # CWD = dir1/dir2/data/src
        # file_path = dir3/dir2/data/src/image
        # = /data/src/image ! wrong
        # num common = 2

        # another problem is when the file path includes back directories
        # CWD = /home/user/project/src
        # file_path = ../data/image.png
        # or even better
        # file_path = project/../data/image.png

        # this will not work for very long
        if file_groups[0] in cwd_groups:
            # how many directories are common to both paths
            num_common = len(list(set(cwd_groups).intersection(set(file_groups))))
            # hopefully the common parts are at the start
            relative_parts = file_groups[num_common:]

            if cwd_groups[-len(relative_parts):] == relative_parts:
                file_path = '/'.join(relative_parts)
            else:
                # build relative path with .. parts
                num_up = len(cwd_groups) - num_common
                relative_parts = ['..'] * num_up + file_groups[num_common:]
                file_path = '/'.join(relative_parts)
            #file_path = './' + '/'.join(relative_parts)


        # replace escape sequences and bad characters for makefiles


        # pair for idempotence
        file_path = file_path.replace(':', '\\:')
        file_path = file_path.replace('\\\\:', '\\:')

        return file_path
    
    def _deduplicate_files(self, files: List[str]) -> List[str]:
        """Remove duplicate files that refer to the same actual file"""
        seen = set()
        result = []
        
        for file_path in files:
            # Normalize the path and convert to absolute for comparison
            if file_path.startswith('/'):
                abs_path = file_path
            elif self.cwd:
                abs_path = os.path.join(self.cwd, file_path)
            else:
                abs_path = os.path.abspath(file_path)
            
            # Use normalized absolute path as the key for deduplication
            if abs_path not in seen:
                seen.add(abs_path)
                result.append(file_path)
        
        return result
    
    
    
    def generate_makefile(self) -> None:
        
        target_lines = self._find_makefile_targets()

        for l in target_lines:
            print(l)

    def generate_jx_workflow(self) -> None:
        
        target_lines = self._find_makefile_targets()

        # there are three types of lines:
        # 1. all: target1 target2 target3 ...
        #       - this is the first line, listing all targets
        # 2. target &: dep1 dep2 dep3 ...
        #       - this is a target with dependencies  
        # 3. \tcommand arg1 arg2 ...
        #       - this is the command to run for the target

        '''
        {
            "rules": [
                        {
                            "command" : "command arg1 arg2 ...",
                            "inputs"  : [ "target1", "target2", ... ],
                            "outputs" : [ "target3", "target4", ... ]
                        }
                    ]
        }
        '''

        # make a json object for each makefile rule of the above format 

        class JXRule:
            def __init__(self):
                self.command: Optional[str] = None
                self.outputs = None
                self.inputs = None

        rules: List[JXRule] = []

        for l in target_lines:
            if l.startswith("all:"):
                continue  # skip the all line
            elif '&:' in l:
                # parse items
                target_part, dep_part = l.split('&:', 1)
                deps, command = dep_part.split('\n\t', 1)
                target_names = target_part.strip().split()
                dependencies = deps.strip().split()

                # remove temporary files XXX
                target_names = [t for t in target_names if not '.tmp' in t]
                dependencies = [d for d in dependencies if not '.tmp' in d]

                directory_structure = set([])

                # # assign remote names, if necessary
                # for i, t in enumerate(target_names):
                #     if '/' in t:
                #         directory_structure.add('/'.join(t.split('/')[0:-1]))
                #         target_names[i] = {'dag_name': t, 'task_name': t.split('../')[-1]}

                # for i, d in enumerate(dependencies):
                #     if '/' in d:
                #         directory_structure.add('/'.join(d.split('/')[0:-1]))
                #         dependencies[i] = {'dag_name': d, 'task_name': d.split('../')[-1]}

                depth = 0
                for dir in directory_structure:
                    num_up = dir.split('../')
                    depth = max(depth, len(num_up) - 1)

                depth -= 1

                directory_structure = ' '.join(set(directory_structure))
                
                command = command.strip()

                if len(directory_structure) > 0:
                    # add a echo return to the real command
                    command = command + '; echo $?; echo CMDRET; ls -l; '

                    # add the down directories first
                    depth_from_cwd = ''.join(['/usr/bin/mkdir -p ' + directory_structure, '; '])

                    # if there are back directories we need to build up and cd there
                    # It works if the program accesses a relative path (depth*../)/something. 
                    # The problem now is if the program accesses something < depth levels up.
                    # The recreated directory structure has the directory names but the contents 
                    # were not linked in by the task setup. They are sitting at the base level. 

                    # where depth is how deep the task cwd is from the worker's starting point
                    if depth > 0:
                        up_dirs = 'dir_structure_auto/' * depth

                        # gets us mkdir -p dir_structure_auto/dir_structure_auto/...; cd dir_structure_auto/...
                        depth_from_worker = ''.join(['/usr/bin/mkdir -p ' + up_dirs + '; cd ' + up_dirs, '; '])

                        back_to_workspace = ''
                        # we need to mv the contents of the base level into the recreated structure
                        for d in directory_structure.split():
                            dir_parts = d.split('/')
                            num_up = len(d.split('../')) - 1

                            # if this path goes up we need to find the contents at the base and move them there
                            # say we are at a/b/c/d/main.c
                            # and we have ../../bob/data.txt
                            # mv ../../../../bob ../../bob
                            if num_up < depth:
                                source = '../' * depth
                                dest = '../' * num_up
                                base = dir_parts[num_up]
                                mov = f' mv {source}{base} {dest}{base} ;'
                                mov_back = f' mv {dest}{base} {source}{base} ;'
                                depth_from_worker += mov
                                back_to_workspace += mov_back

                        #                  mkdir; cd; mv;     mkdir           command  mv back
                        command = ''.join([depth_from_worker, depth_from_cwd, command, back_to_workspace])
                    else:
                        command = depth_from_cwd + '; ' + command


                rule = JXRule()
                rule.outputs = target_names
                rule.inputs = dependencies
                rule.command = command
                rules.append(rule)

        # create the jx workflow. Add rules.
        jx_workflow = {
            "rules": [rules.__dict__ for rules in rules]
        }

        def varname_from_command(command: str) -> str:
            # split from args
            executable = command.split()[0].strip('"')
            # may be absolute path
            name = executable.split('/')[-1].upper()
            return name
        
        def command_args(command: str) -> List[str]:
            parts = command.split()
            return parts[1:] if len(parts) > 1 else []

        def swap_for_var(command: str, args: List[str], varname: str) -> str:
            executable = command.split()[0].strip('"')
            new_cmd = command.replace(executable, f"{{{varname}}}", 1)
            argname = varname + '_ARGLIST'
            if args:
                new_cmd = new_cmd.replace(' '.join(args), f"{{{argname}}}", 1)
            return new_cmd
 
        from inverse_pattern import inverse_pattern_jx_expr

        # create an instance of 'template(expr)' in the jx workflow
        class JxTemplate():
            def __init__(self, expr, varmap=None):
                qrem = ('KWD_REMOVE_QUOTE_BEFORE', 'KWD_REMOVE_QUOTE_AFTER')
                qadd = 'KWD_ADD_QUOTE_HERE'
                self.expr = f'template({qadd}' + str(expr) + f'{qadd})'
                
                # example
                # join([template("small.fasta.{x}.out") for x in range(ceil(TOTAL_SEQ/SEQ_PER_SPLIT))])
                if varmap:
                    for var, minmax in varmap.items():
                        self.expr = ''.join([self.expr, f' for {var} in range({minmax[0]}, {minmax[1]}+1) '])
                    #self.expr = 'join([' + self.expr + '])'

            
                self.expr = ''.join([qrem[0], self.expr, qrem[1]])

        # use when we are substituting a simple expression outside of a string
        class JxExpr():
            def __init__(self, expr):
                qrem = ('KWD_REMOVE_QUOTE_BEFORE', 'KWD_REMOVE_QUOTE_AFTER')
                self.original = expr
                self.expr = str(expr)
                self.expr = ''.join([qrem[0], self.expr, qrem[1]])


        # remove output files that no other task depends on.
        # these are generally temporary to the task. If the task cleans them up
        # then we will have an error when we check if outputs were created
        # pipe resolution may depend on this as well.
        if dag_prune:
            for rule in jx_workflow['rules']:
                outputs = rule['outputs']
                new_outputs = []
                for i, o in enumerate(outputs):
                    if any(o in r['inputs'] for r in jx_workflow['rules']):
                        new_outputs.append(o)
                rule['outputs'] = new_outputs

        pipe_writers = []
        pipe_readers = []
        # combine pipe dependencies into a single task
        for rule in jx_workflow['rules']:
                if any('pipe' in r for r in rule['outputs']):
                    pipe_writers.append(rule)
                if any('pipe' in r for r in rule['inputs']):
                    pipe_readers.append(rule)

       

        pipe_rw_pairs = [(w, r) for w, r in zip(pipe_readers, pipe_writers) if set(w['inputs']).intersection(set(r['outputs']))]

        if pipe_rw_pairs != []:

            for (w, r) in pipe_rw_pairs:
                jx_workflow['rules'].remove(w)
                jx_workflow['rules'].remove(r)

                r['command'] = w['command'] + ' | ' + r['command']
                r['inputs'] += w['inputs']
                r['outputs'] += w['outputs']

            for (w, r) in pipe_rw_pairs:
                r['inputs'].remove(next(i for i in r['inputs'] if 'pipe' in i))
                r['outputs'].remove(next(o for o in r['outputs'] if 'pipe' in o))
                jx_workflow['rules'].append(r)


        if name_comprehension:
            # map of k,v for defines
            task_vars = {}
            count_rules = {}
            # replace names with variables. Add to defines when applicable
            for rule in jx_workflow['rules']:
                # replace command with template + define
                command = rule['command'].strip('"')
                executable = command.split()[0]
        
                name = varname_from_command(executable)
                args = command_args(command)

                # swap command and args with variables
                rule['command'] = JxTemplate(swap_for_var(command, args, name))

                # the executable may appea


        if name_comprehension:
            # map of k,v for defines
            task_vars = {}
            count_rules = {}
            # replace names with variables. Add to defines when applicable
            for rule in jx_workflow['rules']:
                # replace command with template + define
                command = rule['command'].strip('"')
                executable = command.split()[0]
        
                name = varname_from_command(executable)
                args = command_args(command)

                # swap command and args with variables
                rule['command'] = JxTemplate(swap_for_var(command, args, name))

                # the executable may appear more than once with different arguments.
                # we will remove the duplicate tasks and add an expression to represent them
                count_rules[name] = count_rules.get(name, []) + [rule]
                
                if task_vars.get(name + '_ARGLIST'):
                    args = task_vars[name + '_ARGLIST'] + [args]

                task_vars[name] = executable
                task_vars[name + '_ARGLIST'] = [args]

                # inverse pattern files
                const_inputs, expr_inputs, input_varmap = inverse_pattern_jx_expr(rule['inputs'])
                const_outputs, expr_outputs, output_varmap = inverse_pattern_jx_expr(rule['outputs'])

                expr_inputs_templated = [JxTemplate(e, varmap=input_varmap[e]) for e in expr_inputs]
                expr_outputs_templated = [JxTemplate(e, varmap=output_varmap[e]) for e in expr_outputs]

                # the same goes for multiple i/o lists
                if task_vars.get(name + '_INPUTS'):
                    expr_inputs_templated = task_vars[name + '_INPUTS'] + [const_inputs + expr_inputs_templated]

                if task_vars.get(name + '_OUTPUTS'):
                    expr_outputs_templated = task_vars[name + '_OUTPUTS'] + [const_outputs + expr_outputs_templated]
                    
                task_vars[name + '_INPUTS'] = [const_inputs + expr_inputs_templated]
                task_vars[name + '_OUTPUTS'] = [const_outputs + expr_outputs_templated]

                rule['inputs'] = JxExpr(f'{{{name}_INPUTS}}')
                rule['outputs'] = JxExpr(f'{{{name}_OUTPUTS}}')
                
            duplicate_rules = [rules for name, rules in count_rules.items() if len(rules) > 1]

            for r in duplicate_rules:
                count = len(r)
                for dr in r[1:]:
                    jx_workflow['rules'].remove(dr)

                therule = r[0]
                therule["expand"] = count
                therule['inputs'] = JxExpr(f"{ therule['inputs'].original + '[x]' }")
                therule['outputs'] = JxExpr(f"{ therule['outputs'].original + '[x]' }")
                

            # map executables and their arguments to defines.
            jx_workflow["define"] = task_vars

        # allow serialization of jxtemplate 
        class CustomEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, JxTemplate):
                    return obj.expr
                if isinstance(obj, JxExpr):
                    return obj.expr
                return super().default(obj)
                
        json_rep = json.dumps(jx_workflow, indent=2, cls=CustomEncoder)

        if name_comprehension:
            # need to do some non-standard json. no quotes around jx template expressions but add inside
            pat_remove_quotes = r'"KWD_REMOVE_QUOTE_BEFORE(.*)KWD_REMOVE_QUOTE_AFTER"'
            remove_template_quotes = re.sub(pat_remove_quotes, str(r'\1'), json_rep)

            pat_add_quotes = r'KWD_ADD_QUOTE_HERE'
            jx_final = re.sub(pat_add_quotes, '"', remove_template_quotes)
        else:
            jx_final = json_rep

        print(jx_final)
       
    
    def _find_makefile_targets(self) -> None:
        
        sorted_processes = sorted(self.processes.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
        
        target_lines = []
        all_targets = []

        for pid, process in sorted_processes:
            #XXX need to change for setting different level
            if process.level < 1:
                continue  # do not invoke the initial process
            elif process.level > 1:
                continue 

            if process.file_outputs:
                outputs = [self._normalize_path(f) for f in sorted(process.file_outputs)]
                all_targets.extend(outputs)
                
                input_files = []
                
                if process.file_dependencies:
                    normalized_deps = [self._normalize_path(f) for f in process.file_dependencies]
                    input_files.extend(normalized_deps)
                
                # Deduplicate input files to prevent duplicate references
                input_files = self._deduplicate_files(list(set(input_files)))
                
                target_block = []
                if input_files:
                    target_block.append(f"{' '.join(outputs)} &: {' '.join(sorted(input_files))}")
                else:
                    target_block.append(f"{' '.join(outputs)} &:")
                
                if process.executable and process.arguments:
                    args_str = ' '.join(process.arguments)
                    target_block.append(f"\t{'cd ' + os.path.relpath(process.at_fdcwd,self.cwd).strip() + ' ;' if process.at_fdcwd.strip() != self.cwd.strip() else ''} {process.executable} {args_str}")
                elif process.executable:
                    target_block.append(f"\t{process.executable}")
                else:
                    exec_name = os.path.basename(process.executable) if process.executable else f"pid_{pid}"
                    target_block.append(f"\t@echo \"Executing {exec_name} (PID {pid})\"")
             

                target_block.append("")
                target_lines.append('\n'.join(target_block))
            else:
                exec_name = os.path.basename(process.executable) if process.executable else f"pid_{pid}"
                target_name = f"{exec_name}_{pid}".replace('.', '_').replace('-', '_')
                all_targets.append(target_name)
                
                input_files = []
                
                if process.file_dependencies:
                    input_files.extend([self._normalize_path(f) for f in process.file_dependencies])
                
                # Deduplicate input files to prevent duplicate references
                input_files = self._deduplicate_files(list(set(input_files)))
                
                target_block = []
                if input_files:
                    target_block.append(f"{target_name} &: {' '.join(sorted(input_files))}")
                else:
                    target_block.append(f"{target_name} &:")
                
                if process.executable and process.arguments:
                    args_str = ' '.join(process.arguments)
                    target_block.append(f"\t{process.executable} {args_str}")
                elif process.executable:
                    target_block.append(f"\t{process.executable}")
                else:
                    target_block.append(f"\t@echo \"Executing {exec_name} (PID {pid})\"")
                
                target_block.append("")
                target_lines.append('\n'.join(target_block))
        
        target_lines.insert(0, "all: " + ' '.join([self._normalize_path(f) for f in all_targets]) + "\n")

        return target_lines

def main():
    parser = argparse.ArgumentParser(description='Parse contract files and generate Makefile dependencies')
    parser.add_argument('contract_file', help='Path to the contract file to analyze')
    parser.add_argument('--name-comprehension', action='store_true', help='Use name comprehension for JX workflow generation')
    parser.add_argument('--dont-prune', action='store_false', help='Leave all created files as outputs, even if the task deletes them.')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.contract_file):
        print(f"Error: Contract file '{args.contract_file}' not found")
        sys.exit(1)
    
    parser_obj = ContractParser()
    if not parser_obj.parse_contract_file(args.contract_file):
        print("Failed to parse contract file")
        sys.exit(1)
    
    input_base = os.path.splitext(args.contract_file)[0]
    output_file_makeflow = f"{input_base}.makeflow"
    output_file_jx = f"{input_base}.jx"
    
    global name_comprehension
    global dag_prune

    dag_prune = args.dont_prune       
    name_comprehension = args.name_comprehension  

    with open(output_file_jx, 'w') as f:
        import sys
        old_stdout = sys.stdout
        sys.stdout = f
        parser_obj.generate_jx_workflow()
        sys.stdout = old_stdout

    with open(output_file_makeflow, 'w') as f:
        import sys
        old_stdout = sys.stdout
        sys.stdout = f
        parser_obj.generate_makefile()
        sys.stdout = old_stdout


    print(f"Makeflow written to: {output_file_makeflow}")
    print(f"JX workflow written to: {output_file_jx}")


if __name__ == '__main__':
    main()
