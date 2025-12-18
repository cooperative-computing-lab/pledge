#!/usr/bin/env python3

import re
import sys
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
import os


@dataclass
class ProcessInfo:
    pid: str
    executable: Optional[str] = None
    arguments: List[str] = field(default_factory=list)
    written_files: List[str] = field(default_factory=list)
    readable_files: List[str] = field(default_factory=list)
    input_directories: Set[str] = field(default_factory=set)
    output_directories: Set[str] = field(default_factory=set)
    total_reads: int = 0
    total_writes: int = 0
    file_dependencies: Set[str] = field(default_factory=set)
    file_outputs: Set[str] = field(default_factory=set)


class ContractParser:    
    def __init__(self):
        self.processes: Dict[str, ProcessInfo] = {}
        self.cwd: Optional[str] = None
        
    def parse_contract_file(self, file_path: str) -> bool:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            self._parse_processes(content)
            self._parse_cwd(content)
            return True
            
        except Exception as e:
            print(f"Error parsing contract file: {e}")
            return False
    
    def _parse_processes(self, content: str) -> None:
        lines = content.split('\n')
        current_pid = None
        current_directory = None

        for line in lines:
            pid_match = re.search(r'[├└]─ PID (\d+) \([^)]+\) \[([^\]]+)\]', line)
            if pid_match:
                pid, executable = pid_match.groups()
                current_pid = pid
                
                self.processes[pid] = ProcessInfo(
                    pid=pid,
                    executable=executable
                )
                continue
            
            if current_pid and current_pid in self.processes:
                process = self.processes[current_pid]
                
                dir_match = re.match(r'\s+([RWXMPDSCE]+)\s+<([^>]+)>\s+\(\d+\s+files?\)\s+\[([^\]]+)\]', line)
                if dir_match:
                    access_types, directory, stats_str = dir_match.groups()
                    
                    stats = self._parse_stats(stats_str)

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
                
                executable_match = re.search(r'#\s+Executable:\s*(.+)', line)
                if executable_match:
                    exec_line = executable_match.group(1).strip()
                    parts = exec_line.split()
                    if parts:
                        process.arguments = parts[1:] if len(parts) > 1 else []
                
                readable_match = re.search(r'#\s+Readable files(?:\s+\(glob\))?\s*:\s*(.+)', line)
                if readable_match:
                    files_str = readable_match.group(1)
                    files = self._parse_file_list(files_str, current_directory)
                    process.readable_files.extend(files)
                    for file_path in files:
                        # This would create a circular dependency but might point out a flaw in the program
                        if not file_path in process.file_outputs:
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

        cwd_groups = self.cwd.split('/')
        file_groups = file_path.split('/')

        num_common = len(list(set(cwd_groups).intersection(set(file_groups))))

        relative_parts = file_groups[num_common:]
        file_path = '/'.join(relative_parts)

        
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
    
    def analyze_data_flow(self) -> None:
        
        print("Data Flow Analysis:\n")
        
        dependencies = self._build_dependency_graph()
        
        chains = self._find_data_flow_chains(dependencies)
        
        if chains:
            print("Data Flow Chains:")
            for i, chain in enumerate(chains, 1):
                print(f"  Chain {i}: {' → '.join([self._get_process_name(pid) for pid in chain])}")
                # Show what data flows between processes
                for j in range(len(chain) - 1):
                    producer_pid = chain[j]
                    consumer_pid = chain[j + 1]
                    shared_data = self._find_shared_data(producer_pid, consumer_pid)
                    if shared_data:
                        print(f"    {self._get_process_name(producer_pid)} → {self._get_process_name(consumer_pid)}: {', '.join(list(shared_data)[:3])}{'...' if len(shared_data) > 3 else ''}")
            print()
        
        # Show concurrent processes (no dependencies)
        concurrent = self._find_concurrent_processes(dependencies)
        if concurrent:
            print("Processes that can run concurrently:")
            for group in concurrent:
                if len(group) > 1:
                    print(f"  • {', '.join([self._get_process_name(pid) for pid in group])}")
            print()
    
    def _get_process_name(self, pid: str) -> str:
        
        process = self.processes.get(pid)
        if process and process.executable:
            return f"{os.path.basename(process.executable)}({pid})"
        return f"PID{pid}"
    
    def _find_data_flow_chains(self, dependencies: Dict[str, Set[str]]) -> List[List[str]]:
        
        chains = []
        visited = set()
        
        # Start from processes with no dependencies
        root_processes = set(self.processes.keys()) - set(dependencies.keys())
        
        for root in sorted(root_processes, key=lambda x: int(x) if x.isdigit() else 0):
            if root not in visited:
                chain = self._trace_dependency_chain(root, dependencies, visited)
                if len(chain) > 1:
                    chains.append(chain)
        
        return chains
    
    def _trace_dependency_chain(self, pid: str, dependencies: Dict[str, Set[str]], visited: set) -> List[str]:
        
        chain = [pid]
        visited.add(pid)
        
        # Find processes that depend on this one
        dependents = []
        for dependent_pid, deps in dependencies.items():
            if pid in deps and dependent_pid not in visited:
                dependents.append(dependent_pid)
        
        if dependents:
            next_pid = sorted(dependents, key=lambda x: int(x) if x.isdigit() else 0)[0]
            chain.extend(self._trace_dependency_chain(next_pid, dependencies, visited)[1:])
        
        return chain
    
    def _find_shared_data(self, producer_pid: str, consumer_pid: str) -> Set[str]:
        
        producer = self.processes.get(producer_pid)
        consumer = self.processes.get(consumer_pid)
        
        if not producer or not consumer:
            return set()
        
        shared_files = producer.file_outputs & consumer.file_dependencies
        
        shared_dirs = set()
        for out_dir in producer.output_directories:
            for in_dir in consumer.input_directories:
                if self._paths_overlap(out_dir, in_dir):
                    shared_dirs.add(f"directory:{out_dir}")
        
        return shared_files | shared_dirs
    
    def _find_concurrent_processes(self, dependencies: Dict[str, Set[str]]) -> List[List[str]]:
        
        all_deps = set()
        for deps in dependencies.values():
            all_deps.update(deps)
        
        stages = self._find_execution_stages(dependencies)
        return stages
    
    def analyze_execution_order(self) -> None:
        
        dependencies = self._build_dependency_graph()
        
        self._print_makefile_targets(dependencies)
    
    def _print_makefile_targets(self, dependencies: Dict[str, Set[str]]) -> None:
        
        sorted_processes = sorted(self.processes.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)
        
        target_lines = []
        all_targets = []

        for pid, process in sorted_processes:
            if int(pid) == 0:
                continue  # Skip the initial process
            
            if process.file_outputs:
                outputs = [self._normalize_path(f) for f in sorted(process.file_outputs)]
                all_targets.extend(outputs)
                
                input_files = []
                deps = dependencies.get(pid, set())
                for dep_pid in sorted(deps, key=lambda x: int(x) if x.isdigit() else 0):
                    dep_process = self.processes.get(dep_pid)
                    if dep_process and dep_process.file_outputs:
                        normalized_outputs = [self._normalize_path(f) for f in dep_process.file_outputs]
                        input_files.extend(normalized_outputs)
                
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
                    target_block.append(f"\t{process.executable} {args_str}")
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
                deps = dependencies.get(pid, set())
                for dep_pid in sorted(deps, key=lambda x: int(x) if x.isdigit() else 0):
                    dep_process = self.processes.get(dep_pid)
                    if dep_process and dep_process.file_outputs:
                        input_files.extend([self._normalize_path(f) for f in dep_process.file_outputs])
                
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
        
        print("all: " + ' '.join([self._normalize_path(f) for f in all_targets]) + "\n")

        for target in target_lines:
            print(target)
    
    def _find_final_processes(self, dependencies: Dict[str, Set[str]]) -> Set[str]:
        
        all_processes = set(self.processes.keys())
        depended_upon = set()
        
        for deps in dependencies.values():
            depended_upon.update(deps)
        
        return all_processes - depended_upon
    
    def _group_by_executable(self) -> Dict[str, List[str]]:
        
        groups = defaultdict(list)
        for pid, process in self.processes.items():
            if process.executable:
                exec_name = os.path.basename(process.executable)
                groups[exec_name].append(pid)
        return groups
    
    def _build_dependency_graph(self) -> Dict[str, Set[str]]:
        
        dependencies = defaultdict(set)
        
        # Map output files to the processes that create them
        file_producers = defaultdict(set)
        # Map output directories to the processes that create them  
        dir_producers = defaultdict(set)
        
        # First pass: identify all producers
        for pid, process in self.processes.items():
            # Track directory-level outputs
            for output_dir in process.output_directories:
                dir_producers[output_dir].add(pid)
            
            # Track file-level outputs
            for file_path in process.file_outputs:
                file_producers[file_path].add(pid)
                
                # Also associate files with their parent directories
                for output_dir in process.output_directories:
                    if not file_path.startswith('/'):
                        # Relative path, combine with output directory
                        full_path = f"{output_dir}/{file_path}"
                        file_producers[full_path].add(pid)
                    else:
                        file_producers[file_path].add(pid)
        
        # Second pass: find file-level dependencies (more precise)
        for pid, process in self.processes.items():
            # Check if this process reads files produced by other processes
            for read_file in process.file_dependencies:
                # Direct file match
                if read_file in file_producers:
                    for producer_pid in file_producers[read_file]:
                        if producer_pid != pid and int(producer_pid) < int(pid):
                            dependencies[pid].add(producer_pid)
                
                # Check if read file matches any output directory + file combination
                for output_dir in dir_producers:
                    if read_file.startswith(output_dir + '/'):
                        for producer_pid in dir_producers[output_dir]:
                            if producer_pid != pid and int(producer_pid) < int(pid):
                                dependencies[pid].add(producer_pid)
        
        # Third pass: fallback to directory-level dependencies for unmatched cases
        for pid, process in self.processes.items():
            for input_dir in process.input_directories:
                for output_dir, producer_pids in dir_producers.items():
                    if (input_dir in output_dir or output_dir in input_dir or 
                        self._paths_overlap(input_dir, output_dir)):
                        for producer_pid in producer_pids:
                            if producer_pid != pid and int(producer_pid) < int(pid):
                                dependencies[pid].add(producer_pid)
        
        return dependencies
    
    
    def _paths_overlap(self, path1: str, path2: str) -> bool:
        
        p1_parts = path1.strip('/').split('/')
        p2_parts = path2.strip('/').split('/')
        
        min_len = min(len(p1_parts), len(p2_parts))
        if min_len == 0:
            return False
            
        return p1_parts[:min_len] == p2_parts[:min_len]
    
    def _find_execution_stages(self, dependencies: Dict[str, Set[str]]) -> List[Set[str]]:
        
        stages = []
        remaining_processes = set(self.processes.keys())
        processed = set()
        
        while remaining_processes:
            ready_processes = set()
            for pid in remaining_processes:
                if not dependencies[pid] or dependencies[pid].issubset(processed):
                    ready_processes.add(pid)
            
            if not ready_processes:
                ready_processes = remaining_processes.copy()
            
            stages.append(ready_processes)
            processed.update(ready_processes)
            remaining_processes -= ready_processes
        
        return stages


def main():
    parser = argparse.ArgumentParser(description='Parse contract files and generate Makefile dependencies')
    parser.add_argument('contract_file', help='Path to the contract file to analyze')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.contract_file):
        print(f"Error: Contract file '{args.contract_file}' not found")
        sys.exit(1)
    
    parser_obj = ContractParser()
    if not parser_obj.parse_contract_file(args.contract_file):
        print("Failed to parse contract file")
        sys.exit(1)
    
    input_base = os.path.splitext(args.contract_file)[0]
    output_file = f"{input_base}.makeflow"
    
    with open(output_file, 'w') as f:
        import sys
        old_stdout = sys.stdout
        sys.stdout = f
        parser_obj.analyze_execution_order()
        sys.stdout = old_stdout
    
    print(f"Makeflow written to: {output_file}")


if __name__ == '__main__':
    main()
