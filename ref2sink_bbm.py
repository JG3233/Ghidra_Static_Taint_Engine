# A Ghidra Taint Analysis script for buffer overflows, command injection, and performing general 
# control-flow analysis for update related vulnerabilities. Uses the Ghidra Basic Block Model to find 
# paths as opposed to a callmap. Allows for better control-flow information and increased functionality.
#
# @author Jacob Gilhaus, built with the inspiration of SaTC: https://github.com/NSSL-SJTU/SaTC

import time
import sys
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from collections import Counter, defaultdict
from const import non_sparse_consts, sparse_consts, operand_consts, crypto_strs
import re

# Verbosity and scope
DEBUG = False
VERBOSE = False
VVERBOSE  = False
VULNS_TO_CHECK = ['buffer_overflow', 'command_injection', 'control_flow']

# Sinks
cf_sinks = ['system', '___system', 'bstar_system', 'popen',
         'doSystemCmd', 'doShell', 'twsystem', 'CsteSystem', 'cgi_deal_popen',
         'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str']

cmdi_sinks = ['system', '___system', 'bstar_system', 'popen',
         'doSystemCmd', 'doShell', 'twsystem', 'CsteSystem', 'cgi_deal_popen',
         'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str']

bof_sinks = ['strcpy', 'sprintf', 'memcpy', 'strcat']

# Results file and utilities
global f 
f = None
syms = {}
analyzer = None


def a2h(address):
    return '0x' + str(address)


def getAnalyzer():
    global analyzer
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        assert 0


def getCallingArgs(addr, pos):
    if not 0 <= pos <= 3:
        return
    arch = str(currentProgram.language.processor)
    if arch == 'ARM':
        reg = currentProgram.getRegister('r%d' % pos)
    elif arch == 'MIPS':
        nextInst = getInstructionAt(addr).next
        if len(nextInst.pcode):  # not NOP
            addr = addr.add(8)
        reg = currentProgram.getRegister('a%d' % pos)
    elif arch == 'x86' and str(currentProgram.language.getProgramCounter()) == 'RIP':
        # dont know how to tell 32 and 64 apart qwq
        if pos == 3:
            return
        reg = currentProgram.getRegister(['RDI', 'RSI', 'RDX'][pos])
    else:
        return
    return getRegister(addr, reg)


def getRegister(addr, reg):
    if analyzer is None:
        getAnalyzer()

    func = getFunctionContaining(addr)
    if func is None:
        return

    if func in syms:
        symEval = syms[func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)
        analyzer.flowConstants(currentProgram, func.entryPoint, func.body, symEval, monitor)
        syms[func] = symEval

    return symEval.getRegisterValue(addr, reg)


def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return
    return ret[:-1]


def getStrArg(addr, argpos=0):
    rv = getCallingArgs(addr, argpos)
    if rv is None:
        return
    return getStr(toAddr(rv.value))


# Customized function for reboot check 
def checkReboot(addr, argpos=0):
    arg = getStrArg(addr, argpos)
    if arg is not None:
        if "reboot" in arg:
            return True
    return False


def checkConstantStr(addr, argpos=0):
    # empty string is not considered as constant, for it may be uninitialized global variable
    return bool(getStrArg(addr, argpos))


def checkSafeFormat(addr, offset=0):
    data = getStrArg(addr, offset)
    if data is None:
        return False

    fmtIndex = offset
    for i in range(len(data) - 1):
        if data[i] == '%' and data[i + 1] != '%':
            fmtIndex += 1
            if data[i + 1] == 's':
                if fmtIndex > 3:
                    return False
                if not checkConstantStr(addr, fmtIndex):
                    return False
    return True


def getCallee(inst):
    callee = None
    if len(inst.pcode):
        if inst.pcode[-1].mnemonic == 'CALL':
            callee = getFunctionAt(inst.getOpObjects(0)[0])
        elif inst.pcode[-1].mnemonic == 'CALLIND':
            regval = getRegister(inst.address, inst.getOpObjects(0)[0])
            if regval is not None:
                callee = getFunctionAt(toAddr(regval.value))
    return callee


referenced = set()


# Uses Basic Block Model instead
# This is closer to a CFG approach
def findSinkPath(target_addr, vuln, target=None):

    # Control-flow search has additional checks, different entry point
    def cf_search(start_func):
        bbm = BasicBlockModel(currentProgram)
        all_blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)

        pending = []
        completed = []
        cur_visited_block_path = []
        taint_path_count = 0
        total_path_count = 0

        if VVERBOSE:
            funcs = currentProgram.getFunctionManager().getFunctions(True)
            print_funcs(funcs)

        # Get symbols
        sm = currentProgram.getSymbolTable()
        symbols = sm.getDefinedSymbols()

        # Find main first
        block = all_blocks.next()
        while all_blocks.hasNext() and block.getName() != 'main':
            block = all_blocks.next()

        # Get first function, then get that block
        if block.getName() != 'main':
            first_func_addr = getFirstFunction().getBody().getMinAddress()
            block = bbm.getCodeBlocksContaining(first_func_addr, TaskMonitor.DUMMY)[0]
            if DEBUG:
                print("\t!!! Could not find main !!!\n\t! Starting from first function !\n")

        # DFS analysis
        flow = [[block.getName(), block.getMinAddress(), block.getFlowType()]]
        while block:
            # Keep track of completed blocks
            completed.append(block)

            if VERBOSE:
                print("\t===BLOCK===")
                print("\tLabel: {}".format(block.getName()))
                print("\tMin Address: {}".format(block.getMinAddress()))
                print("\tMax address: {}".format(block.getMaxAddress()))
                print("\tFlow Type: {}\n".format(block.getFlowType()))
            if VVERBOSE:
                print("\t===DIS===")
                print_disassembly(block)
                print('')
            
            dests = block.getDestinations(TaskMonitor.DUMMY)

            # Check if block is a sink, if so we found a path from source to sink, stop
            if block.getName() in cf_sinks:
                if DEBUG:
                    print("\t===VULN===")
                    print('\t' + block.getName())
                # Can crash script if getCallingArgs calls next incorrectly (wasn't finding reboot yet anyways)
                # if checkReboot(block.getMaxAddress()):
                #     print("Called with REBOOT!")
                # vuln_arg = getStrArg(block.getMaxAddress())
                # if vuln_arg:
                #     print("Found string argument to sink: " + str(vuln_arg))
                # print('\t' + str(flow))

                # Check symbol table for symbol references in this block
                while symbols.hasNext():
                    s = symbols.next()
                    s_refs = s.getReferences()
                    for r in s_refs:
                        r_addr =r.getFromAddress()
                        if r_addr >= block.getMinAddress() and r_addr <= block.getMaxAddress():
                            if DEBUG:
                                print('\t' + str(s) + " referenced in vulnerable block")
                                print('\tRef Address: ' + str(r_addr))
                symbols = sm.getDefinedSymbols()

                # Check path for calls to crypto funcs, etc
                crypto_syms = []
                crypto_in_path = []
                if DEBUG:
                    print("\n\tChecking crypto in path...")

                # First identify crypto symbols so we don't repeat
                while symbols.hasNext():
                    s = symbols.next()
                    for cs in crypto_strs:
                        if cs in s.getName():
                            crypto_syms.append(s)
                symbols = sm.getDefinedSymbols()

                # Now check if refs to crypto symbols in block
                for b in cur_visited_block_path:
                    for s in crypto_syms:
                        s_refs = s.getReferences()
                        for r in s_refs:
                            r_addr = r.getFromAddress()
                            if r_addr >= b.getMinAddress() and r_addr <= b.getMaxAddress():
                                for cs in crypto_strs:
                                    if cs in s.getName():
                                        crypto_in_path.append(s)
                
                global f
                if not crypto_in_path:
                    if DEBUG:
                        print('\tNo crypto found in path\n')
                    print_path_to_file(flow)
                    taint_path_count += 1
                    if f is not None:
                        print >>f, '\tNo crypto found in path\n'
                else:
                    if DEBUG:
                        print("\tCrypto funcs found on path:\n")
                        for fun in crypto_in_path:
                            print('\t' + fun.getName())
                        print('')
                    if f is not None:
                        print >>f, "\tCrypto funcs found on path:\n", 
                        for fun in crypto_in_path:
                            print >>f, '\t', fun.getName()
                        print >>f, '\n'

                total_path_count += 1

            else:
                # This part does the DFS by getting next unvisited child block, explore next
                # If no new destination blocks, we will backtrack
                while dests.hasNext():
                    d = dests.next()
                    d_block = d.getDestinationBlock()
                    if d_block.getName() in cf_sinks or d_block not in completed:
                        pending.append(d_block)
                        # Update current path
                        flow.append([d_block.getName(), d_block.getMinAddress(), d_block.getFlowType()])
                        # If a sink we stop searching down the tree, so don't add this block to current path
                        if d_block.getName() not in cf_sinks:
                            cur_visited_block_path.append(block)
                        break
            
            if pending:
                # Found child, continue down
                block = pending.pop()
            else:
                # No unvisited child, so check if we can backtrack up tree
                if cur_visited_block_path:
                    block = cur_visited_block_path.pop()
                    flow.pop()
                else:
                    # Back to root, done
                    block = None

        # Check symbol table and count total crypto funcs
        if DEBUG:
            crypto_funcs = get_crypto_funcs(sm)
            print("===Crypto===")
            print('Found ' + str(len(crypto_funcs)) + ' potential crypto functions:')
            for cf in crypto_funcs:
                print(str(cf))
            print('')

        if VVERBOSE:
            with open("symbol_table.txt", 'w') as st:
                print >>st, 'SYMBOL TABLE'
                while symbols.hasNext():
                    s = symbols.next()
                    print >>st, "Symbol: ", str(s)
            
        return taint_path_count, total_path_count

    # Keyword search starts at kw ref, simply looks for path
    def kw_search(start_func, vuln):
        bbm = BasicBlockModel(currentProgram)
        block = bbm.getCodeBlocksContaining(start_func, TaskMonitor.DUMMY)[0]

        pending = []
        completed = []
        cur_visited_block_path = []

        if vuln == 'buffer_overflow':
            sinks = bof_sinks
        elif vuln == 'command_injection':
            sinks = cmdi_sinks

        # DFS analysis
        flow = [[block.getName(), block.getMinAddress(), block.getFlowType()]]
        while block:
            # Keep track of completed blocks
            completed.append(block)

            if VERBOSE:
                print("\t===BLOCK===")
                print("\tLabel: {}".format(block.getName()))
                print("\tMin Address: {}".format(block.getMinAddress()))
                print("\tMax address: {}".format(block.getMaxAddress()))
                print("\tFlow Type: {}\n".format(block.getFlowType()))
            if VVERBOSE:
                print("\t===DIS===")
                print_disassembly(block)
                print('')
            
            dests = block.getDestinations(TaskMonitor.DUMMY)

            # Check if block is a sink, if so we found a path from source to sink, stop
            if block.getName() in sinks:
                if DEBUG:
                    print("\t===VULN===")
                    print('\t' + block.getName())
                # Can crash script if getCallingArgs calls next incorrectly (wasn't finding reboot yet anyways)
                # if checkReboot(block.getMaxAddress()):
                #     print("Called with REBOOT!")
                # vuln_arg = getStrArg(block.getMaxAddress())
                # if vuln_arg:
                #     print("Found string argument to sink: " + str(vuln_arg))
                # print('\t' + str(flow))
                if f is not None:
                    if target:
                        print >>f, 'Target: ', target, ' @ ', start_func
                    else:
                        print >>f, 'IPC @ ', start_func
                print_path_to_file(flow)

                return True
            else:
                # This part does the DFS by getting next unvisited child block, explore next
                # If no new destination blocks, we will backtrack
                while dests.hasNext():
                    d = dests.next()
                    d_block = d.getDestinationBlock()
                    if d_block.getName() in sinks or d_block not in completed:
                        pending.append(d_block)
                        # Update current path
                        flow.append([d_block.getName(), d_block.getMinAddress(), d_block.getFlowType()])
                        # If a sink we stop searching down the tree, so don't add this block to current path
                        if d_block.getName() not in sinks:
                            cur_visited_block_path.append(block)
                        break
            
            if pending:
                # Found child, continue down
                block = pending.pop()
            else:
                # No unvisited child, so check if we can backtrack up tree
                if cur_visited_block_path:
                    block = cur_visited_block_path.pop()
                    flow.pop()
                else:
                    # Back to root, done
                    block = None
            
        return False


    def get_crypto_funcs(sm):
        found = []
        symbols = sm.getDefinedSymbols()
        while symbols.hasNext():
            s = symbols.next()
            for c in non_sparse_consts:
                if s == c["name"]:
                    found.append(s)
            for c in sparse_consts:
                if s == c["name"]:
                    found.append(s)
            for c in operand_consts:
                if s == c["name"]:
                    found.append(s)
            for cs in crypto_strs:
                if cs in s.getName():
                    found.append(s)
        
        return found


    def print_path_to_file(path):
        if f is not None:
            print >>f, '[Path to sink: \n\t(>> block name : block addr : flow type)'
            for i in range(len(path)):
                b_name, b_addr, flow_type = path[i]
                print >>f, '\t>>', b_name, '\t: ', a2h(b_addr), '\t: ', flow_type
            print >>f, ']\n'


    def print_disassembly(block):
        listing = currentProgram.getListing()
        insns = listing.getInstructions(block, True)

        while insns.hasNext():
            ins = insns.next()
            print("\t{} {}".format(ins.getAddressString(False, True), ins))


    def print_funcs(func_it):
        while func_it.hasNext():
            f1 = func_it.next()
            print("Function Name",f1.getName())
            print("Function Body" , f1.getBody())
            print("Function Entry" , f1.getEntryPoint())
            print("Functions Calls",f1.getCalledFunctions(TaskMonitor.DUMMY))
            print("Function is Called From",f1.getCallingFunctions(TaskMonitor.DUMMY))
            print('')

    # Determine which search to run
    if vuln == 'control_flow':
        start_func = getFunctionContaining(target_addr)
        return cf_search(start_func)
    elif vuln == 'buffer_overflow' or vuln == 'command_injection':
        # Find entry points for each kw ref
        # If no target then searching IPC, target_addr is already correct
        if target:
            cur_addr = find(target_addr, target)
        else:
            cur_addr = target_addr
        target_found = False
        vuln_path_found = False
        if cur_addr:
            target_found = True
        searched_addrs = []

        # Find each occurrence of target, check if vuln path, stop if there is
        if target:
            while target_found and cur_addr < currentProgram.maxAddress and cur_addr not in searched_addrs and not vuln_path_found:
                searched_addrs.append(cur_addr)
                refs = getReferencesTo(cur_addr)
                # Run search on each ref/entry point
                for r in refs:
                    if kw_search(r.getFromAddress(), vuln):
                        vuln_path_found = True
                        break
                cur_addr = find(cur_addr, target)
        else:
            # IPC, just search the one address
            searched_addrs.append(cur_addr)
            if kw_search(cur_addr, vuln):
                vuln_path_found = True

        if DEBUG:
            if target:
                print("\nFound Target: " + str(target) + "? " + str(target_found))
            else:
                print("\nIPC searched @ " + str(cur_addr))
            print("Path Found? " + str(vuln_path_found))
            print('')
        return vuln_path_found


if __name__ == '__main__':
    args = getScriptArgs()
    paramTargets = set(open(args[0]).read().strip().split())
    if len(args) > 1:
        f = open(args[1], 'w')

    # Get name of current binary (for checking IPC)
    cur_bin = currentProgram.getExecutablePath()
    cur_bin = cur_bin.split('/')[-1]

    # Read from IPC file of form "a_name:a_addr:b_name:b_addr"
    shared_dict = {}
    shared_file = './results/search_results/shared.txt'
    with open(shared_file, 'r') as shared_handle:
        for line in shared_handle:
            parts = line.strip().split(':')
            shared_dict[parts[0]] = parts

    if 'buffer_overflow' in VULNS_TO_CHECK:
        # Perform buffer overflow analysis
        numOfParam = len(paramTargets)
        t = time.time()
        total = 0

        # Check each keyword for bof
        for i, param in enumerate(paramTargets):
            monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, numOfParam))
            total += findSinkPath(currentProgram.minAddress, 'buffer_overflow', param)

        # Check identified IPCs for bof
        for from_bin in shared_dict:
            if shared_dict[from_bin][2] == cur_bin:
                # Run search if IPC to this binary
                addr_b = currentProgram.parseAddress(str(shared_dict[from_bin][3]))[0]
                print('Also searching from ' + str(addr_b) + ' since IPC was detected from: ' + str(shared_dict[from_bin][0]))
                if f is not None:
                    print >>f, 'Also searching from ', str(addr_b), ' since IPC was detected from: ', str(shared_dict[from_bin][0])
                temp_tot = total
                total += findSinkPath(addr_b, 'buffer_overflow')
                if temp_tot != total:
                    print('Found ' + str(total-temp_tot) + ' vulns from IPC')
                    if f is not None:
                        print >>f, 'Found ', str(total-temp_tot), ' vulns from IPC'
                else:
                    print('Found no vulns from IPC')
                    if f is not None:
                        print >>f, 'Found no vulns from IPC'


        t = time.time() - t
        print('\n= Buffer Overflow Analysis =')
        print('Time Elapsed: ' + str(t))
        print('%d way(s) to sink function\n' % total)

        if f is not None:
            print >>f, '\n= Buffer Overflow Analysis ='
            print >>f, 'Time Elapsed:', t
            print >>f, '%d way(s) to sink function\n' % total

    if 'command_injection' in VULNS_TO_CHECK:
        # Perform command injection analysis
        numOfParam = len(paramTargets)
        t = time.time()
        total = 0

        # Check each keyword for cmdi
        for i, param in enumerate(paramTargets):
            monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, numOfParam))
            total += findSinkPath(currentProgram.minAddress, 'command_injection', param)

        # Check identified IPCs for cmdi
        for from_bin in shared_dict:
            if shared_dict[from_bin][2] == cur_bin:
                # Run search if IPC to this binary
                addr_b = currentProgram.parseAddress(str(shared_dict[from_bin][3]))[0]
                print('Also searching from ' + str(addr_b) + ' since IPC was detected from: ' + str(shared_dict[from_bin][0]))
                if f is not None:
                    print >>f, 'Also searching from ', str(addr_b), ' since IPC was detected from: ', str(shared_dict[from_bin][0])
                temp_tot = total
                total += findSinkPath(addr_b, 'command_injection')
                if temp_tot != total:
                    print('Found ' + str(total-temp_tot) + ' vulns from IPC')
                    if f is not None:
                        print >>f, 'Found ', str(total-temp_tot), ' vulns from IPC'
                else:
                    print('Found no vulns from IPC')
                    if f is not None:
                        print >>f, 'Found no vulns from IPC'

        t = time.time() - t
        print('\n= Command Injection Analysis =')
        print('Time Elapsed:' + str(t))
        print('%d way(s) to sink function\n' % total)

        if f is not None:
            print >>f, '\n= Command Injection Analysis ='
            print >>f, 'Time Elapsed: ', t
            print >>f, '%d way(s) to sink function\n' % total

    if 'control_flow' in VULNS_TO_CHECK:
        # Perform control-flow graph and update analysis
        # No IPC because already searching whole program
        t = time.time()
        taint, total = findSinkPath(currentProgram.minAddress, 'control_flow')

        t = time.time() - t
        print('\n= Full program control-flow searched =')
        print('Time Elapsed: ' + str(t))
        print('%d way(s) to sink function' % total)
        print('%d way(s) potentially vulnerable\n' % taint)

        if f is not None:
            print >>f, '\n= Full program control-flow searched ='
            print >>f, 'Time Elapsed:', t
            print >>f, '%d way(s) to sink function' % total
            print >>f, '%d way(s) potentially vulnerable\n' % taint
    
    # Check for IPC from this binary
    also_check = []
    for from_bin in shared_dict:
        if shared_dict[from_bin][0] == cur_bin:
            also_check.append(shared_dict[from_bin][2])

    # Tell user this binary initiates IPC
    if also_check:
        print('Refer to output for the following for IPC from this binary:')
        if f is not None:
            print >>f, 'Refer to output for the following for IPC from this binary:'
        for b in also_check:
            print('\t' + str(b))
            if f is not None:
                print >>f, '\t', str(b)
        print('')

    if f is not None:
        f.close()