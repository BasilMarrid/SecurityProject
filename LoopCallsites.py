import angr
import itertools
import re
from capstone import *
from capstone.arm64 import *

#Call-Sites detection:
#entry_func.get_call_target
def Detect_Callsites(cfg):
    callsites = dict()
    for func in cfg.kb.functions.values():
        for callsite in func.get_call_sites():
            if func.get_call_target(callsite) is None:
                continue
            callsites[callsite]=func.get_call_target(callsite)
    return  callsites





#Loop finder
#1-  Detect all loops given in a specific binary - angr's Loopfinder method
#The loop finder method returns a list of Loop object containing information about
#the loops such as: entry blocks, entry edges, break edges and continue edges
#2-  replace all starting statements in a loop entry block with the word loops
#3- replace all break edges and continue edges with the words break and continue
#steps 2 and 3 can be done by finding all addresses of continues and break and replacing
# the line in those addresses with the words continue and break.
def Detect_Loops(proj):
    entriesAddresses = dict()   #(address,LoopNumber)- contains the address of the entry and the numebr of the loop(incase of subloops)
    continueAddresses = set() #continue addresses
    breakAddresses = set() #break addresses
    for loop in proj.analyses.LoopFinder().loops:
        number = find_Loop_Depth(loop,0)
        entriesAddresses[loop.entry.addr]=f"Loop{number}"
        for edge in loop.continue_edges:
            continueAddresses.add(proj.factory.block(edge[0].addr))
        for edge in loop.break_edges:
            breakAddresses.add(proj.factory.block(edge[0].addr))
    #notice while updating addresses in the sm_to_output section that in continue and break cases
    #the last command in the black should be updated to be the keyword in continue and break and in
    # the loop enteries addresses
    return (entriesAddresses,continueAddresses,breakAddresses)

def find_Loop_Depth(loop,i):
    if(i==5):
        return 5
    if(len(loop.subloops)==0):
        return i
    max = 0;
    for l in loop.subloops:
         temp= find_Loop_Depth(l,i+1)
         if(temp>max):
            max=temp
    return max
def con_to_str(con, replace_strs=[', ', ' ', '(', ')'], max_depth=8):
    repr = con.shallow_repr(max_depth=max_depth, details=con.MID_REPR).replace('{UNINITIALIZED}', '')
    for r_str in replace_strs:
        repr = repr.replace(r_str, '|')

    return remove_consecutive_pipes(repr) + "\t"
def remove_consecutive_pipes(s1):
    return re.sub("(\|)+", "|", s1)

def gen_new_name(old_name, counters):
    if re.match(r"mem", old_name):
        return 'mem_%d' % next(counters['mem'])
    if re.match(r"fake_ret_value", old_name):
        return 'ret_%d' % next(counters['ret'])
    if re.match(r"reg", old_name):
        return re.sub("(_[0-9]+)+", '', old_name)
    if re.match(r"unconstrained_ret", old_name):
        return re.sub("(_[0-9]+)+", '', old_name[len("unconstrained_ret_") : ])
    return old_name
def varify_cons(cons, var_map=None, counters=None, max_depth=8):
    """
    abstract away constants from the constraints
    """
    counters = {'mem': itertools.count(), 'ret': itertools.count()} if counters is None else counters
    var_map = {} if var_map is None else var_map
    new_cons = []

    for con in cons:
        if con.concrete:
            continue
        for v in con.leaf_asts():
            if v.cache_key not in var_map and v.op in { 'BVS', 'BoolS', 'FPS' }:
                new_name = gen_new_name(v.args[0], counters=counters)
                var_map[v.cache_key] = v._rename(new_name)
        new_cons.append(con_to_str(con.replace_dict(var_map), max_depth=max_depth))

    return var_map, new_cons


def tokenize_function_name(function_name):
    return "|".join(function_name.split("_"))

def block_to_ins(block: angr.block.Block):
    result = []
    for ins in block.capstone.insns:
        if(ins.menmonics == "push" || ins.menmonics == "pop"):
            continue
        op_str = ins.op_str
        operands=[]
        operands_str = op_str.strip(" ").split(",")
        k = 0
        for operand in ins.operands:
            if operand.type == ARM64_OP_REG:
                operands.append("REG")
            else:
                operands.append(operands_str[k])
            k=k+1
        operands = [i.strip().replace("[","").replace("]", "") for i in operands if i != ""]
        parsed_ins = [ins.mnemonic] + list(filter(None, operands))
        result.append("|".join(parsed_ins).replace(" ", "|") + "|\t")
        # result.append(f"{ins.mnemonic}|{operands[0]}|{operands[1]}".replace(" ", "|"))
    return "|".join(result)
def get_addr(block):
    return block.addr


def LoopReplace(proj,cfg,entriesAddresses,continueAddresses,breakAddresses):
    var_map={}
    counters={'mem':itertools.count(),'ret':itertools.count()}
    output=open("OurOut.txt","w")
    call_state=proj.factory.entry_state()
    sm = proj.factory.simulation_manager(call_state)
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg,bound=0))
    sm.run()
    callsites=Detect_Callsites(cfg)
    for exec_paths in sm.stashes.values():
        for exec_path in exec_paths:
            processed_code = ""
            blocks = [proj.factory.block(baddr) for baddr in exec_path.history.bbl_addrs]
#            processed_code = "|".join(list(filter(None, map(block_to_ins, blocks))))

            for block in blocks:
                block_code = ""
                if block.addr in callsites:
                    func_addr = callsites[block.addr]
                    called_func = cfg.kb.functions[func_addr]
                    block_code = f"call {called_func.name}|\t"
                elif block.addr in entriesAddresses:
                    block_code = entriesAddresses[block.addr]+"|\t"
                else:
                    block_code = block_to_ins(block)
                processed_code += ("|" + block_code)
			# processed_code now holds the instructions converted from blocks of the current # state
            var_map, relified_consts = varify_cons(exec_path.solver.constraints, var_map=var_map, counters=counters)
			# relified_consts holds the solved constraints(the optimized equations)
            relified_consts = "|".join(relified_consts)
            found_constants = set(re.findall(r"0[xX][0-9a-fA-F]+", processed_code))
			# we find all the hexadecimal constants in line
            for constant in found_constants:
                processed_code=processed_code.replace(constant,"C")
			# we separate constraints by the | dilemeter
            func_name="Output"
            line = f"{tokenize_function_name(func_name)} DUM,{processed_code}|CONS|{relified_consts},DUM\n"
            output.write(line)
            #MB:        constants_mapper[constant] = f"const_{next(constants_counter)}"
			# the upper loop iterates over all constants, adding the new ones while updating
			# the counter
            #MB: for constant, replacement in sorted(constants_mapper.items(), key=lambda x: len(x[0]), reverse=True):
            #MB:    line = line.replace(constant, replacement)
			# TODO: we replace all constants with their mappings in line (in reverse?)





proj = angr.Project("a.out", auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True)
(entriesAddresses,continueAddresses,breakAddresses)=Detect_Loops(proj)
LoopReplace(proj,cfg,entriesAddresses,continueAddresses,breakAddresses)
