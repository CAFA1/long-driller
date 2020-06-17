from __future__ import absolute_import
import copy
import sys
'''
old=copy.deepcopy(sys.path)
#sys.path.insert(0,'/usr/lib/python2.7/')
sys.path=['/usr/lib/python2.7', '/usr/lib/python2.7/plat-x86_64-linux-gnu', '/usr/lib/python2.7/lib-tk','/usr/local/lib/python2.7/dist-packages/']


sys.path=old

print sys_threading.Thread
'''
import logging
from itertools import islice, izip
import angr
import time
import datetime
from . import ExplorationTechnique
import threading as sys_threading 
import os

l = logging.getLogger("angr.exploration_techniques.driller_core")
#long
l.setLevel(logging.DEBUG)

#long write file into driller directory
#generated: string
#to_addr: online expore to addr
def write_file(generated,to_addr):
    driller_queue_dir=''
    with open('/tmp/.cur','r') as f:
        driller_queue_dir=f.read()
    

    id_num = len(os.listdir(driller_queue_dir))
    fuzzer_from = 'online'+hex(to_addr).rstrip('L')
    filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",to:" + fuzzer_from
    filepath = os.path.join(driller_queue_dir, filepath)
    
    
    l.warning("found %d online explore inputs:%s", id_num,repr(generated))
    
    #long check diff
    find_same_flag=0
    for driller_sample in os.listdir(driller_queue_dir):
        driller_sample_path=os.path.join(driller_queue_dir, driller_sample)
        r=open(driller_sample_path,'r')
        content=r.read().rstrip(b'\0')
        r.close()
        #l.waring()
        if content==generated.rstrip(b'\0'):
            find_same_flag=1
            break

    if find_same_flag==0:
        l.warning('generating '+filepath)
        myfile=open(filepath,'wb')
        myfile.write(generated)
        myfile.close()
    else:
        l.warning('the same sample')
        



#long online explore thread
#binary: binary name
#find_addr: int
def OnlineExplore(binary,find_addr):  
    cur_time=datetime.datetime.now()
    l.warning('%s %s %s : %s \n' % (cur_time.hour,cur_time.minute,cur_time.second,'begin online explore'))
    #print 'start online explore thread time:', time.strftime('%H:%M:%S')
    proj = angr.Project(binary, load_options={"auto_load_libs": False})
    state1 = proj.factory.entry_state(stdin=angr.SimFile)
    sm = proj.factory.simulation_manager(state1)
    sm.explore(find=find_addr) #, avoid=AVOID_ADDR)
    generated=''
    for find_state in sm.found:
        generated = find_state.posix.stdin.load(0, find_state.posix.stdin.size)
        generated = find_state.se.eval(generated, cast_to=str)
        write_file(generated,find_addr)

    cur_time=datetime.datetime.now()
    l.warning('%s %s %s : %s \n' % (cur_time.hour,cur_time.minute,cur_time.second,'stop online explore')) 
class DrillerCore(ExplorationTechnique):
    """
    An exploration technique that symbolically follows an input looking for new
    state transitions.

    It has to be used with Tracer exploration technique. Results are put in
    'diverted' stash.
    """

    def __init__(self, trace, fuzz_bitmap=None):
        """
        :param trace      : The basic block trace.
        :param fuzz_bitmap: AFL's bitmap of state transitions. Defaults to saying every transition is worth satisfying.
        """

        super(DrillerCore, self).__init__()
        self.trace = trace
        self.fuzz_bitmap = fuzz_bitmap or "\xff" * 65536

        # Set of encountered basic block transitions.
        self.encounters = set()

    def setup(self, simgr):
        self.project = simgr._project

        # Update encounters with known state transitions.
        self.encounters.update(izip(self.trace, islice(self.trace, 1, None)))


    def complete(self, simgr):
        return not simgr.active or simgr.one_active.globals['bb_cnt'] >= len(self.trace)
    #long
    def ForwardProbe(self, state,log_str):
        steps = 0
        p = angr.Project(self.project.filename)
        #l.warning("start ForwardProbe at "+hex(state.addr))
        prev_states=[state]
        while steps < 3:
            prev_addrs=[m.addr for m in prev_states]
            strmy=[hex(m) for m in prev_addrs]
            l.warning('prev: '+repr(strmy))
            prev_states1=set()
            for prev_state in prev_states:
                prev_addr=prev_state.addr
                simgr = p.factory.simgr(prev_state,save_unsat=True)
                simgr.step()
                this_states=simgr.stashes['active'] +simgr.stashes['unsat']#long unsat
                #l.warning('active: '+repr(simgr.stashes['active']))
                #l.warning('unsat: '+repr(simgr.stashes['unsat']))
                this_addrs=[m.addr for m in this_states]
                strmy=[hex(m) for m in this_addrs]
                l.warning('this: '+repr(strmy))
                for this_state in this_states:
                    #state=this_state.copy()
                    prev_states1.add(this_state.copy())
                    this_addr=this_state.addr
                    prev_loc = prev_addr
                    prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                    prev_loc &= len(self.fuzz_bitmap) - 1
                    prev_loc = prev_loc >> 1
                    cur_loc = this_addr
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= len(self.fuzz_bitmap) - 1
                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)
                    #if (len(simgr._stashes['active']) > 1 or ((prev_addr,this_addr) not in self.encounters and not hit)):
                    if ((prev_addr,this_addr) not in self.encounters and not hit):
                        #self.encounters.add((prev_addr,this_addr)) #add to the encounters after
                        #self.fuzz_bitmap[cur_loc ^ prev_loc] = chr(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) & ~1)
                        l.warning('flip : '+log_str+' because found: '+hex(prev_addr)+' --> '+hex(this_addr))
                        logfile=open('/tmp/probe.txt','a')
                        cur_time=datetime.datetime.now()
                        logfile.write('%s %s %s : %s \n' % (cur_time.hour,cur_time.minute,cur_time.second,log_str))
                        logfile.close()
                        #long online symbolic thread to explore this address
                        if 0:
                            thread1 = sys_threading.Thread(target = OnlineExplore,args=[self.project.filename,this_addr])  
                            thread1.setDaemon(True)
                            thread1.start()
                            thread1.join(600)
                        #time.sleep(10000)
                        return 1
            prev_states=[]
            for prev_state in prev_states1:
                prev_states.append(prev_state.copy())
            steps += 1
            l.warning(str(steps))
            
        return 0

    def step(self, simgr, stash='active', **kwargs):
        simgr.step(stash=stash, **kwargs)

        # Mimic AFL's indexing scheme.
        if 'missed' in simgr.stashes and simgr.missed:
            # A bit ugly, might be replaced by tracer.predecessors[-1] or crash_monitor.last_state.
            prev_addr = simgr.one_missed.history.bbl_addrs[-1]
            prev_loc = prev_addr
            prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
            prev_loc &= len(self.fuzz_bitmap) - 1
            prev_loc = prev_loc >> 1

            for state in simgr.missed:
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)

                transition = (prev_addr, state.addr)
                mapped_to = self.project.loader.find_object_containing(state.addr).binary

                #l.debug("Found %#x -> %#x transition.", transition[0], transition[1])
                #long
                log_str=hex(transition[0])+' --> '+hex(transition[1])
                #long disable encounters
                #if not hit and transition not in self.encounters and not self._has_false(state) and mapped_to != 'cle##externs':
                if not self._has_false(state) and mapped_to != 'cle##externs':
                    diverted_flag=0
                    if transition  in self.encounters or hit:
                        state1 = state.copy()
                        state1.preconstrainer.remove_preconstraints()
                        if state1.satisfiable():
                            if(self.ForwardProbe(state1,log_str)):
                                diverted_flag=1
                    else:
                        diverted_flag=1
                    if(diverted_flag==1):
                        state.preconstrainer.remove_preconstraints()
                        if state.satisfiable():
                            # A completely new state transition.
                            #l.debug("Found a completely new transition, putting into 'diverted' stash.")
                            #l.debug(repr(state.se.constraints))
                            l.debug("Found diverted transition %#x -> %#x.", transition[0], transition[1])
                            simgr.stashes['diverted'].append(state)
                            self.encounters.add(transition)
                            #long update bitmap # no need update;relay on the fuzzer to update
                            #self.fuzz_bitmap[cur_loc ^ prev_loc]=chr(ord(self.fuzz_bitmap[cur_loc ^ prev_loc])&~1)
                        else:
                            l.debug("State at %#x is not satisfiable.", transition[1])
                            pass
                    else:
                        l.debug("%#x -> %#x transition has already been encountered even after ForwardProbe.", transition[0], transition[1])
                        pass

                

        return simgr

    #
    # Private methods
    #

    @staticmethod
    def _has_false(state):
        # Check if the state is unsat even if we remove preconstraints.
        claripy_false = state.se.false
        if state.scratch.guard.cache_key == claripy_false.cache_key:
            return True

        for c in state.se.constraints:
            if c.cache_key == claripy_false.cache_key:
                return True

        return False
