
<!-- TOC -->

- [28. driller](#28-driller)
	- [28.1 driller.Driller](#281-drillerdriller)
	- [28.2 d.drill()](#282-ddrill)
	- [28.3 _drill_input()](#283-_drill_input)
		- [28.3.1 tracer实验（no）](#2831-tracer实验no)
		- [28.3.2 angr hook实验（no）](#2832-angr-hook实验no)
		- [28.3.3 preconstrain_file 将符号文件具体化，往状态约束里面添加这个约束](#2833-preconstrain_file-将符号文件具体化往状态约束里面添加这个约束)
		- [28.3.4 _writeout 记录新发现的路径以及求解的输入](#2834-_writeout-记录新发现的路径以及求解的输入)
		- [28.3.5 关键在于driller core的step了，怎么找到的diverted。](#2835-关键在于driller-core的step了怎么找到的diverted)
			- [28.3.5.1 ‘missed’ stash中存储的是trace中没有遍历的分支](#28351-missed-stash中存储的是trace中没有遍历的分支)
			- [28.3.5.2 remove_preconstraints 清除原来的输入约束](#28352-remove_preconstraints-清除原来的输入约束)
		- [28.3.6 use_technique实际是hook了sim_manager的一些函数](#2836-use_technique实际是hook了sim_manager的一些函数)
		- [28.3.7 _symbolic_explorer_stub](#2837-_symbolic_explorer_stub)
- [29. shellphuzz](#29-shellphuzz)
	- [29.1 fuzzer.start()](#291-fuzzerstart)
		- [29.1.1 _start_afl <- start fuzzer.py](#2911-_start_afl---start-fuzzerpy)
		- [29.1.2 _start_afl_instance <- _start_afl fuzzer.py](#2912-_start_afl_instance---_start_afl-fuzzerpy)
	- [29.2 fuzzer/fuzzer.py : _create_dict](#292-fuzzerfuzzerpy--_create_dict)
	- [29.3 fuzzer/bin/create_dict.py](#293-fuzzerbincreate_dictpy)
	- [29.4 _timer定时器](#294-_timer定时器)
		- [29.4.1 Fuzzer类__init__初始化self._timer](#2941-fuzzer类__init__初始化self_timer)
		- [29.4.2 InfiniteTimer类](#2942-infinitetimer类)
		- [29.4.3 Fuzzer::_timer_callback回调函数 fuzzer/fuzzer.py](#2943-fuzzer_timer_callback回调函数-fuzzerfuzzerpy)
			- [29.4.3.1 stats来自afl目录fuzzer_stats](#29431-stats来自afl目录fuzzer_stats)
		- [29.4.4 _stuck_callback函数<-_timer_callback函数](#2944-_stuck_callback函数-_timer_callback函数)
		- [29.4.5 drill_extension回调函数<-_stuck_callback](#2945-drill_extension回调函数-_stuck_callback)
		- [29.4.6 LocalCallback:: driller_callback <-drill_extension](#2946-localcallback-driller_callback--drill_extension)
			- [29.4.6.1 _queue_files 索引queue目录里面的文件名](#29461-_queue_files-索引queue目录里面的文件名)
		- [29.4.7 _run_drill <- driller_callback](#2947-_run_drill---driller_callback)
		- [29.4.8 driller/local_callback.py __main__](#2948-drillerlocal_callbackpy-__main__)
		- [29.4.9 drill_generator<- _run_drill](#2949-drill_generator--_run_drill)
		- [29.4.10 _timer.start 开启计时器](#29410-_timerstart-开启计时器)
	- [29.5 seeds初始化](#295-seeds初始化)
		- [29.5.1 Fuzzer::__init__](#2951-fuzzer__init__)
		- [29.5.2 _initialize_seeds](#2952-_initialize_seeds)
- [30. driller与fuzzer同步的问题](#30-driller与fuzzer同步的问题)
	- [30.1 start_listener driller/tasks.py 不是](#301-start_listener-drillertaskspy-不是)
	- [30.2 listen.py <- start_listener 不是](#302-listenpy---start_listener-不是)
	- [30.3 问题是afl的同步](#303-问题是afl的同步)
- [31. step](#31-step)
	- [31.1 sim_manager.py step 主要是分类可解不可解](#311-sim_managerpy-step-主要是分类可解不可解)
		- [31.1.1 step_state <- step执行一步](#3111-step_state---step执行一步)
		- [31.1.2 sim_manager.py successors <- step_state](#3112-sim_managerpy-successors---step_state)
			- [31.1.2.1 factory.py successors <- sim_manager.py successors](#31121-factorypy-successors---sim_managerpy-successors)
			- [31.1.2.2 hub.py successors <- factory.py successors](#31122-hubpy-successors---factorypy-successors)
			- [31.1.2.3 vex/engine.py process](#31123-vexenginepy-process)
			- [31.1.2.4 engine/engine.py process](#31124-engineenginepy-process)
			- [31.1.2.5 vex/engine.py _process](#31125-vexenginepy-_process)
			- [31.1.2.6 _handle_irsb angr/engines/vex/engine.py](#31126-_handle_irsb-angrenginesvexenginepy)
				- [31.1.2.6.1 _handle_statement SimIRStmt_Exit例子](#311261-_handle_statement-simirstmt_exit例子)
			- [31.1.2.7 add_successor engines/successors.py 添加后继](#31127-add_successor-enginessuccessorspy-添加后继)
			- [31.1.2.8 SimSuccessors :: _categorize_successor <- add_successor engines/successors.py分类](#31128-simsuccessors--_categorize_successor---add_successor-enginessuccessorspy分类)
	- [31.2 stashes操作](#312-stashes操作)
		- [31.2.1 _store_states 保存状态到stash](#3121-_store_states-保存状态到stash)
		- [31.2.2 stash函数将active保存到stashed](#3122-stash函数将active保存到stashed)
		- [31.2.3 unstash 函数](#3123-unstash-函数)
		- [31.2.4 drop函数](#3124-drop函数)
	- [31.3 tracer.py step -> sim_manager.py step](#313-tracerpy-step---sim_managerpy-step)
	- [31.4 driller_core.py step -> tracer.py step](#314-driller_corepy-step---tracerpy-step)
		- [31.4.1 one_missed angr/sim_manager.py](#3141-one_missed-angrsim_managerpy)
		- [31.4.2 _fetch_states angr/sim_manager.py](#3142-_fetch_states-angrsim_managerpy)
		- [31.4.3 remove_preconstraints <- step](#3143-remove_preconstraints---step)
		- [31.4.4 覆盖率统计](#3144-覆盖率统计)
			- [31.4.4.1 afl_maybe_log (afl qemu mode )](#31441-afl_maybe_log-afl-qemu-mode-)
- [32. hook api](#32-hook-api)
	- [32.1 file.py read](#321-filepy-read)
	- [32.2 strcmp](#322-strcmp)
	- [32.3 crc32](#323-crc32)
		- [32.3.1 调用流程](#3231-调用流程)
			- [32.3.1.0 SimEngineHook: check  hook.py](#32310-simenginehook-check--hookpy)
			- [32.3.1.1 hook.py:process](#32311-hookpyprocess)
			- [32.3.1.2 procedure.py:_process](#32312-procedurepy_process)
			- [32.3.1.3 sim_procedure.py:execute](#32313-sim_procedurepyexecute)
			- [32.3.1.4 ReturnUnconstrained](#32314-returnunconstrained)
		- [32.3.2 初始化流程](#3232-初始化流程)
			- [32.3.2.1 __init__,project.py:209](#32321-__init__projectpy209)
			- [32.3.2.2 _register_object, project.py:295](#32322-_register_object-projectpy295)
			- [32.3.2.3 hook_symbol, project.py:462](#32323-hook_symbol-projectpy462)
			- [32.3.2.4 hook, project.py:352](#32324-hook-projectpy352)
- [33. hook](#33-hook)
	- [33.1 测试代码：教给我们hook以及添加约束](#331-测试代码教给我们hook以及添加约束)
	- [33.2 hook函数 angr/angr/project.py](#332-hook函数-angrangrprojectpy)
	- [33.3 约束](#333-约束)
- [34. angr-doc例子](#34-angr-doc例子)
	- [34.1 例子 angr-doc/examples/asisctffinals2015_fake](#341-例子-angr-docexamplesasisctffinals2015_fake)
		- [34.1.1 代码](#3411-代码)
	- [34.2 explore angr/angr/sim_manager.py](#342-explore-angrangrsim_managerpy)
		- [34.2.1 run<-explore](#3421-run-explore)
			- [34.2.1.1 step<-run<-explore](#34211-step-run-explore)
		- [34.2.2 use_technique(Explorer<-explore](#3422-use_techniqueexplorer-explore)

<!-- /TOC -->
# 28. driller
	https://blog.csdn.net/chen_zju/article/details/80791281
	安装使用
	driller工具是由python语言写的，主要依赖于angr，afl等2个工具。我们可以通过shellphfuzz工具来使用driller，安装步骤可以参考博客driller安装教程 
	使用方式： 
	官方推荐的driller的使用方法是通过shellphuzz工具来使用，使用方式如下，“-i”选项指定afl-fuzz的线程数，“-d”选项指定driller（即符号执行工具）的线程数，如果不使用-d或者-d 0，则不使用符号执行。
	# fuzz with 4 AFL cores
	shellphuzz -i -c 4 /path/to/binary

	# perform symbolic-assisted fuzzing with 4 AFL cores and 2 symbolic tracing (drilling) cores.
	shellphuzz -i -c 4 -d 2 /path/to/binary
## 28.1 driller.Driller
	d = driller.Driller(os.path.join(bin_location, binary), "AAAA", "\xff"*65535, "whatever~")

	class Driller(object):
		"""
		Driller object, symbolically follows an input looking for new state transitions.
		"""

		def __init__(self, binary, input_str, fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None):
			"""
			:param binary	 : The binary to be traced.
			:param input_str  : Input string to feed to the binary.
			:param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
			:param redis	  : redis.Redis instance for coordinating multiple Driller instances.
			:param hooks	  : Dictionary of addresses to simprocedures.
			:param argv	   : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
								defaults to binary name with no params.
			"""

			self.binary	  = binary

			# Redis channel identifier.
			self.identifier  = os.path.basename(binary)
			self.input	   = input_str
			self.fuzz_bitmap = fuzz_bitmap
			self.tag		 = tag
			self.redis	   = redis
			self.argv = argv or [binary]

			self.base = os.path.join(os.path.dirname(__file__), "..")

			# The simprocedures.
			self._hooks = {} if hooks is None else hooks

			# The driller core, which is now an exploration technique in angr.
			self._core = None

			# Start time, set by drill method.
			self.start_time = time.time()

			# Set of all the generated inputs.
			self._generated = set()

			# Set the memory limit specified in the config.
			if config.MEM_LIMIT is not None:
				resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

			l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))
## 28.2 d.drill()
	new_inputs = d.drill()

	def drill(self):
			"""
			Perform the drilling, finding more code coverage based off our existing input base.
			"""

			# Don't re-trace the same input.
			if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
				return -1

			# Write out debug info if desired.
			if l.level == logging.DEBUG and config.DEBUG_DIR:
				self._write_debug_info()
			elif l.level == logging.DEBUG and not config.DEBUG_DIR:
				l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

			# Update traced.
			if self.redis:
				self.redis.sadd(self.identifier + '-traced', self.input)

			list(self._drill_input())

			if self.redis:
				return len(self._generated)
			else:
				return self._generated
	在redis中记录每个二进制traced的input字符串值。Sadd sismember用法
## 28.3 _drill_input()
	list(self._drill_input())

	def _drill_input(self):
			"""
			Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
			state transitions.
			"""

			# initialize the tracer
			r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv) 注意这里有输入
			p = angr.Project(self.binary)
			for addr, proc in self._hooks.items():
				p.hook(addr, proc)
				l.debug("Hooking %#x -> %s...", addr, proc.display_name)

			if p.loader.main_object.os == 'cgc':
				p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

				s = p.factory.entry_state(stdin=angr.storage.file.SimFileStream, flag_page=r.magic)
			else:
				s = p.factory.full_init_state(stdin=angr.storage.file.SimFileStream)

			s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True) 是对标准输入文件做的

			simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

			t = angr.exploration_techniques.Tracer(trace=r.trace)
			c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_addr=r.crash_addr)
			self._core = angr.exploration_techniques.DrillerCore(trace=r.trace)

			if r.crash_mode:
				simgr.use_technique(c)
			simgr.use_technique(t)
			simgr.use_technique(angr.exploration_techniques.Oppologist())
			simgr.use_technique(self._core)

			self._set_concretizations(simgr.one_active) 设置了阈值常数

			l.debug("Drilling into %r.", self.input)
			l.debug("Input is %r.", self.input)

			while simgr.active and simgr.one_active.globals['bb_cnt'] < len(r.trace):
				simgr.step() #liu 见31.4

				# Check here to see if a crash has been found.
				if self.redis and self.redis.sismember(self.identifier + '-finished', True):
					return

				if 'diverted' not in simgr.stashes: #liu in step(31.4) function find the 'diverted' state
					continue
				#http://angr.io/api-doc/angr.html
				while simgr.diverted:
					state = simgr.diverted.pop(0)
					l.debug("Found a diverted state, exploring to some extent.")
					w = self._writeout(state.history.bbl_addrs[-1], state) #liu solve the state and generate a new sample
					if w is not None:
						yield w
					for i in self._symbolic_explorer_stub(state):
						yield i
### 28.3.1 tracer实验（no）
	r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
### 28.3.2 angr hook实验（no）
	p.hook(addr, proc)
### 28.3.3 preconstrain_file 将符号文件具体化，往状态约束里面添加这个约束
	s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)
	在angr/angr/state_plugins/preconstrainer.py文件中

	def preconstrain_file(self, content, simfile, set_length=False):
		"""
		Preconstrain the contents of a file.
		:param content:	 The content to preconstrain the file to. Can be a bytestring or a list thereof.
		:param simfile:	 The actual simfile to preconstrain
		"""
		repair_entry_state_opts = False
		if o.TRACK_ACTION_HISTORY in self.state.options:
			repair_entry_state_opts = True
			self.state.options -= {o.TRACK_ACTION_HISTORY}

		if set_length: # disable read bounds
			simfile.has_end = False

		pos = 0
		for write in content:
			data, length, pos = simfile.read(pos, len(write), short_reads=False)
			if not claripy.is_true(length == len(write)):
				raise AngrError("Bug in either SimFile or in usage of preconstrainer: couldn't get requested data from file")
			self.preconstrain(write, data)

		# if the file is a stream, reset its position
		if simfile.pos is not None:
			simfile.pos = 0

		if set_length: # enable read bounds; size is now maximum size
			simfile.has_end = True

		if repair_entry_state_opts:
			self.state.options |= {o.TRACK_ACTION_HISTORY}

	def preconstrain(self, value, variable):
			"""
			Add a preconstraint that ``variable == value`` to the state.
			:param value:	   The concrete value. Can be a bitvector or a bytestring or an integer.
			:param variable:	The BVS to preconstrain.
			"""
			if not isinstance(value, claripy.ast.Base):
				value = self.state.solver.BVV(value, len(variable))
			elif value.op != 'BVV':
				raise ValueError("Passed a value to preconstrain that was not a BVV or a string")

			constraint = variable == value
			l.debug("Preconstraint: %s", constraint)

			# add the constraint for reconstraining later
			self.variable_map[next(iter(variable.variables))] = constraint
			self.preconstraints.append(constraint)
			if o.REPLACEMENT_SOLVER in self.state.options:
				self.state.solver._solver.add_replacement(variable, value, invalidate_cache=False)
			else:
				self.state.add_constraints(*self.preconstraints)
			if not self.state.satisfiable():
				l.warning("State went unsat while adding preconstraints")
### 28.3.4 _writeout 记录新发现的路径以及求解的输入
	l.debug("Found a diverted state, exploring to some extent.")
	w = self._writeout(state.history.bbl_addrs[-1], state)

	def _writeout(self, prev_addr, state):
			generated = state.posix.stdin.load(0, state.posix.stdin.pos) #liu 只有标准输入的求解！！！
			generated = state.se.eval(generated, cast_to=str)

			key = (len(generated), prev_addr, state.addr)

			# Checks here to see if the generation is worth writing to disk.
			# If we generate too many inputs which are not really different we'll seriously slow down AFL.
			if self._in_catalogue(*key):
				self._core.encounters.remove((prev_addr, state.addr))
				return None

			else:
				self._add_to_catalogue(*key)

			l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

			self._generated.add((key, generated))

			if self.redis:
				# Publish it out in real-time so that inputs get there immediately.
				channel = self.identifier + '-generated'

				self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag})) 通过redis发布新发现

			else:
				l.debug("Generated: %s", generated.encode('hex'))

			return (key, generated)
### 28.3.5 关键在于driller core的step了，怎么找到的diverted。
	l.debug("Found a completely new transition, putting into 'diverted' stash.")
	/home/l/driller/angr/angr/exploration_techniques/driller_core.py

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

				l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

				if not hit and transition not in self.encounters and not self._has_false(state) and mapped_to != 'cle##externs': #liu traversal algorithm
					state.preconstrainer.remove_preconstraints()

					if state.satisfiable():
						# A completely new state transition.
						l.debug("Found a completely new transition, putting into 'diverted' stash.")
						simgr.stashes['diverted'].append(state) #liu add the new state to stashes
						self.encounters.add(transition)

					else:
						l.debug("State at %#x is not satisfiable.", transition[1])

				elif self._has_false(state):
					l.debug("State at %#x is not satisfiable even remove preconstraints.", transition[1])

				else:
					l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

		return simgr
#### 28.3.5.1 ‘missed’ stash中存储的是trace中没有遍历的分支
	/home/l/driller/angr/angr/exploration_techniques/tracer.py里面的step函数

	if len(simgr.active) > 1:
		# if we get to this point there's more than one active path
		# if we have to ditch the trace we use satisfiability
		# or if a split occurs in a library routine
		a_paths = simgr.active

		if self._no_follow or all(map( lambda p: not self._address_in_binary(p.addr), a_paths)):
			simgr.prune(to_stash='missed')
		else:
			l.debug("bb %d / %d", current.globals['bb_cnt'], len(self._trace))
			if current.globals['bb_cnt'] < len(self._trace):
				simgr.stash(lambda s: s.addr != self._trace[current.globals['bb_cnt']], to_stash='missed')
		if len(simgr.active) > 1: # rarely we get two active paths
			simgr.prune(to_stash='missed')
	其中的stash函数其实就是move函数，有了缺省值。
	def stash(self, filter_func=None, from_stash='active', to_stash='stashed'):
			"""
			Stash some states. This is an alias for move(), with defaults for the stashes.

			:param filter_func: Stash states that match this filter. Should be a function that
								takes a state and returns True or False. (default: stash all states)
			:param from_stash:  Take matching states from this stash. (default: 'active')
			:param to_stash:	Put matching states into this stash. (default: 'stashed')

			:returns:		   The resulting SimulationManager
			:rtype:			 SimulationManager
			"""
			return self.move(from_stash, to_stash, filter_func=filter_func)
#### 28.3.5.2 remove_preconstraints 清除原来的输入约束
	/home/l/driller/angr/angr/state_plugins/preconstrainer.py
	def remove_preconstraints(self, to_composite_solver=True, simplify=True):
		if not self.preconstraints:
			return

		# cache key set creation
		precon_cache_keys = set()

		for con in self.preconstraints:
			precon_cache_keys.add(con.cache_key)

		# if we used the replacement solver we didn't add constraints we need to remove so keep all constraints
		if o.REPLACEMENT_SOLVER in self.state.options:
			new_constraints = self.state.se.constraints
		else:
			new_constraints = filter(lambda x: x.cache_key not in precon_cache_keys, self.state.se.constraints)

		if self.state.has_plugin("zen_plugin"):
			new_constraints = self.state.get_plugin("zen_plugin").filter_constraints(new_constraints)

		if to_composite_solver:
			self.state.options.discard(o.REPLACEMENT_SOLVER)
			self.state.options.add(o.COMPOSITE_SOLVER)

		self.state.release_plugin('solver')
		self.state.add_constraints(*new_constraints)

		l.debug("downsizing unpreconstrained state")
		self.state.downsize()

		if simplify:
			l.debug("simplifying solver...")
			self.state.solver.simplify()
			l.debug("...simplification done")

		self.state.solver._solver.result = None
### 28.3.6 use_technique实际是hook了sim_manager的一些函数
	def use_technique(self, tech):
		"""
		Use an exploration technique with this SimulationManager.

		Techniques can be found in :mod:`angr.exploration_techniques`. 位于angr/angr/ exploration_techniques文件夹中

		:param tech:	An ExplorationTechnique object that contains code to modify
						this SimulationManager's behavior.
		:type tech:	 ExplorationTechnique
		:return:		The technique that was added, for convenience
		"""
		if not isinstance(tech, ExplorationTechnique):
			raise SimulationManagerError

		# XXX: as promised
		tech.project = self._project
		tech.setup(self)

		def _is_overriden(name):
			return getattr(tech, name).__code__ is not getattr(ExplorationTechnique, name).__code__

		overriden = filter(_is_overriden, ('step', 'filter', 'selector', 'step_state', 'successors')) #hook这些函数
		hooks = {name: getattr(tech, name) for name in overriden}
		HookSet.install_hooks(self, **hooks)

		self._techniques.append(tech)
		return tech
### 28.3.7 _symbolic_explorer_stub
	Driller/driller/driller_main.py
	def _symbolic_explorer_stub(self, state):
		# Create a new simulation manager and step it forward up to 1024
		# accumulated active states or steps.
		steps = 0
		accumulated = 1

		p = angr.Project(self.binary)
		simgr = p.factory.simgr(state, immutable=False, hierarchy=False)

		l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

		while len(simgr.active) and accumulated < 1024:
			simgr.step()
			steps += 1

			# Dump all inputs.
			accumulated = steps * (len(simgr.active) + len(simgr.deadended))

		l.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

		for dumpable in simgr.deadended:
			try:
				if dumpable.satisfiable():
					w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
					if w is not None:
						yield w

			# If the state we're trying to dump wasn't actually satisfiable.
			except IndexError:
				pass
# 29. shellphuzz
	在fuzzer没有发现新的transition的时候(Fuzzer::_timer_callback回调函数 fuzzer/fuzzer.py,见29.4.3)，调用driller（Fuzzer::_stuck_callback-> driller_callback，见29.4.8）来求解新路径。
	Driller会执行afl queue中每一个样本，然后将新发现放到driller/queue。
	Afl同步机制会从driller/queue获取driller新发现的样本，添加到自己的queue。
	if args.driller_workers:
	print "[*] Drilling..."
	drill_extension = driller.LocalCallback(num_workers=args.driller_workers, worker_timeout=args.driller_timeout, length_extension=args.length_extension)

	stuck_callback = (
		(lambda f: (grease_extension(f), drill_extension(f))) if drill_extension and grease_extension
		else drill_extension or grease_extension
	)
	print "[*] Creating fuzzer..."
	fuzzer = fuzzer.Fuzzer(
		args.binary, args.work_dir, afl_count=args.afl_cores, force_interval=args.force_interval,
		create_dictionary=not args.no_dictionary, stuck_callback=stuck_callback, time_limit=args.timeout,
		memory=args.memory, seeds=seeds, timeout=args.run_timeout
	)

	# start it!
	print "[*] Starting fuzzer..."
	fuzzer.start()
## 29.1 fuzzer.start()
	fuzzer/fuzzer.py
	def start(self):
		'''
		start fuzzing
		'''
	 
		# spin up the AFL workers
		self._start_afl()
	 
		# start the callback timer
		self._timer.start() 开启计时器
	 
		self._on = True
### 29.1.1 _start_afl <- start fuzzer.py
	def _start_afl(self):
		'''
		start up a number of AFL instances to begin fuzzing
		'''

		# spin up the master AFL instance
		master = self._start_afl_instance() # the master fuzzer
		self.procs.append(master)

		if self.afl_count > 1:
			driller = self._start_afl_instance()
			self.procs.append(driller)

		# only spins up an AFL instances if afl_count > 1
		for _ in range(2, self.afl_count):
			slave = self._start_afl_instance()
			self.procs.append(slave)
### 29.1.2 _start_afl_instance <- _start_afl fuzzer.py
	def _start_afl_instance(self):
	 
		args = [self.afl_path]
	 
		args += ["-i", self.in_dir]
		args += ["-o", self.out_dir]
		args += ["-m", self.memory]
	 
		if self.qemu:
			args += ["-Q"]
	 
		if self.crash_mode:
			args += ["-C"]
	 
		if self.fuzz_id == 0:
			args += ["-M", "fuzzer-master"]
			outfile = "fuzzer-master.log"
		else:
			args += ["-S", "fuzzer-%d" % self.fuzz_id]
			outfile = "fuzzer-%d.log" % self.fuzz_id
	 
		if self.dictionary is not None:
			args += ["-x", self.dictionary]
	 
		if self.extra_opts is not None:
			args += self.extra_opts
	 
		# auto-calculate timeout based on the number of binaries
		if self.is_multicb:
			args += ["-t", "%d+" % (1000 * len(self.binary_path))]
		elif self.timeout:
			args += ["-t", "%d+" % self.timeout]
	 
		args += ["--"]
		args += self.binary_path if self.is_multicb else [self.binary_path]
	 
		args.extend(self.target_opts)
	 
		l.debug("execing: %s > %s", ' '.join(args), outfile)
	 
		# increment the fuzzer ID
		self.fuzz_id += 1
	 
		outfile = os.path.join(self.job_dir, outfile)
		with open(outfile, "w") as fp:
			return subprocess.Popen(args, stdout=fp, close_fds=True)打开afl输出log到.log文件中
## 29.2 fuzzer/fuzzer.py : _create_dict
	def _create_dict(self, dict_file):
	 
		l.warning("creating a dictionary of string references within binary \"%s\"",
				self.binary_id)
	 
		args = [sys.executable, self.create_dict_path]
		args += self.binary_path if self.is_multicb else [self.binary_path]
	 
		with open(dict_file, "wb") as dfp:
			p = subprocess.Popen(args, stdout=dfp)将create_dic.py标准输出重定向到字典文件中
			retcode = p.wait()
	 
		return retcode == 0 and os.path.getsize(dict_file)
## 29.3 fuzzer/bin/create_dict.py
	def main(argv):
	 
		if len(argv) < 2:
			l.error("incorrect number of arguments passed to create_dict")
			print "usage: %s [binary1] [binary2] [binary3] ... " % sys.argv[0]
			return 1
	 
		for binary in argv[1:]:
			if os.path.isfile(binary):
				create(binary) 创建字典
	 
		return int(strcnt.next() == 0)
	 
	def create(binary):
	 
		b = angr.Project(binary, load_options={'auto_load_libs': False})
		cfg = b.analyses.CFG(resolve_indirect_jumps=True, collect_data_references=True)使用cfg来遍历字符串
	 
		state = b.factory.blank_state()
	 
		string_references = []
		for v in cfg._memory_data.values():
			if v.sort == "string" and v.size > 1:
				st = state.se.eval(state.memory.load(v.address, v.size), cast_to=str)
				string_references.append((v.address, st))
	 
		strings = [] if len(string_references) == 0 else zip(*string_references)[1]
	 
		valid_strings = []
		if len(strings) > 0:
			for s in strings:
				if len(s) <= 128:
					valid_strings.append(s)
				for s_atom in s.split():
					# AFL has a limit of 128 bytes per dictionary entries
					if len(s_atom) <= 128:
						valid_strings.append(s_atom)
	 
		for s in set(valid_strings):
			s_val = hexescape(s)
			print "string_%d=\"%s\"" % (strcnt.next(), s_val)
## 29.4 _timer定时器
	设置定时器，来定时观察afl是否stuck了，若stuck了，就调用driller。
	(1) Fuzzer init
	self._timer = InfiniteTimer(30, self._timer_callback)  
	self._stuck_callback = stuck_callback  
	(2) timer trigger the  _timer_callback function
	self._stuck_callback(self)
	(3) _stuck_callback is assigned by the Fuzzer init function
	
### 29.4.1 Fuzzer类__init__初始化self._timer
	class Fuzzer(object):
	''' Fuzzer object, spins up a fuzzing job on a binary '''
	def __init__(): #function
		if self.force_interval is None:
			l.warning("not forced")
			self._timer = InfiniteTimer(30, self._timer_callback) #liu 设置定时间隔
		else:
			l.warning("forced")
			self._timer = InfiniteTimer(self.force_interval, self._timer_callback)

		self._stuck_callback = stuck_callback #liu 
### 29.4.2 InfiniteTimer类
	class InfiniteTimer():
		"""A Timer class that does not stop, unless you want it to."""

		def __init__(self, seconds, target):
			self._should_continue = False
			self.is_running = False
			self.seconds = seconds
			self.target = target
			self.thread = None
### 29.4.3 Fuzzer::_timer_callback回调函数 fuzzer/fuzzer.py
	def _timer_callback(self):
		if self._stuck_callback is not None:
			# check if afl has pending fav's
			if ('fuzzer-master' in self.stats and 'pending_favs' in self.stats['fuzzer-master'] and \
				int(self.stats['fuzzer-master']['pending_favs']) == 0) or self.force_interval is not None: 强制间隔或者没有pending_favs的时候，调用_stuck_callback回调函数
				self._stuck_callback(self)
#### 29.4.3.1 stats来自afl目录fuzzer_stats
	@property
	def stats(self):

		# collect stats into dictionary
		stats = {}
		if os.path.isdir(self.out_dir):
			for fuzzer_dir in os.listdir(self.out_dir):
				stat_path = os.path.join(self.out_dir, fuzzer_dir, "fuzzer_stats")
				if os.path.isfile(stat_path):
					stats[fuzzer_dir] = {}

					with open(stat_path, "rb") as f:
						stat_blob = f.read()
						stat_lines = stat_blob.split("\n")[:-1]
						for stat in stat_lines:
							key, val = stat.split(":")
							stats[fuzzer_dir][key.strip()] = val.strip()

		return stats
### 29.4.4 _stuck_callback函数<-_timer_callback函数
	初始化Fuzzer对象的时候，传参（shellphuzz文件中）
	stuck_callback = (
			(lambda f: (grease_extension(f), drill_extension(f))) if drill_extension and grease_extension
			else drill_extension or grease_extension
		)
	print "[*] Creating fuzzer..."
		fuzzer = fuzzer.Fuzzer(
			args.binary, args.work_dir, afl_count=args.afl_cores, force_interval=args.force_interval,
			create_dictionary=not args.no_dictionary, stuck_callback=stuck_callback, time_limit=args.timeout,
			memory=args.memory, seeds=seeds, timeout=args.run_timeout
		)
### 29.4.5 drill_extension回调函数<-_stuck_callback
	if args.driller_workers:
		print "[*] Drilling..."
		drill_extension = driller.LocalCallback(num_workers=args.driller_workers, worker_timeout=args.driller_timeout, length_extension=args.length_extension)
### 29.4.6 LocalCallback:: driller_callback <-drill_extension
	在driller/local_callback.py文件中
	class LocalCallback(object):
		def __init__(self, num_workers=1, worker_timeout=10*60, length_extension=None):
			self._already_drilled_inputs = set()

			self._num_workers = num_workers
			self._running_workers = []
			self._worker_timeout = worker_timeout
			self._length_extension = length_extension

	python __call__关键词的使用，对象作为函数进行调用。
	def driller_callback(self, fuzz):
		l.warning("Driller stuck callback triggered!")
		# remove any workers that aren't running
		self._running_workers = [x for x in self._running_workers if x.is_alive()]

		# get the files in queue
		queue = self._queue_files(fuzz)  索引queue目录里面的文件名
		#for i in range(1, fuzz.fuzz_id):
		#	fname = "fuzzer-%d" % i
		#	queue.extend(self.queue_files(fname))

		# start drilling
		not_drilled = set(queue) - self._already_drilled_inputs
		if len(not_drilled) == 0:
			l.warning("no inputs left to drill")

		while len(self._running_workers) < self._num_workers and len(not_drilled) > 0:
			to_drill_path = list(not_drilled)[0]
			not_drilled.remove(to_drill_path)
			self._already_drilled_inputs.add(to_drill_path)

			proc = multiprocessing.Process(target=_run_drill, args=(self, fuzz, to_drill_path),
					kwargs={'length_extension': self._length_extension}) 开启一个新的进程
			proc.start()
			self._running_workers.append(proc)
	__call__ = driller_callback 对象调用函数
#### 29.4.6.1 _queue_files 索引queue目录里面的文件名
	@staticmethod
	def _queue_files(fuzz, fuzzer='fuzzer-master'):
		'''
		retrieve the current queue of inputs from a fuzzer
		:return: a list of strings which represent a fuzzer's queue
		'''

		queue_path = os.path.join(fuzz.out_dir, fuzzer, 'queue')
		queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))
		queue_files = [os.path.join(queue_path, q) for q in queue_files]

	return queue_files
### 29.4.7 _run_drill <- driller_callback
	def _run_drill(drill, fuzz, _path_to_input_to_drill, length_extension=None):
		_binary_path = fuzz.binary_path
		_fuzzer_out_dir = fuzz.out_dir
		_bitmap_path = os.path.join(_fuzzer_out_dir, 'fuzzer-master', "fuzz_bitmap")
		_timeout = drill._worker_timeout
		l.warning("starting drilling of %s, %s", os.path.basename(_binary_path), os.path.basename(_path_to_input_to_drill))
		args = (
			"timeout", "-k", str(_timeout+10), str(_timeout),
			sys.executable, os.path.abspath(__file__),
			_binary_path, _fuzzer_out_dir, _bitmap_path, _path_to_input_to_drill
		)  #liu 就是调用自身python文件
		if length_extension:
			args += ('--length-extension', str(length_extension))

		p = subprocess.Popen(args, stdout=subprocess.PIPE) # liu create a new process
		print p.communicate()
### 29.4.8 driller/local_callback.py __main__
	# this is for running with bash timeout
	if __name__ == "__main__":
		parser = argparse.ArgumentParser(description="Driller local callback")
		parser.add_argument('binary_path')
		parser.add_argument('fuzzer_out_dir')
		parser.add_argument('bitmap_path')
		parser.add_argument('path_to_input_to_drill')
		parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
		args = parser.parse_args()

		logcfg_file = os.path.join(os.getcwd(), '.driller.ini')
		if os.path.isfile(logcfg_file):
			logging.config.fileConfig(logcfg_file)

		binary_path, fuzzer_out_dir, bitmap_path, path_to_input_to_drill = sys.argv[1:5]

		fuzzer_bitmap = open(args.bitmap_path, "r").read()

		# create a folder
		driller_dir = os.path.join(args.fuzzer_out_dir, "driller")
		driller_queue_dir = os.path.join(driller_dir, "queue")
		try: os.mkdir(driller_dir)
		except OSError: pass
		try: os.mkdir(driller_queue_dir)
		except OSError: pass

		l.debug('drilling %s', path_to_input_to_drill)
		# get the input
		inputs_to_drill = [open(args.path_to_input_to_drill, "r").read()]
		if args.length_extension:
			inputs_to_drill.append(inputs_to_drill[0] + '\0' * args.length_extension)

		for input_to_drill in inputs_to_drill:
			d = driller.Driller(args.binary_path, input_to_drill, fuzzer_bitmap) 见28.1
			count = 0
			for new_input in d.drill_generator():# liu real offline symbolic execution
				id_num = len(os.listdir(driller_queue_dir))
				fuzzer_from = args.path_to_input_to_drill.split("sync/")[1].split("/")[0] + args.path_to_input_to_drill.split("id:")[1].split(",")[0]
				filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",from:" + fuzzer_from
				filepath = os.path.join(driller_queue_dir, filepath) 命名规则
				with open(filepath, "wb") as f:
					f.write(new_input[1]) 新发现写到driller/queque的文件中
				count += 1
		l.warning("found %d new inputs", count)
### 29.4.9 drill_generator<- _run_drill
	Driller/driller_main.py
	def drill_generator(self):
		"""
		A generator interface to the actual drilling.
		"""

		# Set up alarm for timeouts.
		if config.DRILL_TIMEOUT is not None:
			signal.alarm(config.DRILL_TIMEOUT)

		for i in self._drill_input(): #liu 见28.3
			yield i
### 29.4.10 _timer.start 开启计时器
	fuzzer/fuzzer.py
	def start(self):
		'''
		start fuzzing
		'''
	 
		# spin up the AFL workers
		self._start_afl()
	 
		# start the callback timer
		self._timer.start() 开启计时器
	 
		self._on = True

	#  http://stackoverflow.com/a/41450617
	class InfiniteTimer():
		"""A Timer class that does not stop, unless you want it to."""

		def __init__(self, seconds, target):
			self._should_continue = False
			self.is_running = False
			self.seconds = seconds
			self.target = target 执行的函数
			# self._timer = InfiniteTimer(30, self._timer_callback)设置定时间隔 见29.4.1
			self.thread = None

		def _handle_target(self):
			self.is_running = True
			self.target()
			self.is_running = False
			self._start_timer() 重新计时

		def _start_timer(self):
			if self._should_continue: # Code could have been running when cancel was called.
				self.thread = threading.Timer(self.seconds, self._handle_target) 定时器
				self.thread.start()

		def start(self):
			if not self._should_continue and not self.is_running:
				self._should_continue = True
				self._start_timer()
			else:
				print "Timer already started or running, please wait if you're restarting."
## 29.5 seeds初始化
### 29.5.1 Fuzzer::__init__
	class Fuzzer(object):
		''' Fuzzer object, spins up a fuzzing job on a binary '''

		def __init__(
			self, binary_path, work_dir, afl_count=1, library_path=None, time_limit=None, memory="8G",
			target_opts=None, extra_opts=None, create_dictionary=False,
			seeds=None, crash_mode=False, never_resume=False, qemu=True, stuck_callback=None,
			force_interval=None, job_dir=None, timeout=None
		):
			'''
			:param binary_path: path to the binary to fuzz. List or tuple for multi-CB.
			:param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
			:param afl_count: number of AFL jobs total to spin up for the binary
			:param library_path: library path to use, if none is specified a default is chosen
			:param timelimit: amount of time to fuzz for, has no effect besides returning True when calling timed_out
			:param seeds: list of inputs to seed fuzzing with
			:param target_opts: extra options to pass to the target
			:param extra_opts: extra options to pass to AFL when starting up
			:param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
			:param never_resume: never resume an old fuzzing run, even if it's possible
			:param qemu: Utilize QEMU for instrumentation of binary.
			:param memory: AFL child process memory limit (default: "8G")
			:param stuck_callback: the callback to call when afl has no pending fav's
			:param job_dir: a job directory to override the work_dir/binary_name path
			:param timeout: timeout for individual runs within AFL
			'''

			self.binary_path	= binary_path
			self.work_dir	   = work_dir
			self.afl_count	  = afl_count
			self.time_limit	 = time_limit
			self.library_path   = library_path
			self.target_opts	= [ ] if target_opts is None else target_opts
			self.crash_mode	 = crash_mode
			self.memory		 = memory
			self.qemu		   = qemu
			self.force_interval = force_interval
			self.timeout		= timeout

			Fuzzer._perform_env_checks()

			if isinstance(binary_path,basestring):
				self.is_multicb = False
				self.binary_id = os.path.basename(binary_path)
			elif isinstance(binary_path,(list,tuple)):
				self.is_multicb = True
				self.binary_id = os.path.basename(binary_path[0])
			else:
				raise ValueError("Was expecting either a string or a list/tuple for binary_path! It's {} instead.".format(type(binary_path)))

			# sanity check crash mode
			if self.crash_mode:
				if seeds is None:
					raise ValueError("Seeds must be specified if using the fuzzer in crash mode")
				l.info("AFL will be started in crash mode")

			self.seeds		  = ["fuzz"] if seeds is None or len(seeds) == 0 else seeds 默认为fuzz字符串

			self.job_dir  = os.path.join(self.work_dir, self.binary_id) if not job_dir else job_dir
			self.in_dir   = os.path.join(self.job_dir, "input")
			self.out_dir  = os.path.join(self.job_dir, "sync")

			# sanity check extra opts
			self.extra_opts = extra_opts
			if self.extra_opts is not None:
				if not isinstance(self.extra_opts, list):
					raise ValueError("extra_opts must be a list of command line arguments")

			# base of the fuzzer package
			self.base = Fuzzer._get_base()

			self.start_time	   = int(time.time())
			# create_dict script
			self.create_dict_path = os.path.join(self.base, "bin", "create_dict.py")
			# afl dictionary
			self.dictionary	   = None
			# processes spun up
			self.procs			= [ ]
			# start the fuzzer ids at 0
			self.fuzz_id		  = 0
			# test if we're resuming an old run
			self.resuming		 = bool(os.listdir(self.out_dir)) if os.path.isdir(self.out_dir) else False
			# has the fuzzer been turned on?
			self._on = False

			if never_resume and self.resuming:
				l.info("could resume, but starting over upon request")
				shutil.rmtree(self.job_dir)
				self.resuming = False

			if self.is_multicb:
				# Where cgc/setup's Dockerfile checks it out
				# NOTE: 'afl/fakeforksrv' serves as 'qemu', as far as AFL is concerned
				#	   Will actually invoke 'fakeforksrv/multicb-qemu'
				#	   This QEMU cannot run standalone (always speaks the forkserver "protocol"),
				#	   but 'fakeforksrv/run_via_fakeforksrv' allows it.
				# XXX: There is no driller/angr support, and probably will never be.
				self.afl_path = shellphish_afl.afl_bin('multi-cgc')
				self.afl_path_var = shellphish_afl.afl_path_var('multi-cgc')
				self.qemu_name = 'TODO'
			else:

				p = angr.Project(binary_path)

				self.os = p.loader.main_object.os

				self.afl_dir		  = shellphish_afl.afl_dir(self.os)

				# the path to AFL capable of calling driller
				self.afl_path		 = shellphish_afl.afl_bin(self.os)

				if self.os == 'cgc':
					self.afl_path_var = shellphish_afl.afl_path_var('cgc')
				else:
					self.afl_path_var = shellphish_afl.afl_path_var(p.arch.qemu_name)
					# set up libraries
					self._export_library_path(p)

				# the name of the qemu port used to run these binaries
				self.qemu_name = p.arch.qemu_name

			self.qemu_dir = self.afl_path_var

			l.debug("self.start_time: %r", self.start_time)
			l.debug("self.afl_path: %s", self.afl_path)
			l.debug("self.afl_path_var: %s", self.afl_path_var)
			l.debug("self.qemu_dir: %s", self.qemu_dir)
			l.debug("self.binary_id: %s", self.binary_id)
			l.debug("self.work_dir: %s", self.work_dir)
			l.debug("self.resuming: %s", self.resuming)

			# if we're resuming an old run set the input_directory to a '-'
			if self.resuming:
				l.info("[%s] resuming old fuzzing run", self.binary_id)
				self.in_dir = "-"

			else:
				# create the work directory and input directory
				try:
					os.makedirs(self.in_dir)
				except OSError:
					l.warning("unable to create in_dir \"%s\"", self.in_dir)

				# populate the input directory
				self._initialize_seeds() #初始化-i input文件夹

			# look for a dictionary
			dictionary_file = os.path.join(self.job_dir, "%s.dict" % self.binary_id)
			if os.path.isfile(dictionary_file):
				self.dictionary = dictionary_file

			# if a dictionary doesn't exist and we aren't resuming a run, create a dict
			elif not self.resuming:
				# call out to another process to create the dictionary so we can
				# limit it's memory
				if create_dictionary:
					if self._create_dict(dictionary_file):
						self.dictionary = dictionary_file
						l.warning("done making dictionary")
					else:
						# no luck creating a dictionary
						l.warning("[%s] unable to create dictionary", self.binary_id)

			if self.force_interval is None:
				l.warning("not forced")
				self._timer = InfiniteTimer(30, self._timer_callback) #liu fuzzer timer
			else:
				l.warning("forced")
				self._timer = InfiniteTimer(self.force_interval, self._timer_callback)

			self._stuck_callback = stuck_callback

			# set environment variable for the AFL_PATH
			os.environ['AFL_PATH'] = self.afl_path_var
### 29.5.2 _initialize_seeds
	def _initialize_seeds(self):
		'''
		populate the input directory with the seeds specified
		'''

		assert len(self.seeds) > 0, "Must specify at least one seed to start fuzzing with"

		l.debug("initializing seeds %r", self.seeds)

		template = os.path.join(self.in_dir, "seed-%d") 文件名称
		for i, seed in enumerate(self.seeds):
			with open(template % i, "wb") as f:
				f.write(seed)
# 30. driller与fuzzer同步的问题
	Fuzzer通过同步机制，来获取driller的成果。
## 30.1 start_listener driller/tasks.py 不是
	def start_listener(fzr):
		'''
		start a listener for driller inputs
		'''

		driller_queue_dir = os.path.join(fzr.out_dir, "driller", "queue")
		channel = "%s-generated" % fzr.binary_id  与产生时一致，见28.3.4

		# find the bin directory listen.py will be installed in
		base = os.path.dirname(__file__)

		while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
			base = os.path.join(base, "..")

		if os.path.abspath(base) == "/":
			raise Exception("could not find driller listener install directory")

		args = [os.path.join(base, "bin", "driller", "listen.py"), driller_queue_dir, channel] 调用脚本
		p = subprocess.Popen(args)

		# add the proc to the fuzzer's list of processes
		fzr.procs.append(p)
## 30.2 listen.py <- start_listener 不是
	''' 
	listen for new inputs produced by driller

	:param queue_dir: directory to places new inputs
	:param channel: redis channel on which the new inputs will be arriving
	'''

	queue_dir = sys.argv[1]
	channel   = sys.argv[2]

	l = logging.getLogger("driller.listen")

	l.debug("subscring to redis channel %s" % channel)
	l.debug("new inputs will be placed into %s" % queue_dir)

	try:
		os.makedirs(queue_dir)
	except OSError:
		l.warning("could not create output directory '%s'" % queue_dir)

	redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) 配置文件driller/driller/config.py
	p = redis_inst.pubsub()

	p.subscribe(channel)

	input_cnt = 0 

	for msg in p.listen():
		if msg['type'] == 'message':
			real_msg = pickle.loads(msg['data'])
			out_filename = "driller-%d-%x-%x" % real_msg['meta']
			out_filename += "_%s" % real_msg['tag'] #与产生时一致，见28.3.4
			l.debug("dumping new input to %s" % out_filename)
			afl_name = "id:%06d,src:%s" % (input_cnt, out_filename)
			out_file = os.path.join(queue_dir, afl_name)

			with open(out_file, 'wb') as ofp:
				ofp.write(real_msg['data'])  #写到driller的queue目录中

			input_cnt += 1
## 30.3 问题是afl的同步
	sync_fuzzers 同步其他fuzzer的queue成果
	#define SYNC_INTERVAL	   5 每隔5次同步
	调用时机，在afl-fuzz.c的main
	while (1) {

	u8 skipped_fuzz;

	cull_queue();

	if (!queue_cur) {

		queue_cycle++;
		current_entry	 = 0;
		cur_skipped_paths = 0;
		queue_cur		 = queue;

		while (seek_to) {
		current_entry++;
		seek_to--;
		queue_cur = queue_cur->next;
		}

		show_stats();

		if (not_on_tty) {
		ACTF("Entering queue cycle %llu.", queue_cycle);
		fflush(stdout);
		}

		/* If we had a full queue cycle with no new finds, try
			recombination strategies next. */

		if (queued_paths == prev_queued) {

		if (use_splicing) cycles_wo_finds++; else use_splicing = 1;

		} else cycles_wo_finds = 0;

		prev_queued = queued_paths;

		if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
		sync_fuzzers(use_argv);

	}

	skipped_fuzz = fuzz_one(use_argv);

	if (!stop_soon && sync_id && !skipped_fuzz) {
		
		if (!(sync_interval_cnt++ % SYNC_INTERVAL)) 每隔一定次数，同步一下，其中就包括driller的
		sync_fuzzers(use_argv);

	}


	/* Grab interesting test cases from other fuzzers. */

	static void sync_fuzzers(char** argv) {

	  DIR* sd;
	  struct dirent* sd_ent;
	  u32 sync_cnt = 0;

	  sd = opendir(sync_dir);打开同步目录sync
	  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

	  stage_max = stage_cur = 0;
	  cur_depth = 0;

	  /* Look at the entries created for every other fuzzer in the sync directory. */

	  while ((sd_ent = readdir(sd))) { 读目录项


		static u8 stage_tmp[128];

		DIR* qd;
		struct dirent* qd_ent;
		u8 *qd_path, *qd_synced_path;
		u32 min_accept = 0, next_min_accept;

		s32 id_fd;

		/* Skip dot files and our own output directory. */

		if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue; 过滤掉自身

		/* Skip anything that doesn't have a queue/ subdirectory. */

		qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name); 获取人家的劳动成果queue路径

		if (!(qd = opendir(qd_path))) {
		  ck_free(qd_path);
		  continue;
		}

		/* Retrieve the ID of the last seen test case. */

		qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name); 该文件记录最后同步过的id

		id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

		if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

		if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
		  lseek(id_fd, 0, SEEK_SET);

		next_min_accept = min_accept;

		/* Show stats */	

		sprintf(stage_tmp, "sync %u", ++sync_cnt);
		stage_name = stage_tmp;
		stage_cur  = 0;
		stage_max  = 0;

		/* For every file queued by this fuzzer, parse ID and see if we have looked at
		   it before; exec a test case if not. */

		while ((qd_ent = readdir(qd))) { 遍历queue中的样本

		  u8* path;
		  s32 fd;
		  struct stat st;

		  if (qd_ent->d_name[0] == '.' ||
			  sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 || 
			  syncing_case < min_accept) continue;  获取没有遍历过的样本

		  /* OK, sounds like a new one. Let's give it a try. */

		  if (syncing_case >= next_min_accept)
			next_min_accept = syncing_case + 1;

		  path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);
	为了证明，在这里打印出来文件名
		  printf("\n%s\n",path); 添加的log，afl-unix里面make编译，下图证明我是对的。
		  


		  /* Allow this to fail in case the other fuzzer is resuming or so... */

		  fd = open(path, O_RDONLY);

		  if (fd < 0) {
			 ck_free(path);
			 continue;
		  }

		  if (fstat(fd, &st)) PFATAL("fstat() failed");

		  /* Ignore zero-sized or oversized files. */

		  if (st.st_size && st.st_size <= MAX_FILE) {

			u8  fault;
			u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

			if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

			/* See what happens. We rely on save_if_interesting() to catch major
			   errors and save the test case. */

			write_to_testcase(mem, st.st_size); 写入输入文件（detect_file_args中赋值为.cur_input）

			fault = run_target(argv, exec_tmout); 执行

			if (stop_soon) return;

			syncing_party = sd_ent->d_name;
			queued_imported += save_if_interesting(argv, mem, st.st_size, fault); 如果好的话，导入到自己的queue
			syncing_party = 0;

			munmap(mem, st.st_size);

			if (!(stage_cur++ % stats_update_freq)) show_stats();

		  }

		  ck_free(path);
		  close(fd);

		}

		ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

		close(id_fd);
		closedir(qd);
		ck_free(qd_path);
		ck_free(qd_synced_path);
		
	  }  

	  closedir(sd);

	}
# 31. step
	发起者
	def _drill_input(self):
		"""
		Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
		state transitions.
		"""

		# initialize the tracer
		r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
		p = angr.Project(self.binary)
		for addr, proc in self._hooks.items():
			p.hook(addr, proc)
			l.debug("Hooking %#x -> %s...", addr, proc.display_name)

		if p.loader.main_object.os == 'cgc':
			p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

			s = p.factory.entry_state(stdin=angr.storage.file.SimFileStream, flag_page=r.magic)
		else:
			s = p.factory.full_init_state(stdin=angr.storage.file.SimFileStream)

		s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)

		simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

		t = angr.exploration_techniques.Tracer(trace=r.trace)
		c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_addr=r.crash_addr)
		self._core = angr.exploration_techniques.DrillerCore(trace=r.trace)

		if r.crash_mode:
			simgr.use_technique(c)
		simgr.use_technique(t)
		simgr.use_technique(angr.exploration_techniques.Oppologist())
		simgr.use_technique(self._core)

		self._set_concretizations(simgr.one_active)

		l.debug("Drilling into %r.", self.input)
		l.debug("Input is %r.", self.input)

		while simgr.active and simgr.one_active.globals['bb_cnt'] < len(r.trace):
			simgr.step() 从这里发起，不断循环

			# Check here to see if a crash has been found.
			if self.redis and self.redis.sismember(self.identifier + '-finished', True):
				return

			if 'diverted' not in simgr.stashes:
				continue

			while simgr.diverted:
				state = simgr.diverted.pop(0)
				l.debug("Found a diverted state, exploring to some extent.")
				w = self._writeout(state.history.bbl_addrs[-1], state)
				if w is not None:
					yield w
				for i in self._symbolic_explorer_stub(state):
					yield i

	Hook层级关系
## 31.1 sim_manager.py step 主要是分类可解不可解
	@ImmutabilityMixin.immutable
	def step(self, n=None, selector_func=None, step_func=None, stash='active', 默认从active的state执行
				successor_func=None, until=None, filter_func=None, **run_args):
		"""
		Step a stash of states forward and categorize the successors appropriately.

		The parameters to this function allow you to control everything about the stepping and
		categorization process.

		:param stash:		   The name of the stash to step (default: 'active')
		:param n:			   (DEPRECATED) The number of times to step (default: 1 if "until" is not provided)
		:param selector_func:   If provided, should be a function that takes a state and returns a
								boolean. If True, the state will be stepped. Otherwise, it will be
								kept as-is.
		:param step_func:	   If provided, should be a function that takes a SimulationManager and
								returns a SimulationManager. Will be called with the SimulationManager
								at every step. Note that this function should not actually perform any
								stepping - it is meant to be a maintenance function called after each step.
		:param successor_func:  If provided, should be a function that takes a state and return its successors.
								Otherwise, project.factory.successors will be used.
		:param until:		   (DEPRECATED) If provided, should be a function that takes a SimulationManager and
								returns True or False. Stepping will terminate when it is True.
		:param filter_func:	 If provided, should be a function that takes a state and return the name
								of the stash, to which the state should be moved.

		Additionally, you can pass in any of the following keyword args for project.factory.sim_run:

		:param jumpkind:		The jumpkind of the previous exit
		:param addr:			An address to execute at instead of the state's ip.
		:param stmt_whitelist:  A list of stmt indexes to which to confine execution.
		:param last_stmt:	   A statement index at which to stop execution.
		:param thumb:		   Whether the block should be lifted in ARM's THUMB mode.
		:param backup_state:	A state to read bytes from instead of using project memory.
		:param opt_level:	   The VEX optimization level to use.
		:param insn_bytes:	  A string of bytes to use for the block instead of the project.
		:param size:			The maximum size of the block, in bytes.
		:param num_inst:		The maximum number of instructions.
		:param traceflags:	  traceflags to be passed to VEX. Default: 0

		:returns:		   The resulting SimulationManager.
		:rtype:			 SimulationManager
		"""
		l.info("Stepping %s of %s", stash, self)
		# 8<----------------- Compatibility layer -----------------
		if n is not None or until is not None:
			if once('simgr_step_n_until'):
				print "\x1b[31;1mDeprecation warning: the use of `n` and `until` arguments is deprecated. " \
						"Consider using simgr.run() with the same arguments if you want to specify " \
						"a number of steps or an additional condition on when to stop the execution.\x1b[0m"
			return self.run(stash, n, until, selector_func=selector_func, step_func=step_func,
							successor_func=successor_func, filter_func=filter_func, **run_args)
		# ------------------ Compatibility layer ---------------->8
		bucket = defaultdict(list)

		for state in self._fetch_states(stash=stash): 获取该stash的状态,每一个状态都要执行

			goto = self.filter(state, filter_func)
			if isinstance(goto, tuple):
				goto, state = goto

			if goto not in (None, stash):
				bucket[goto].append(state)
				continue

			if not self.selector(state, selector_func):
				bucket[stash].append(state)
				continue

			pre_errored = len(self._errored)
			successors = self.step_state(state, successor_func, **run_args) 真正的执行
			if not any(successors.itervalues()) and len(self._errored) == pre_errored:
				bucket['deadended'].append(state)
				continue

			for to_stash, successor_states in successors.iteritems():
				bucket[to_stash or stash].extend(successor_states) 将下一步的状态填入bucket

		self._clear_states(stash=stash)
		for to_stash, states in bucket.iteritems():
			self._store_states(to_stash or stash, states) 将bucket里面的状态转移到stash，见31.2.1

		if step_func is not None:
			return step_func(self)
	return self
### 31.1.1 step_state <- step执行一步
	def step_state(self, state, successor_func=None, **run_args):
		"""
		Don't use this function manually - it is meant to interface with exploration techniques.
		"""
		try:
			successors = self.successors(state, successor_func, **run_args) 关键函数
			stashes = {None: successors.flat_successors,
						'unsat': successors.unsat_successors,
						'unconstrained': successors.unconstrained_successors}

		except (SimUnsatError, claripy.UnsatError) as e:
			if self._hierarchy:
				self._hierarchy.unreachable_state(state)
				self._hierarchy.simplify()
			stashes = {'pruned': [state]}

		except tuple(self._resilience) as e:
			self._errored.append(ErrorRecord(state, e, sys.exc_info()[2]))
			stashes = {}

		return stashes
### 31.1.2 sim_manager.py successors <- step_state
	def successors(self, state, successor_func=None, **run_args):
		"""
		Don't use this function manually - it is meant to interface with exploration techniques.
		"""
		if successor_func is not None:
			return successor_func(state, **run_args)
		return self._project.factory.successors(state, **run_args)
#### 31.1.2.1 factory.py successors <- sim_manager.py successors
	def successors(self, *args, **kwargs):
		"""
		Perform execution using any applicable engine. Enumerate the current engines and use the
		first one that works. Return a SimSuccessors object classifying the results of the run.

		:param state:		   The state to analyze
		:param addr:			optional, an address to execute at instead of the state's ip
		:param jumpkind:		optional, the jumpkind of the previous exit
		:param inline:		  This is an inline execution. Do not bother copying the state.

		Additional keyword arguments will be passed directly into each engine's process method.
		"""

		return self.project.engines.successors(*args, **kwargs) 不同的符号执行引擎，最终使用的是angr/engines/vex/engine.py
#### 31.1.2.2 hub.py successors <- factory.py successors
	def successors(self, state, addr=None, jumpkind=None, default_engine=False, procedure_engine=False,
					engines=None, **kwargs):
		"""
		Perform execution using any applicable engine. Enumerate the current engines and use the
		first one that works. Engines are enumerated in order, specified by the ``order`` attribute.

		:param state:			   The state to analyze
		:param addr:				optional, an address to execute at instead of the state's ip
		:param jumpkind:			optional, the jumpkind of the previous exit
		:param default_engine:	  Whether we should only attempt to use the default engine (usually VEX)
		:param procedure_engine:	Whether we should only attempt to use the procedure engine
		:param engines:			 A list of engines to try to use, instead of the default.
									This list is expected to contain engine names or engine instances.

		Additional keyword arguments will be passed directly into each engine's process method.

		:return SimSuccessors:	  A SimSuccessors object classifying the results of the run.
		"""
		if addr is not None or jumpkind is not None:
			state = state.copy()
			if addr is not None:
				state.ip = addr
			if jumpkind is not None:
				state.history.jumpkind = jumpkind

		if default_engine and self.has_default_engine():
			engines = [self.default_engine]
		elif procedure_engine and self.has_procedure_engine():
			engines = [self.procedure_engine]
		elif engines is None:
			engines = (self.get_plugin(name) for name in self.order)
		else:
			engines = (self.get_plugin(e) if isinstance(e, str) else e for e in engines)

		for engine in engines:
			if engine.check(state, **kwargs):
				r = engine.process(state, **kwargs) 选择engine执行
				if r.processed:
					return r

		raise AngrExitError("All engines failed to execute!")
#### 31.1.2.3 vex/engine.py process
	def process(self, state,
			irsb=None,
			skip_stmts=0,
			last_stmt=99999999,
			whitelist=None,
			inline=False,
			force_addr=None,
			insn_bytes=None,
			size=None,
			num_inst=None,
			traceflags=0,
			thumb=False,
			opt_level=None,
			**kwargs):
		"""
		:param state:	   The state with which to execute
		:param irsb:		The PyVEX IRSB object to use for execution. If not provided one will be lifted.
		:param skip_stmts:  The number of statements to skip in processing
		:param last_stmt:   Do not execute any statements after this statement
		:param whitelist:   Only execute statements in this set
		:param inline:	  This is an inline execution. Do not bother copying the state.
		:param force_addr:  Force execution to pretend that we're working at this concrete address

		:param thumb:		   Whether the block should be lifted in ARM's THUMB mode.
		:param opt_level:	   The VEX optimization level to use.
		:param insn_bytes:	  A string of bytes to use for the block instead of the project.
		:param size:			The maximum size of the block, in bytes.
		:param num_inst:		The maximum number of instructions.
		:param traceflags:	  traceflags to be passed to VEX. (default: 0)
		:returns:		   A SimSuccessors object categorizing the block's successors
		"""
		if 'insn_text' in kwargs:

			if insn_bytes is not None:
				raise SimEngineError("You cannot provide both 'insn_bytes' and 'insn_text'!")

			insn_bytes = \
				self.project.arch.asm(kwargs['insn_text'], addr=kwargs.get('addr', 0),
										thumb=kwargs.get('thumb', False), as_bytes=True)

			if insn_bytes is None:
				raise AngrAssemblyError("Assembling failed. Please make sure keystone is installed, and the assembly"
										" string is correct.")

		return super(SimEngineVEX, self).process(state, irsb,
				skip_stmts=skip_stmts,
				last_stmt=last_stmt,
				whitelist=whitelist,
				inline=inline,
				force_addr=force_addr,
				insn_bytes=insn_bytes,
				size=size,
				num_inst=num_inst,
				traceflags=traceflags,
				thumb=thumb,
				opt_level=opt_level)
#### 31.1.2.4 engine/engine.py process
	def process(self, state, *args, **kwargs):
		"""
		Perform execution with a state.

		You should only override this method in a subclass in order to provide the correct method signature and
		docstring. You should override the ``_process`` method to do your actual execution.

		:param state:	   The state with which to execute. This state will be copied before
							modification.
		:param inline:	  This is an inline execution. Do not bother copying the state.
		:param force_addr:  Force execution to pretend that we're working at this concrete address
		:returns:		   A SimSuccessors object categorizing the execution's successor states
		"""
		inline = kwargs.pop('inline', False)
		force_addr = kwargs.pop('force_addr', None)
		addr = state.se.eval(state._ip) if force_addr is None else force_addr

		# make a copy of the initial state for actual processing, if needed
		if not inline and o.COW_STATES in state.options:
			new_state = state.copy()
		else:
			new_state = state
		# enforce this distinction
		old_state = state
		del state

		# we have now officially begun the stepping process! now is where we "cycle" a state's
		# data - move the "present" into the "past" by pushing an entry on the history stack.
		# nuance: make sure to copy from the PREVIOUS state to the CURRENT one
		# to avoid creating a dead link in the history, messing up the statehierarchy
		new_state.register_plugin('history', old_state.history.make_child())
		new_state.history.recent_bbl_addrs.append(addr)
		new_state.scratch.executed_pages_set = {addr & ~0xFFF}

		successors = SimSuccessors(addr, old_state) 类构造

		new_state._inspect('engine_process', when=BP_BEFORE, sim_engine=self, sim_successors=successors, address=addr)
		successors = new_state._inspect_getattr('sim_successors', successors)
		try:
			self._process(new_state, successors, *args, **kwargs) 执行
		except SimException:
			if o.EXCEPTION_HANDLING not in old_state.options:
				raise
			old_state.project.simos.handle_exception(successors, self, *sys.exc_info())

		new_state._inspect('engine_process', when=BP_AFTER, sim_successors=successors, address=addr)
		successors = new_state._inspect_getattr('sim_successors', successors)

		# downsizing
		new_state.inspect.downsize()
		# if not TRACK, clear actions on OLD state
		#if o.TRACK_ACTION_HISTORY not in old_state.options:
		#	old_state.history.recent_events = []

		# fix up the descriptions...
		description = str(successors)
		l.info("Ticked state: %s", description)
		for succ in successors.all_successors:
			succ.history.recent_description = description
		for succ in successors.flat_successors:
			succ.history.recent_description = description

		return successors
#### 31.1.2.5 vex/engine.py _process
	def _process(self, state, successors, irsb=None, skip_stmts=0, last_stmt=99999999, whitelist=None, insn_bytes=None, size=None, num_inst=None, traceflags=0, thumb=False, opt_level=None):
		successors.sort = 'IRSB'
		successors.description = 'IRSB'
		state.history.recent_block_count = 1
		state.scratch.guard = claripy.true  每个bbl初始化为真
		state.scratch.sim_procedure = None
		addr = successors.addr

		state._inspect('irsb', BP_BEFORE, address=addr)
		while True:
			if irsb is None:
				irsb = self.lift(
					addr=addr,
					state=state,
					insn_bytes=insn_bytes,
					size=size,
					num_inst=num_inst,
					traceflags=traceflags,
					thumb=thumb,
					opt_level=opt_level) 提取中间语言

			if irsb.size == 0:
				if irsb.jumpkind == 'Ijk_NoDecode' and not state.project.is_hooked(irsb.addr):
					raise SimIRSBNoDecodeError("IR decoding error at %#x. You can hook this instruction with "
												"a python replacement using project.hook"
												"(%#x, your_function, length=length_of_instruction)." % (addr, addr))

				raise SimIRSBError("Empty IRSB passed to SimIRSB.")

			# check permissions, are we allowed to execute here? Do we care?
			if o.STRICT_PAGE_ACCESS in state.options:
				try:
					perms = state.memory.permissions(addr)
				except SimMemoryError:
					raise SimSegfaultError(addr, 'exec-miss')
				else:
					if not perms.symbolic:
						perms = state.se.eval(perms)
						if not perms & 4 and o.ENABLE_NX in state.options:
							raise SimSegfaultError(addr, 'non-executable')

			state.scratch.tyenv = irsb.tyenv
			state.scratch.irsb = irsb

			try:
				self._handle_irsb(state, successors, irsb, skip_stmts, last_stmt, whitelist) 符号执行中间语言
			except SimReliftException as e:
				state = e.state
				if insn_bytes is not None:
					raise SimEngineError("You cannot pass self-modifying code as insn_bytes!!!")
				new_ip = state.scratch.ins_addr
				if size is not None:
					size -= new_ip - addr
				if num_inst is not None:
					num_inst -= state.scratch.num_insns
				addr = new_ip

				# clear the stage before creating the new IRSB
				state.scratch.dirty_addrs.clear()
				irsb = None

			except SimError as ex:
				ex.record_state(state)
				raise
			else:
				break
		state._inspect('irsb', BP_AFTER, address=addr)

		successors.processed = True
#### 31.1.2.6 _handle_irsb angr/engines/vex/engine.py 
	def _handle_irsb(self, state, successors, irsb, skip_stmts, last_stmt, whitelist):
		# shortcut. we'll be typing this a lot
		ss = irsb.statements
		num_stmts = len(ss)

		# fill in artifacts
		successors.artifacts['irsb'] = irsb
		successors.artifacts['irsb_size'] = irsb.size
		successors.artifacts['irsb_direct_next'] = irsb.direct_next
		successors.artifacts['irsb_default_jumpkind'] = irsb.jumpkind

		insn_addrs = [ ]

		# if we've told the block to truncate before it ends, it will definitely have a default
		# exit barring errors
		has_default_exit = num_stmts <= last_stmt

		# This option makes us only execute the last four instructions
		if o.SUPER_FASTPATH in state.options:
			imark_counter = 0
			for i in xrange(len(ss) - 1, -1, -1):
				if type(ss[i]) is pyvex.IRStmt.IMark:
					imark_counter += 1
				if imark_counter >= 4:
					skip_stmts = max(skip_stmts, i)
					break

		# set the current basic block address that's being processed
		state.scratch.bbl_addr = irsb.addr

		for stmt_idx, stmt in enumerate(ss): 每一条语句遍历
			if isinstance(stmt, pyvex.IRStmt.IMark):
				insn_addrs.append(stmt.addr + stmt.delta)

			if stmt_idx < skip_stmts:
				l.debug("Skipping statement %d", stmt_idx)
				continue
			if last_stmt is not None and stmt_idx > last_stmt:
				l.debug("Truncating statement %d", stmt_idx)
				continue
			if whitelist is not None and stmt_idx not in whitelist:
				l.debug("Blacklisting statement %d", stmt_idx)
				continue

			try:
				state.scratch.stmt_idx = stmt_idx
				state._inspect('statement', BP_BEFORE, statement=stmt_idx)
				self._handle_statement(state, successors, stmt) 执行这条语句
				state._inspect('statement', BP_AFTER)
			except UnsupportedDirtyError:
				if o.BYPASS_UNSUPPORTED_IRDIRTY not in state.options:
					raise
				if stmt.tmp not in (0xffffffff, -1):
					retval_size = state.scratch.tyenv.sizeof(stmt.tmp)
					retval = state.se.Unconstrained("unsupported_dirty_%s" % stmt.cee.name, retval_size, key=('dirty', stmt.cee.name))
					state.scratch.store_tmp(stmt.tmp, retval, None, None)
				state.history.add_event('resilience', resilience_type='dirty', dirty=stmt.cee.name,
									message='unsupported Dirty call')
			except (SimSolverError, SimMemoryAddressError):
				l.warning("%#x hit an error while analyzing statement %d", successors.addr, stmt_idx, exc_info=True)
				has_default_exit = False
				break

		state.scratch.stmt_idx = num_stmts

		successors.artifacts['insn_addrs'] = insn_addrs

		# If there was an error, and not all the statements were processed,
		# then this block does not have a default exit. This can happen if
		# the block has an unavoidable "conditional" exit or if there's a legitimate
		# error in the simulation
		if has_default_exit: 执行结束
			l.debug("%s adding default exit.", self)

			try:
				next_expr = translate_expr(irsb.next, state) 下一个bbl地址
				state.history.extend_actions(next_expr.actions)

				if o.TRACK_JMP_ACTIONS in state.options:
					target_ao = SimActionObject(
						next_expr.expr,
						reg_deps=next_expr.reg_deps(), tmp_deps=next_expr.tmp_deps()
					)
					state.history.add_action(SimActionExit(state, target_ao, exit_type=SimActionExit.DEFAULT))
				successors.add_successor(state, next_expr.expr, state.scratch.guard, irsb.jumpkind,
											exit_stmt_idx='default', exit_ins_addr=state.scratch.ins_addr) 将下一个跳转地址添加到successor中

			except KeyError:
				# For some reason, the temporary variable that the successor relies on does not exist.
				# It can be intentional (e.g. when executing a program slice)
				# We save the current state anyways
				successors.unsat_successors.append(state)
				l.debug("The temporary variable for default exit of %s is missing.", self)
		else:
			l.debug("%s has no default exit", self)

		# do return emulation and calless stuff
		for exit_state in list(successors.all_successors):
			exit_jumpkind = exit_state.history.jumpkind
			if exit_jumpkind is None: exit_jumpkind = ""

			if o.CALLLESS in state.options and exit_jumpkind == "Ijk_Call":
				exit_state.registers.store(
					exit_state.arch.ret_offset,
					exit_state.se.Unconstrained('fake_ret_value', exit_state.arch.bits)
				)
				exit_state.scratch.target = exit_state.se.BVV(
					successors.addr + irsb.size, exit_state.arch.bits
				)
				exit_state.history.jumpkind = "Ijk_Ret"
				exit_state.regs.ip = exit_state.scratch.target

			elif o.DO_RET_EMULATION in exit_state.options and \
				(exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith('Ijk_Sys')):
				l.debug("%s adding postcall exit.", self)

				ret_state = exit_state.copy()
				guard = ret_state.se.true if o.TRUE_RET_EMULATION_GUARD in state.options else ret_state.se.false
				target = ret_state.se.BVV(successors.addr + irsb.size, ret_state.arch.bits)
				if ret_state.arch.call_pushes_ret and not exit_jumpkind.startswith('Ijk_Sys'):
					ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
				successors.add_successor(
					ret_state, target, guard, 'Ijk_FakeRet', exit_stmt_idx='default',
					exit_ins_addr=state.scratch.ins_addr
				)

		if whitelist and successors.is_empty:
			# If statements of this block are white-listed and none of the exit statement (not even the default exit) is
			# in the white-list, successors will be empty, and there is no way for us to get the final state.
			# To this end, a final state is manually created
			l.debug('Add an incomplete successor state as the result of an incomplete execution due to the white-list.')
			successors.flat_successors.append(state)
##### 31.1.2.6.1 _handle_statement SimIRStmt_Exit例子
	def _handle_statement(self, state, successors, stmt):
		"""
		This function receives an initial state and imark and processes a list of pyvex.IRStmts
		It annotates the request with a final state, last imark, and a list of SimIRStmts
		"""
		if type(stmt) == pyvex.IRStmt.IMark:
			ins_addr = stmt.addr + stmt.delta
			state.scratch.ins_addr = ins_addr

			# Raise an exception if we're suddenly in self-modifying code
			for subaddr in xrange(stmt.len):
				if subaddr + stmt.addr in state.scratch.dirty_addrs:
					raise SimReliftException(state)
			state._inspect('instruction', BP_AFTER)

			l.debug("IMark: %#x", stmt.addr)
			state.scratch.num_insns += 1
			state._inspect('instruction', BP_BEFORE, instruction=ins_addr)

		# process it!
		s_stmt = translate_stmt(stmt, state) #解析每条语句
		if s_stmt is not None:
			state.history.extend_actions(s_stmt.actions)

		# for the exits, put *not* taking the exit on the list of constraints so
		# that we can continue on. Otherwise, add the constraints
		if type(stmt) == pyvex.IRStmt.Exit: 对于结束的语句，比如jz
			l.debug("%s adding conditional exit", self)

			# Produce our successor state!
			# Let SimSuccessors.add_successor handle the nitty gritty details
			exit_state = state.copy()
			successors.add_successor(exit_state, s_stmt.target, s_stmt.guard, s_stmt.jumpkind,
										exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr) 添加后继，像jz这样的，有一个满足，一个不满足，或者两个都可满足。返回到has_default_exit正好相反。

			# Do our bookkeeping on the continuing state
			cont_condition = claripy.Not(s_stmt.guard) #约束取反
			state.add_constraints(cont_condition)
			state.scratch.guard = claripy.And(state.scratch.guard, cont_condition)

	Engines/vex/statements/exit.py
	class SimIRStmt_Exit(SimIRStmt):
		def __init__(self, stmt, state):
			SimIRStmt.__init__(self, stmt, state)

			self.guard = None
			self.target = None
			self.jumpkind = None

		def _execute(self):
			guard_irexpr = self._translate_expr(self.stmt.guard)
			self.guard = guard_irexpr.expr != 0

			# get the destination
			self.target = translate_irconst(self.state, self.stmt.dst)
			self.jumpkind = self.stmt.jumpkind

			if o.TRACK_JMP_ACTIONS in self.state.options:
				guard_ao = SimActionObject(self.guard, reg_deps=guard_irexpr.reg_deps(), tmp_deps=guard_irexpr.tmp_deps())
				self.actions.append(SimActionExit(self.state, target=self.target, condition=guard_ao, exit_type=SimActionExit.CONDITIONAL))
#### 31.1.2.7 add_successor engines/successors.py 添加后继
	def add_successor(self, state, target, guard, jumpkind, add_guard=True, exit_stmt_idx=None, exit_ins_addr=None,
						source=None):
		"""
		Add a successor state of the SimRun.
		This procedure stores method parameters into state.scratch, does some housekeeping,
		and calls out to helper functions to prepare the state and categorize it into the appropriate
		successor lists.

		:param SimState state:	The successor state.
		:param target:			The target (of the jump/call/ret).
		:param guard:			 The guard expression.
		:param str jumpkind:	  The jumpkind (call, ret, jump, or whatnot).
		:param bool add_guard:	Whether to add the guard constraint (default: True).
		:param int exit_stmt_idx: The ID of the exit statement, an integer by default. 'default'
									stands for the default exit, and None means it's not from a
									statement (for example, from a SimProcedure).
		:param int exit_ins_addr: The instruction pointer of this exit, which is an integer by default.
		:param int source:		The source of the jump (i.e., the address of the basic block).
		"""

		# First, trigger the SimInspect breakpoint
		state._inspect('exit', BP_BEFORE, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
		state.scratch.target = state._inspect_getattr("exit_target", target) 添加到scratch中
		state.scratch.guard = state._inspect_getattr("exit_guard", guard)
		state.history.jumpkind = state._inspect_getattr("exit_jumpkind", jumpkind)
		state.history.jump_target = state.scratch.target
		state.history.jump_guard = state.scratch.guard

		# track some vex-specific stuff here for now
		state.scratch.source = source if source is not None else self.addr
		state.scratch.exit_stmt_idx = exit_stmt_idx
		state.scratch.exit_ins_addr = exit_ins_addr

		self._preprocess_successor(state, add_guard=add_guard)

		if state.history.jumpkind == 'Ijk_SigFPE_IntDiv' and o.PRODUCE_ZERODIV_SUCCESSORS not in state.options:
			return

		self._categorize_successor(state) 分类添加到successor lists
		state._inspect('exit', BP_AFTER, exit_target=target, exit_guard=guard, exit_jumpkind=jumpkind)
		state.inspect.downsize()
#### 31.1.2.8 SimSuccessors :: _categorize_successor <- add_successor engines/successors.py分类
	class SimSuccessors(object):
		"""
		This class serves as a categorization of all the kinds of result states that can come from a
		SimEngine run.

		:ivar int addr:		 The address at which execution is taking place, as a python int
		:ivar initial_state:	The initial state for which execution produced these successors
		:ivar engine:		   The engine that produced these successors
		:ivar sort:			 A string identifying the type of engine that produced these successors
		:ivar bool processed:   Whether or not the processing succeeded
		:ivar str description:  A textual description of the execution step

		The successor states produced by this run are categorized into several lists:

		:ivar dict artifacts:   Any analysis byproducts (for example, an IRSB) that were produced during execution
		:ivar successors:	   The "normal" successors. IP may be symbolic, but must have reasonable number of solutions
		:ivar unsat_successors: Any successor which is unsatisfiable after its guard condition is added.
		:ivar all_successors:   successors + unsat_successors
		:ivar flat_successors:  The normal successors, but any symbolic IPs have been concretized. There is one state in
								this list for each possible value an IP may be concretized to for each successor state.
		:ivar unconstrained_successors:
								Any state for which during the flattening process we find too many solutions.

		A more detailed description of the successor lists may be found here: https://docs.angr.io/docs/simuvex.html
		"""

		def __init__(self, addr, initial_state):
			self.addr = addr
			self.initial_state = initial_state

			self.successors = [ ]
			self.all_successors = [ ]
			self.flat_successors = [ ]
			self.unsat_successors = [ ]
			self.unconstrained_successors = [ ]

			# the engine that should process or did process this request
			self.engine = None
			self.processed = False
			self.description = 'SimSuccessors'
			self.sort = None
			self.artifacts = {}

	def _categorize_successor(self, state):
		"""
		Append state into successor lists.

		:param state: a SimState instance
		:param target: The target (of the jump/call/ret)
		:return: The state
		"""

		self.all_successors.append(state)
		target = state.scratch.target

		# categorize the state
		if o.APPROXIMATE_GUARDS in state.options and state.se.is_false(state.scratch.guard, exact=False):
			if o.VALIDATE_APPROXIMATIONS in state.options:
				if state.satisfiable():
					raise Exception('WTF')
			self.unsat_successors.append(state)
		elif o.APPROXIMATE_SATISFIABILITY in state.options and not state.se.satisfiable(exact=False):
			if o.VALIDATE_APPROXIMATIONS in state.options:
				if state.se.satisfiable():
					raise Exception('WTF')
			self.unsat_successors.append(state)
		elif not state.scratch.guard.symbolic and state.se.is_false(state.scratch.guard): 评判标准guard是否满足，guard为常数，且为恒假，state.scratch.guard是不断累积的，见31.1.2.6.1 _handle_statement最后state.scratch.guard = claripy.And(state.scratch.guard, cont_condition)，在改bbl process前设置为true，见engines/vex/engine.py _process函数，即31.1.2.5，state.scratch.guard = claripy.true
			self.unsat_successors.append(state) 
		elif o.LAZY_SOLVES not in state.options and not state.satisfiable():
			self.unsat_successors.append(state)
		elif o.NO_SYMBOLIC_JUMP_RESOLUTION in state.options and state.se.symbolic(target): 分类依据target
			self.unconstrained_successors.append(state)
		elif not state.se.symbolic(target) and not state.history.jumpkind.startswith("Ijk_Sys"):
			# a successor with a concrete IP, and it's not a syscall
			self.successors.append(state)
			self.flat_successors.append(state)
		elif state.history.jumpkind.startswith("Ijk_Sys"):
			# syscall
			self.successors.append(state)

			# Misuse the ip_at_syscall register to save the return address for this syscall
			# state.ip *might be* changed to be the real address of syscall SimProcedures by syscall handling code in
			# angr
			state.regs.ip_at_syscall = state.ip

			try:
				symbolic_syscall_num, concrete_syscall_nums = self._resolve_syscall(state)
				if concrete_syscall_nums is not None:
					for n in concrete_syscall_nums:
						split_state = state.copy()
						split_state.add_constraints(symbolic_syscall_num == n)
						split_state.inspect.downsize()
						self._fix_syscall_ip(split_state)

						self.flat_successors.append(split_state)
				else:
					# We cannot resolve the syscall number
					# However, we still put it to the flat_successors list, and angr.SimOS.handle_syscall will pick it
					# up, and create a "unknown syscall" stub for it.
					self._fix_syscall_ip(state)
					self.flat_successors.append(state)
			except AngrUnsupportedSyscallError:
				self.unsat_successors.append(state)

		else:
			# a successor with a symbolic IP
			_max_targets = state.options.symbolic_ip_max_targets
			_max_jumptable_targets = state.options.jumptable_symbolic_ip_max_targets
			try:
				if o.KEEP_IP_SYMBOLIC in state.options:
					s = claripy.Solver()
					addrs = s.eval(target, _max_targets + 1, extra_constraints=tuple(state.ip_constraints))
					if len(addrs) > _max_targets:
						# It is not a library
						l.debug("It is not a Library")
						addrs = state.se.eval_upto(target, _max_targets + 1)
						l.debug("addrs :%s", addrs)
					cond_and_targets = [ (target == addr, addr) for addr in addrs ]
					max_targets = _max_targets
				else:
					cond_and_targets = self._eval_target_jumptable(state, target, _max_jumptable_targets + 1)
					if cond_and_targets is None:
						# Fallback to the traditional and slow method
						cond_and_targets = self._eval_target_brutal(state, target, _max_targets + 1)
						max_targets = _max_targets
					else:
						max_targets = _max_jumptable_targets

				if len(cond_and_targets) > max_targets:
					l.warning(
						"Exit state has over %d possible solutions. Likely unconstrained; skipping. %s",
						max_targets,
						target.shallow_repr()
					)
					self.unconstrained_successors.append(state)
				else:
					for cond, a in cond_and_targets:
						split_state = state.copy()
						if o.KEEP_IP_SYMBOLIC in split_state.options:
							split_state.regs.ip = target
						else:
							split_state.add_constraints(cond, action=True)
							split_state.regs.ip = a
						split_state.inspect.downsize()
						self.flat_successors.append(split_state)
					self.successors.append(state)
			except SimSolverModeError:
				self.unsat_successors.append(state)

		return state
## 31.2 stashes操作
### 31.2.1 _store_states 保存状态到stash
	def _store_states(self, stash, states):
		if stash not in self._auto_drop:
			if stash not in self._stashes:
				self._stashes[stash] = list()
			self._stashes[stash].extend(states)
### 31.2.2 stash函数将active保存到stashed
	@ImmutabilityMixin.immutable
	def stash(self, filter_func=None, from_stash='active', to_stash='stashed'):
		"""
		Stash some states. This is an alias for move(), with defaults for the stashes.

		:param filter_func: Stash states that match this filter. Should be a function that
							takes a state and returns True or False. (default: stash all states)
		:param from_stash:  Take matching states from this stash. (default: 'active')
		:param to_stash:	Put matching states into this stash. (default: 'stashed')

		:returns:		   The resulting SimulationManager
		:rtype:			 SimulationManager
		"""
		return self.move(from_stash, to_stash, filter_func=filter_func)
### 31.2.3 unstash 函数
	def unstash(self, filter_func=None, to_stash='active', from_stash='stashed'):
		"""
		Unstash some states. This is an alias for move(), with defaults for the stashes.

		:param filter_func: Unstash states that match this filter. Should be a function that
							takes a state and returns True or False. (default: unstash all states)
		:param from_stash:  take matching states from this stash. (default: 'stashed')
		:param to_stash:	put matching states into this stash. (default: 'active')

		:returns:			The resulting SimulationManager.
		:rtype:			 SimulationManager
		"""
		return self.move(from_stash, to_stash, filter_func=filter_func)
### 31.2.4 drop函数
	def drop(self, filter_func=None, stash='active'):
		"""
		Drops states from a stash. This is an alias for move(), with defaults for the stashes.

		:param filter_func: Drop states that match this filter. Should be a function that takes
							a state and returns True or False. (default: drop all states)
		:param stash:	   Drop matching states from this stash. (default: 'active')

		:returns:		   The resulting SimulationManager
		:rtype:			 SimulationManager
		"""
		return self.move(stash, self.DROP, filter_func=filter_func)
## 31.3 tracer.py step -> sim_manager.py step
	def step(self, simgr, stash='active', **kwargs):
		if stash != 'active':
			raise Exception("TODO: tracer doesn't work with stashes other than active")

		if len(simgr.active) == 1:
			current = simgr.active[0]

			if current.history.recent_block_count > 1:
				# executed unicorn fix bb_cnt
				current.globals['bb_cnt'] += current.history.recent_block_count - 1 - current.history.recent_syscall_count

			if not self._no_follow:
				# termination condition: we exhausted the dynamic trace log
				if current.globals['bb_cnt'] >= len(self._trace):
					return simgr
	# now, we switch through several ways that the dynamic and symbolic traces can interact

				# basic, convenient case: the two traces match
				if current.addr == self._trace[current.globals['bb_cnt']]:
					current.globals['bb_cnt'] += 1

				# angr will count a syscall as a step, qemu will not. they will sync next step.
				elif current.history.jumpkind.startswith("Ijk_Sys"):
					pass

				# handle library calls and simprocedures
				elif self.project.is_hooked(current.addr)			  \
					or self.project.simos.is_syscall_addr(current.addr) \
					or not self._address_in_binary(current.addr):
					# If dynamic trace is in the PLT stub, update bb_cnt until it's out
					while current.globals['bb_cnt'] < len(self._trace) and self._addr_in_plt(self._trace[current.globals['bb_cnt']]):
						current.globals['bb_cnt'] += 1

				# handle hooked functions
				# TODO: this branch is totally missed by the test cases
				elif self.project.is_hooked(current.history.addr) \
					and current.history.addr in self.project._sim_procedures:
					l.debug("ending hook for %s", self.project.hooked_by(current.history.addr))
					l.debug("previous addr %#x", current.history.addr)
					l.debug("bb_cnt %d", current.globals['bb_cnt'])
					# we need step to the return
					current_addr = current.addr
					while current.globals['bb_cnt'] < len(self._trace) and current_addr != self._trace[current.globals['bb_cnt']]:
						current.globals['bb_cnt'] += 1
					# step 1 more for the normal step that would happen
					current.globals['bb_cnt'] += 1
					l.debug("bb_cnt after the correction %d", current.globals['bb_cnt'])
					if current.globals['bb_cnt'] >= len(self._trace):
						return simgr

				else:
					l.error( "the dynamic trace and the symbolic trace disagreed")

					l.error("[%s] dynamic [0x%x], symbolic [0x%x]",
							self.project.filename,
							self._trace[current.globals['bb_cnt']],
							current.addr)

					if self._resiliency:
						l.error("TracerMisfollowError encountered")
						l.warning("entering no follow mode")
						self._no_follow = True
					else:
						raise AngrTracerError("misfollow")

			# maintain the predecessors list
			self.predecessors.append(current)
			self.predecessors.pop(0)

			# Basic block's max size in angr is greater than the one in Qemu
			# We follow the one in Qemu
			if current.globals['bb_cnt'] >= len(self._trace):
				bbl_max_bytes = 800
			else:
				y2 = self._trace[current.globals['bb_cnt']]
				y1 = self._trace[current.globals['bb_cnt'] - 1]
				bbl_max_bytes = y2 - y1
				if bbl_max_bytes <= 0:
					bbl_max_bytes = 800

			# detect back loops (a block jumps back to the middle of itself) that have to be differentiated from the
			# case where max block sizes doesn't match.

			# this might still break for huge basic blocks with back loops, but it seems unlikely.
			try:
				bl = self.project.factory.block(self._trace[current.globals['bb_cnt']-1],
						backup_state=current)
				back_targets = set(bl.vex.constant_jump_targets) & set(bl.instruction_addrs)
				if current.globals['bb_cnt'] < len(self._trace) and self._trace[current.globals['bb_cnt']] in back_targets:
					target_to_jumpkind = bl.vex.constant_jump_targets_and_jumpkinds
					if target_to_jumpkind[self._trace[current.globals['bb_cnt']]] == "Ijk_Boring":
						bbl_max_bytes = 800
			except (SimMemoryError, SimEngineError):
				bbl_max_bytes = 800

			# drop the missed stash before stepping, since driller needs missed paths later.
			simgr.drop(stash='missed')

			simgr.step(stash=stash, size=bbl_max_bytes) 调用sim_manager.py step

			# if our input was preconstrained we have to keep on the lookout for unsat paths.
			simgr.stash(from_stash='unsat', to_stash='active') 会将不满足的，也添加进去，因为preconstrain的问题

			simgr.drop(stash='unsat')

		# if we stepped to a point where there are no active paths, return the simgr.
		if len(simgr.active) == 0:
			# possibly we want to have different behaviour if we're in crash mode.
			return simgr

		if len(simgr.active) > 1:
			# if we get to this point there's more than one active path
			# if we have to ditch the trace we use satisfiability
			# or if a split occurs in a library routine
			a_paths = simgr.active

			if self._no_follow or all(map( lambda p: not self._address_in_binary(p.addr), a_paths)):
				simgr.prune(to_stash='missed')
			else:
				l.debug("bb %d / %d", current.globals['bb_cnt'], len(self._trace))
				if current.globals['bb_cnt'] < len(self._trace):
					simgr.stash(lambda s: s.addr != self._trace[current.globals['bb_cnt']], to_stash='missed') 将新的后继不在trace中的，加入missed stash


			if len(simgr.active) > 1: # rarely we get two active paths
				simgr.prune(to_stash='missed')

			if len(simgr.active) > 1: # might still be two active
				simgr.stash(to_stash='missed', filter_func=lambda x: x.jumpkind == "Ijk_EmWarn")

			# make sure we only have one or zero active paths at this point
			assert len(simgr.active) < 2

			# something weird... maybe we hit a rep instruction?
			# qemu and vex have slightly different behaviors...
			if not simgr.active[0].se.satisfiable():
				l.info("detected small discrepancy between qemu and angr, "
						"attempting to fix known cases...")

				# Have we corrected it?
				corrected = False

				# did our missed branch try to go back to a rep?
				target = simgr.missed[0].addr
				if self.project.arch.name == 'X86' or self.project.arch.name == 'AMD64':

					# does it looks like a rep? rep ret doesn't count!
					if self.project.factory.block(target).bytes.startswith("\xf3") and \
						not self.project.factory.block(target).bytes.startswith("\xf3\xc3"):

						l.info("rep discrepency detected, repairing...")
						# swap the stashes
						simgr.move('missed', 'chosen')
						simgr.move('active', 'missed')
						simgr.move('chosen', 'active')

						corrected = True
					else:
						l.info("...not rep showing up as one/many basic blocks")

				if not corrected:
					l.warning("Unable to correct discrepancy between qemu and angr.")

		return simgr
## 31.4 driller_core.py step -> tracer.py step
	def step(self, simgr, stash='active', **kwargs):
		simgr.step(stash=stash, **kwargs) 调用 tracer.py step

		# Mimic AFL's indexing scheme.
		if 'missed' in simgr.stashes and simgr.missed: #在tracer.py step中发现了missed的话
			# A bit ugly, might be replaced by tracer.predecessors[-1] or crash_monitor.last_state.
			prev_addr = simgr.one_missed.history.bbl_addrs[-1]  计算方法与afl qemu模式相同，见31.4.4
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

				l.debug("Found %#x -> %#x transition.", transition[0], transition[1])

				if not hit and transition not in self.encounters and not self._has_false(state) and mapped_to != 'cle##externs': #liu 如果fuzzer没有遍历到，driller也没有遍历到，并且不是恒假

					state.preconstrainer.remove_preconstraints() #liu 移除输入约束


					if state.satisfiable():
						# A completely new state transition.
						l.debug("Found a completely new transition, putting into 'diverted' stash.")
						simgr.stashes['diverted'].append(state) #liu 如果可解，则加入diverted stash
						self.encounters.add(transition) #liu encounters记录遍历过的边，是一个set集合，他的初始化为###################self.encounters.update(izip(self.trace, islice(self.trace, 1, None)))根据trace

					else:
						l.debug("State at %#x is not satisfiable.", transition[1])

				elif self._has_false(state):
					l.debug("State at %#x is not satisfiable even remove preconstraints.", transition[1])

				else:
					l.debug("%#x -> %#x transition has already been encountered.", transition[0], transition[1])

		return simgr
### 31.4.1 one_missed angr/sim_manager.py
	def __getattr__(self, item):
		try:
			return object.__getattribute__(self, item)
		except AttributeError:
			return SimulationManager._fetch_states(self, stash=item)
### 31.4.2 _fetch_states angr/sim_manager.py
	def _fetch_states(self, stash):
		if stash in self._stashes:
			return self._stashes[stash]
		elif stash == SimulationManager.ALL:
			return list(itertools.chain.from_iterable(self._stashes.values()))
		elif stash == 'mp_' + SimulationManager.ALL:
			return mulpyplexer.MP(self._fetch_states(stash=SimulationManager.ALL))
		elif stash.startswith('mp_'):
			return mulpyplexer.MP(self._stashes.get(stash[3:], []))
		elif stash.startswith('one_'):
			return self._stashes.get(stash[4:], [None])[0] #python dict字典get key，获取一个
		else:
			raise AttributeError("No such stash: %s" % stash)
### 31.4.3 remove_preconstraints <- step
	def remove_preconstraints(self, to_composite_solver=True, simplify=True):
		if not self.preconstraints:
			return

		# cache key set creation
		precon_cache_keys = set()

		for con in self.preconstraints:
			precon_cache_keys.add(con.cache_key)

		# if we used the replacement solver we didn't add constraints we need to remove so keep all constraints
		if o.REPLACEMENT_SOLVER in self.state.options:
			new_constraints = self.state.se.constraints
		else:
			new_constraints = filter(lambda x: x.cache_key not in precon_cache_keys, self.state.se.constraints) #从self.state.se.constraints过滤出来,关键数据结构。

		if self.state.has_plugin("zen_plugin"):
			new_constraints = self.state.get_plugin("zen_plugin").filter_constraints(new_constraints)

		if to_composite_solver:
			self.state.options.discard(o.REPLACEMENT_SOLVER)
			self.state.options.add(o.COMPOSITE_SOLVER)

		self.state.release_plugin('solver')
		self.state.add_constraints(*new_constraints) #添加新的约束

		l.debug("downsizing unpreconstrained state")
		self.state.downsize()

		if simplify:
			l.debug("simplifying solver...")
			self.state.solver.simplify() #简化约束
			l.debug("...simplification done")

		self.state.solver._solver.result = None


	断点 state.addr < 0x400644 and state.addr > 0x4005d0
### 31.4.4 覆盖率统计
#### 31.4.4.1 afl_maybe_log (afl qemu mode )
	shellphish-afl/bin/afl-cgc/qemu_mode/patches/afl-qemu-cpu-inl.h:
	#define AFL_QEMU_CPU_SNIPPET2 do { \
		if(tb->pc == afl_entry_point) { \
		  afl_setup(); \
		  afl_forkserver(env); \
		} \
		afl_maybe_log(tb->pc); \
	  } while (0)


	/* The equivalent of the tuple logging routine from afl-as.h. */

	static inline void afl_maybe_log(abi_ulong cur_loc) { 当前bbl地址

	  static abi_ulong prev_loc;
	  abi_ulong cur_val, overflow_loc;

	  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
		 Linux systems. */

	  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
		return;

	  /* Looks like QEMU always maps to fixed locations, so we can skip this:
		 cur_loc -= afl_start_code; */

	  /* Instruction addresses may be aligned. Let's mangle the value to get
		 something quasi-uniform. */

	  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
	  cur_loc &= MAP_SIZE - 1;

	  /* Implement probabilistic instrumentation by looking at scrambled block
		 address. This keeps the instrumented locations stable across runs. */

	  if (cur_loc >= afl_inst_rms) return;

	  cur_val = afl_area_ptr[cur_loc ^ prev_loc];

	  /* Check to see if the byte is overflowing, this should hopefully get us
		 another byte for branch hit counters. */
	  if (cur_val == 255)
	  {
		/* Yan thinks this is an acceptable hash so I do too. */
		overflow_loc  = (cur_loc ^ prev_loc) + 1;
		overflow_loc &= MAP_SIZE - 1;

		/* Increment our overflow counter. */
		afl_area_ptr[overflow_loc]++;
	  }

	  /* Now increment the original transition. */
	  afl_area_ptr[cur_loc ^ prev_loc]++;

	  prev_loc = cur_loc >> 1;

	}
# 32. hook api
	Angr/angr/procedures/posix/read.py下断点
	调用栈回溯
## 32.1 file.py read
	Angr/angr/storage/file.py
	def read(self, pos, size, **kwargs):
		"""
		Reads some data from the file, storing it into memory.

		:param pos:	 The address to write the read data into memory
		:param size:	The requested length of the read
		:return:		The real length of the read
		"""
		data, realsize = self.read_data(size, **kwargs) 读取文件内容，符号值
		if not self.state.solver.is_true(realsize == 0):
			self.state.memory.store(pos, data, size=realsize) 保存到内存
		return realsize
## 32.2 strcmp
	class strcmp(angr.SimProcedure):
		#pylint:disable=arguments-differ

		def run(self, a_addr, b_addr, wchar=False, ignore_case=False):
			self.argument_types = {0: self.ty_ptr(SimTypeString()),
						   1: self.ty_ptr(SimTypeString())}
			self.return_type = SimTypeInt(32, True)

			strlen = angr.SIM_PROCEDURES['libc']['strlen']

			a_strlen = self.inline_call(strlen, a_addr, wchar=wchar)
			b_strlen = self.inline_call(strlen, b_addr, wchar=wchar)
			maxlen = self.state.se.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

			strncmp = self.inline_call(angr.SIM_PROCEDURES['libc']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen, wchar=wchar, ignore_case=ignore_case)
			return strncmp.ret_expr
## 32.3 crc32
### 32.3.1 调用流程
#### 32.3.1.0 SimEngineHook: check  hook.py
	class SimEngineHook(SimEngine):
		def _check(self, state, procedure=None, **kwargs):
			# we have not yet entered the next step - we should check the "current" jumpkind
			if state.history.jumpkind == 'Ijk_NoHook':
				return False

			if state._ip.symbolic:
				# symbolic IP is not supported
				return False

			if procedure is None:
				if state.addr not in self.project._sim_procedures:
					if state.arch.name.startswith('ARM') and state.addr & 1 == 1 and state.addr - 1 in self.project._sim_procedures:
						return True
					return False

			return True
#### 32.3.1.1 hook.py:process
	Angr/angr/engines/hook.py
	def process(self, state, procedure=None, force_addr=None, **kwargs):
		"""
		Perform execution with a state.

		:param state:	   The state with which to execute
		:param procedure:   An instance of a SimProcedure to run, optional
		:param ret_to:	  The address to return to when this procedure is finished
		:param inline:	  This is an inline execution. Do not bother copying the state.
		:param force_addr:  Force execution to pretend that we're working at this concrete address
		:returns:		   A SimSuccessors object categorizing the execution's successor states
		"""
		addr = state.addr if force_addr is None else force_addr

		if procedure is None:
			if addr not in self.project._sim_procedures:
				if state.arch.name.startswith('ARM') and addr & 1 == 1 and addr - 1 in self.project._sim_procedures:
					procedure = self.project._sim_procedures[addr - 1]
				else:
					return SimSuccessors.failure()
			else:
				procedure = self.project._sim_procedures[addr] #每个导入函数都有吗？

		l.debug("Running %s (originally at %#x)", repr(procedure), addr)
		return self.project.factory.procedure_engine.process(state, procedure, force_addr=force_addr, **kwargs) #执行hook函数
#### 32.3.1.2 procedure.py:_process
	Angr/angr/engines/procedure.py
	def _process(self, state, successors, procedure, ret_to=None):
		successors.sort = 'SimProcedure'

		# fill in artifacts
		successors.artifacts['is_syscall'] = procedure.is_syscall
		successors.artifacts['name'] = procedure.display_name
		successors.artifacts['no_ret'] = procedure.NO_RET
		successors.artifacts['adds_exits'] = procedure.ADDS_EXITS

		# Update state.scratch
		state.scratch.sim_procedure = procedure
		state.history.recent_block_count = 1

		# prepare and run!
		state._inspect('simprocedure',
						BP_BEFORE,
						simprocedure_name=procedure.display_name,
						simprocedure_addr=successors.addr,
						simprocedure=procedure
						)
		if procedure.is_syscall:
			state._inspect('syscall', BP_BEFORE, syscall_name=procedure.display_name)

		cleanup_options = o.AUTO_REFS not in state.options
		if cleanup_options:
			state.options.add(o.AST_DEPS)
			state.options.add(o.AUTO_REFS)

		# do it
		inst = procedure.execute(state, successors, ret_to=ret_to)
		successors.artifacts['procedure'] = inst

		if cleanup_options:
			state.options.discard(o.AST_DEPS)
			state.options.discard(o.AUTO_REFS)

		if procedure.is_syscall:
			state._inspect('syscall', BP_AFTER, syscall_name=procedure.display_name)
		state._inspect('simprocedure',
						BP_AFTER,
						simprocedure_name=procedure.display_name,
						simprocedure_addr=successors.addr,
						simprocedure=inst
						)

		successors.description = 'SimProcedure ' + procedure.display_name
		if procedure.is_syscall:
			successors.description += ' (syscall)'
		if procedure.is_stub:
			successors.description += ' (stub)'
		successors.processed = True
#### 32.3.1.3 sim_procedure.py:execute
	Angr/angr/sim_procedure.py
	def execute(self, state, successors=None, arguments=None, ret_to=None):
		"""
		Call this method with a SimState and a SimSuccessors to execute the procedure.

		Alternately, successors may be none if this is an inline call. In that case, you should
		provide arguments to the function.
		"""
		# fill out all the fun stuff we don't want to frontload
		#if self.addr is None:
		#	self.addr = state.addr
		if self.arch is None:
			self.arch = state.arch
		if self.project is None:
			self.project = state.project
		if self.cc is None:
			if self.arch.name in DEFAULT_CC:
				self.cc = DEFAULT_CC[self.arch.name](self.arch)
			else:
				raise SimProcedureError('There is no default calling convention for architecture %s.'
										' You must specify a calling convention.', self.arch.name)

		inst = copy.copy(self)
		inst.state = state
		inst.successors = successors
		inst.ret_to = ret_to
		inst.inhibit_autoret = False

		# check to see if this is a syscall and if we should override its return value
		override = None
		if inst.is_syscall:
			state.history.recent_syscall_count = 1
			if len(state.posix.queued_syscall_returns):
				override = state.posix.queued_syscall_returns.pop(0)

		if callable(override):
			try:
				r = override(state, run=inst)
			except TypeError:
				r = override(state)
			inst.use_state_arguments = True

		elif override is not None:
			r = override
			inst.use_state_arguments = True

		else:
			# get the arguments

			# handle if this is a continuation from a return
			if inst.is_continuation:
				if state.callstack.top.procedure_data is None:
					raise SimProcedureError("Tried to return to a SimProcedure in an inapplicable stack frame!")

				saved_sp, sim_args, saved_local_vars, saved_lr = state.callstack.top.procedure_data
				state.regs.sp = saved_sp
				if saved_lr is not None:
					state.regs.lr = saved_lr
				inst.arguments = sim_args
				inst.use_state_arguments = True
				inst.call_ret_expr = state.registers.load(state.arch.ret_offset, state.arch.bytes, endness=state.arch.register_endness)
				for name, val in saved_local_vars:
					setattr(inst, name, val)
			else:
				if arguments is None:
					inst.use_state_arguments = True
					sim_args = [ inst.arg(_) for _ in xrange(inst.num_args) ]
					inst.arguments = sim_args
				else:
					inst.use_state_arguments = False
					sim_args = arguments[:inst.num_args]
					inst.arguments = arguments

			# run it
			l.debug("Executing %s%s%s%s with %s, %s",
					inst.display_name,
					' (syscall)' if inst.is_syscall else '',
					' (inline)' if not inst.use_state_arguments else '',
					' (stub)' if inst.is_stub else '',
					sim_args,
					inst.kwargs)
			r = getattr(inst, inst.run_func)(*sim_args, **inst.kwargs)

		if inst.returns and inst.is_function and not inst.inhibit_autoret:
			inst.ret(r)

		return inst
#### 32.3.1.4 ReturnUnconstrained
	Angr/angr/procedure/stubs/ReturnUnconstrained.py

	class ReturnUnconstrained(angr.SimProcedure):
		def run(self, *args, **kwargs): #pylint:disable=arguments-differ
			#pylint:disable=attribute-defined-outside-init

			return_val = kwargs.pop('return_val', None)
			if return_val is None:
				o = self.state.se.Unconstrained("unconstrained_ret_%s" % self.display_name, self.state.arch.bits, key=('api', '?', self.display_name)) #将返回值符号化
			else:
				o = return_val

			return o
### 32.3.2 初始化流程
#### 32.3.2.1 __init__,project.py:209
	__init__构造函数
	# Step 6: Register simprocedures as appropriate for library functions
	for obj in self.loader.initial_load_objects:
		self._register_object(obj)
#### 32.3.2.2 _register_object, project.py:295
	def _register_object(self, obj):
		"""
		This scans through an objects imports and hooks them with simprocedures from our library whenever possible
		"""

		# Step 1: get the set of libraries we are allowed to use to resolve unresolved symbols
		missing_libs = []
		for lib_name in self.loader.missing_dependencies:
			try:
				missing_libs.append(SIM_LIBRARIES[lib_name])
			except KeyError:
				l.info("There are no simprocedures for missing library %s :(", lib_name)

		# Step 2: Categorize every "import" symbol in each object.
		# If it's IGNORED, mark it for stubbing
		# If it's blacklisted, don't process it
		# If it matches a simprocedure we have, replace it
		for reloc in obj.imports.itervalues():
			# Step 2.1: Quick filter on symbols we really don't care about
			func = reloc.symbol
			if func is None:
				continue
			if not func.is_function and func.type != cle.backends.symbol.Symbol.TYPE_NONE:
				continue
			if not reloc.resolved:
				l.debug("Ignoring unresolved import '%s' from %s ...?", func.name, reloc.owner_obj)
				continue
			export = reloc.resolvedby
			if self.is_hooked(export.rebased_addr):
				l.debug("Already hooked %s (%s)", export.name, export.owner_obj)
				continue

			# Step 2.2: If this function has been resolved by a static dependency,
			# check if we actually can and want to replace it with a SimProcedure.
			# We opt out of this step if it is blacklisted by ignore_functions, which
			# will cause it to be replaced by ReturnUnconstrained later.
			if export.owner_obj is not self.loader._extern_object and \
					export.name not in self._ignore_functions:
				if self._check_user_blacklists(export.name):
					continue
				owner_name = export.owner_obj.provides
				if isinstance(self.loader.main_object, cle.backends.pe.PE):
					owner_name = owner_name.lower()
				if owner_name not in SIM_LIBRARIES:
					continue
				sim_lib = SIM_LIBRARIES[owner_name]
				if not sim_lib.has_implementation(export.name):
					continue
				l.info("Using builtin SimProcedure for %s from %s", export.name, sim_lib.name)
				self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, self.arch))

			# Step 2.3: If 2.2 didn't work, check if the symbol wants to be resolved
			# by a library we already know something about. Resolve it appropriately.
			# Note that _check_user_blacklists also includes _ignore_functions.
			# An important consideration is that even if we're stubbing a function out,
			# we still want to try as hard as we can to figure out where it comes from
			# so we can get the calling convention as close to right as possible.
			elif reloc.resolvewith is not None and reloc.resolvewith in SIM_LIBRARIES:
				sim_lib = SIM_LIBRARIES[reloc.resolvewith]
				if self._check_user_blacklists(export.name):
					if not func.is_weak:
						l.info("Using stub SimProcedure for unresolved %s from %s", func.name, sim_lib.name)
						self.hook_symbol(export.rebased_addr, sim_lib.get_stub(export.name, self.arch))
				else:
					l.info("Using builtin SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
					self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, self.arch))

			# Step 2.4: If 2.3 didn't work (the symbol didn't request a provider we know of), try
			# looking through each of the SimLibraries we're using to resolve unresolved
			# functions. If any of them know anything specifically about this function,
			# resolve it with that. As a final fallback, just ask any old SimLibrary
			# to resolve it.
			elif missing_libs:
				for sim_lib in missing_libs:
					if sim_lib.has_metadata(export.name):
						if self._check_user_blacklists(export.name):
							if not func.is_weak:
								l.info("Using stub SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
								self.hook_symbol(export.rebased_addr, sim_lib.get_stub(export.name, self.arch))
						else:
							l.info("Using builtin SimProcedure for unresolved %s from %s", export.name, sim_lib.name)
							self.hook_symbol(export.rebased_addr, sim_lib.get(export.name, self.arch))
						break
				else:
					if not func.is_weak:
						l.info("Using stub SimProcedure for unresolved %s", export.name)
						self.hook_symbol(export.rebased_addr, missing_libs[0].get(export.name, self.arch))

			# Step 2.5: If 2.4 didn't work (we have NO SimLibraries to work with), just
			# use the vanilla ReturnUnconstrained, assuming that this isn't a weak func
			elif not func.is_weak:
				l.info("Using stub SimProcedure for unresolved %s", export.name)
				self.hook_symbol(export.rebased_addr, SIM_PROCEDURES['stubs']['ReturnUnconstrained'](display_name=export.name, is_stub=True))
#### 32.3.2.3 hook_symbol, project.py:462
	def hook_symbol(self, symbol_name, simproc, kwargs=None, replace=None):
		"""
		Resolve a dependency in a binary. Looks up the address of the given symbol, and then hooks that
		address. If the symbol was not available in the loaded libraries, this address may be provided
		by the CLE externs object.

		Additionally, if instead of a symbol name you provide an address, some secret functionality will
		kick in and you will probably just hook that address, UNLESS you're on powerpc64 ABIv1 or some
		yet-unknown scary ABI that has its function pointers point to something other than the actual
		functions, in which case it'll do the right thing.

		:param symbol_name: The name of the dependency to resolve.
		:param simproc:	 The SimProcedure instance (or function) with which to hook the symbol
		:param kwargs:	  If you provide a SimProcedure for the hook, these are the keyword
							arguments that will be passed to the procedure's `run` method
							eventually.
		:param replace:	 Control the behavior on finding that the address is already hooked. If
							true, silently replace the hook. If false, warn and do not replace the
							hook. If none (default), warn and replace the hook.
		:returns:		   The address of the new symbol.
		:rtype:			 int
		"""
		if type(symbol_name) not in (int, long):
			sym = self.loader.find_symbol(symbol_name)
			if sym is None:
				# it could be a previously unresolved weak symbol..?
				new_sym = None
				for reloc in self.loader.find_relevant_relocations(symbol_name):
					if not reloc.symbol.is_weak:
						raise Exception("Symbol is strong but we couldn't find its resolution? Report to @rhelmot.")
					if new_sym is None:
						new_sym = self.loader.extern_object.make_extern(symbol_name)
					reloc.resolve(new_sym)
					reloc.relocate([])

				if new_sym is None:
					l.error("Could not find symbol %s", symbol_name)
					return None
				sym = new_sym

			basic_addr = sym.rebased_addr
		else:
			basic_addr = symbol_name
			symbol_name = None

		hook_addr, _ = self.simos.prepare_function_symbol(symbol_name, basic_addr=basic_addr)

		self.hook(hook_addr, simproc, kwargs=kwargs, replace=replace)
		return hook_addr
#### 32.3.2.4 hook, project.py:352
	def hook(self, addr, hook=None, length=0, kwargs=None, replace=False):
		"""
		Hook a section of code with a custom function. This is used internally to provide symbolic
		summaries of library functions, and can be used to instrument execution or to modify
		control flow.

		When hook is not specified, it returns a function decorator that allows easy hooking.
		Usage::

			# Assuming proj is an instance of angr.Project, we will add a custom hook at the entry
			# point of the project.
			@proj.hook(proj.entry)
			def my_hook(state):
				print "Welcome to execution!"

		:param addr:		The address to hook.
		:param hook:		A :class:`angr.project.Hook` describing a procedure to run at the
							given address. You may also pass in a SimProcedure class or a function
							directly and it will be wrapped in a Hook object for you.
		:param length:	  If you provide a function for the hook, this is the number of bytes
							that will be skipped by executing the hook by default.
		:param kwargs:	  If you provide a SimProcedure for the hook, these are the keyword
							arguments that will be passed to the procedure's `run` method
							eventually.
		:param replace:	 Control the behavior on finding that the address is already hooked. If
							true, silently replace the hook. If false (default), warn and do not
							replace the hook. If none, warn and replace the hook.
		"""
		if hook is None:
			# if we haven't been passed a thing to hook with, assume we're being used as a decorator
			return self._hook_decorator(addr, length=length, kwargs=kwargs)

		if kwargs is None: kwargs = {}

		l.debug('hooking %#x with %s', addr, hook)

		if self.is_hooked(addr):
			if replace is True:
				pass
			elif replace is False:
				l.warning("Address is already hooked, during hook(%#x, %s). Not re-hooking.", addr, hook)
				return
			else:
				l.warning("Address is already hooked, during hook(%#x, %s). Re-hooking.", addr, hook)

		if isinstance(hook, type):
			if once("hook_instance_warning"):
				l.critical("Hooking with a SimProcedure class is deprecated! Please hook with an instance.")
			hook = hook(**kwargs)

		if callable(hook):
			hook = SIM_PROCEDURES['stubs']['UserHook'](user_func=hook, length=length, **kwargs)

		self._sim_procedures[addr] = hook #注册
# 33. hook
	例子angr-doc/examples/asisctffinals2015_fake

	Argv[1]一个字符串，strtol转换为整数，然后经过运算转换为32个字节的字符串，格式为'ASIS{f5f7af556bd6973bd6f2687280a243d9}'，总长度为40.
## 33.1 测试代码：教给我们hook以及添加约束
	Explore的时间比较短，求解的时间比较长。
	Hook函数的编写，函数摘要，或者引入符号值。
	import angr

	unconstrained_number = None

	def strtol(state): 就是hook函数
	# We return an unconstrained number here
	global unconstrained_number
	unconstrained_number = state.solver.BVS(‘strtol’, 64)
	# Store it to rax
	state.regs.rax = unconstrained_number

	def main():
	p = angr.Project(“fake”, load_options={‘auto_load_libs’: False})
		p.hook(0x4004a7, strtol, length=5)#hook的位置，就是call指令

		state = p.factory.entry_state(
			args=['fake', '123'], # Specify an arbitrary number so that we can bypass 
								  # the check of argc in program
			env={"HOME": "/home/angr"}
		)
		ex = p.surveyors.Explorer(find=(0x400450, ),
								  start=state
								  )
		ex.run()

		found = ex.found[0]
		# We know the flag starts with "ASIS{"
		flag_addr = found.regs.rsp + 0x8 + 0x38 - 0x38
		found.add_constraints(found.memory.load(flag_addr, 5) == int("ASIS{".encode("hex"), 16))

		# More constraints: the whole flag should be printable
		for i in xrange(0, 32):
			cond_0 = found.memory.load(flag_addr + 5 + i, 1) >= ord('0')
			cond_1 = found.memory.load(flag_addr + 5 + i, 1) <= ord('9')
			cond_2 = found.memory.load(flag_addr + 5 + i, 1) >= ord('a')
			cond_3 = found.memory.load(flag_addr + 5 + i, 1) <= ord('f')
			found.add_constraints(
				found.solver.Or(
					found.solver.And(cond_0, cond_1),
					found.solver.And(cond_2, cond_3)
				)
			)

		# And it ends with a '}'
		found.add_constraints(found.memory.load(flag_addr + 5 + 32, 1) ==
									ord('}'))

		# In fact, putting less constraints (for example, only constraining the first 
		# several characters) is enough to get the final flag, and Z3 runs much faster 
		# if there are less constraints. I added all constraints just to stay on the 
		# safe side.

		flag = found.solver.eval(found.memory.load(flag_addr, 8 * 5))
		return hex(flag)[2:-1].decode("hex").strip('\0')

		#print "The number to input: ", found.solver.eval(unconstrained_number)
		#print "Flag:", flag

		# The number to input:  25313971399
		# Flag: ASIS{f5f7af556bd6973bd6f2687280a243d9}

	def test():
		a = main()
		assert main() == 'ASIS{f5f7af556bd6973bd6f2687280a243d9}'

	if __name__ == '__main__':
		print main()

	栈回溯
## 33.2 hook函数 angr/angr/project.py
	def hook(self, addr, hook=None, length=0, kwargs=None, replace=False):
		"""
		Hook a section of code with a custom function. This is used internally to provide symbolic
		summaries of library functions, and can be used to instrument execution or to modify
		control flow.

		When hook is not specified, it returns a function decorator that allows easy hooking.
		Usage::

			# Assuming proj is an instance of angr.Project, we will add a custom hook at the entry
			# point of the project.
			@proj.hook(proj.entry)
			def my_hook(state):
				print "Welcome to execution!"

		:param addr:		The address to hook.
		:param hook:		A :class:`angr.project.Hook` describing a procedure to run at the
							given address. You may also pass in a SimProcedure class or a function
							directly and it will be wrapped in a Hook object for you.
		:param length:	  If you provide a function for the hook, this is the number of bytes
							that will be skipped by executing the hook by default.
		:param kwargs:	  If you provide a SimProcedure for the hook, these are the keyword
							arguments that will be passed to the procedure's `run` method
							eventually.
		:param replace:	 Control the behavior on finding that the address is already hooked. If
							true, silently replace the hook. If false (default), warn and do not
							replace the hook. If none, warn and replace the hook.
		"""
		if hook is None:
			# if we haven't been passed a thing to hook with, assume we're being used as a decorator
			return self._hook_decorator(addr, length=length, kwargs=kwargs)

		if kwargs is None: kwargs = {}

		l.debug('hooking %#x with %s', addr, hook)

		if self.is_hooked(addr):
			if replace is True:
				pass
			elif replace is False:
				l.warning("Address is already hooked, during hook(%#x, %s). Not re-hooking.", addr, hook)
				return
			else:
				l.warning("Address is already hooked, during hook(%#x, %s). Re-hooking.", addr, hook)

		if isinstance(hook, type):
			if once("hook_instance_warning"):
				l.critical("Hooking with a SimProcedure class is deprecated! Please hook with an instance.")
			hook = hook(**kwargs)

		if callable(hook):
			hook = SIM_PROCEDURES['stubs']['UserHook'](user_func=hook, length=length, **kwargs)

		self._sim_procedures[addr] = hook #在这里注册
## 33.3 约束
	如何传递过来的呢？
	import angr

	class UserHook(angr.SimProcedure):
		NO_RET = True

		# pylint: disable=arguments-differ
		def run(self, user_func=None, length=None):
			result = user_func(self.state)
			if result is None:
				self.successors.add_successor(self.state, self.state.addr+length, self.state.se.true, 'Ijk_NoHook') #跳转到call指令之后的指令，作为successor
			else:
				for state in result:
					self.successors.add_successor(state, state.addr, state.scratch.guard, state.history.jumpkind)


	后继为

	转换为vex中间语言为

	其中offset=16就是rax。
	实现在vex/expressions/get.py
	class SimIRExpr_Get(SimIRExpr):
		def _execute(self):
			size = self.size_bytes(self._expr.type)
			size_in_bits = self.size_bits(self._expr.type)
			self.type = self._expr.type

			# get it!
			self.expr = self.state.registers.load(self._expr.offset, size)#加载寄存器

			if self.type.startswith('Ity_F'):
				self.expr = self.expr.raw_to_fp()

			# finish it and save the register references
			self._post_process()
			if o.TRACK_REGISTER_ACTIONS in self.state.options:
				r = SimActionData(self.state, self.state.registers.id, SimActionData.READ, addr=self._expr.offset,
								  size=size_in_bits, data=self.expr
								  )
				self.actions.append(r)
	最终也是从page结构获取的。
# 34. angr-doc例子
## 34.1 例子 angr-doc/examples/asisctffinals2015_fake
### 34.1.1 代码
	import angr

	def main():
		p = angr.Project("fake", auto_load_libs=False)

	state = p.factory.blank_state(addr=0x4004AC) #入口状态，起始状态

		inp = state.solver.BVS('inp', 8*8) #符号值定义
		state.regs.rax = inp #引入符号值到rax（污点引入）

		simgr= p.factory.simulation_manager(state)
	simgr.explore(find=0x400684) #开始遍历，找到路径（路径遍历）

		found = simgr.found[0] #找到的状态

		# We know the flag starts with "ASIS{"
		flag_addr = found.regs.rdi
		found.add_constraints(found.memory.load(flag_addr, 5) == int("ASIS{".encode("hex"), 16)) #添加约束

		# More constraints: the whole flag should be printable
		flag = found.memory.load(flag_addr, 40) #此时的内存值是与符号有关的表达式
		for i in xrange(5, 5+32):
			cond_0 = flag.get_byte(i) >= ord('0')
			cond_1 = flag.get_byte(i) <= ord('9')
			cond_2 = flag.get_byte(i) >= ord('a')
			cond_3 = flag.get_byte(i) <= ord('f')
			cond_4 = found.solver.And(cond_0, cond_1)
			cond_5 = found.solver.And(cond_2, cond_3)
			found.add_constraints(found.solver.Or(cond_4, cond_5)) #添加约束

		# And it ends with a '}'
		found.add_constraints(flag.get_byte(32+5) == ord('}'))

		# In fact, putting less constraints (for example, only constraining the first 
		# several characters) is enough to get the final flag, and Z3 runs much faster 
		# if there are less constraints. I added all constraints just to stay on the 
		# safe side.

		flag_str = found.solver.eval(flag, cast_to=str) #求解感兴趣的内存值
		return flag_str.rstrip('\0')

		#print "The number to input: ", found.solver.eval(inp)
		#print "Flag:", flag

		# The number to input:  25313971399
		# Flag: ASIS{f5f7af556bd6973bd6f2687280a243d9}

	def test():
		a = main()
		assert a == 'ASIS{f5f7af556bd6973bd6f2687280a243d9}'

	if __name__ == '__main__':
		import logging
		logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
		print main()
## 34.2 explore angr/angr/sim_manager.py
	@ImmutabilityMixin.immutable
	def explore(self, stash='active', n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None,
				num_find=1, **kwargs):
		"""
		Tick stash "stash" forward (up to "n" times or until "num_find" states are found), looking for condition "find",
		avoiding condition "avoid". Stores found states into "find_stash' and avoided states into "avoid_stash".

		The "find" and "avoid" parameters may be any of:

		- An address to find
		- A set or list of addresses to find
		- A function that takes a state and returns whether or not it matches.

		If an angr CFG is passed in as the "cfg" parameter and "find" is either a number or a list or a set, then
		any states which cannot possibly reach a success state without going through a failure state will be
		preemptively avoided.
		"""
		num_find += len(self._stashes[find_stash]) if find_stash in self._stashes else 0
		tech = self.use_technique(Explorer(find, avoid, find_stash, avoid_stash, cfg, num_find)) #遍历技术，或者遍历策略是可扩展的

		try:
			self.run(stash=stash, n=n, **kwargs)
		finally:
			self.remove_technique(tech)

		return self
### 34.2.1 run<-explore
	def run(self, stash='active', n=None, until=None, **kwargs):
		"""
		Run until the SimulationManager has reached a completed state, according to
		the current exploration techniques.

		:param stash:	   Operate on this stash
		:param n:		   Step at most this many times
		:param until:	   If provided, should be a function that takes a SimulationManager and
							returns True or False. Stepping will terminate when it is True.

		:return:			The resulting SimulationManager.
		:rtype:			 SimulationManager
		"""
		for _ in (itertools.count() if n is None else xrange(0, n)):
			if not self.complete() and self._stashes[stash]: #结束条件，找到find就结束，在technique中实现
				self.step(stash=stash, **kwargs)  #结合下面的step来看，是广度遍历算法，每次执行所有active的状态一步，然后获取新的active后继状态，继续。
				if not (until and until(self)): #直到找到,实际这个参数没有提供是None
					continue
			break
		return self
#### 34.2.1.1 step<-run<-explore
	def step(self, n=None, selector_func=None, step_func=None, stash='active',
				successor_func=None, until=None, filter_func=None, **run_args):
		"""
		Step a stash of states forward and categorize the successors appropriately.  广度遍历算法

		The parameters to this function allow you to control everything about the stepping and
		categorization process.

		:param stash:		   The name of the stash to step (default: 'active')
		:param n:			   (DEPRECATED) The number of times to step (default: 1 if "until" is not provided)
		:param selector_func:   If provided, should be a function that takes a state and returns a
								boolean. If True, the state will be stepped. Otherwise, it will be
								kept as-is.
		:param step_func:	   If provided, should be a function that takes a SimulationManager and
								returns a SimulationManager. Will be called with the SimulationManager
								at every step. Note that this function should not actually perform any
								stepping - it is meant to be a maintenance function called after each step.
		:param successor_func:  If provided, should be a function that takes a state and return its successors.
								Otherwise, project.factory.successors will be used.
		:param until:		   (DEPRECATED) If provided, should be a function that takes a SimulationManager and
								returns True or False. Stepping will terminate when it is True.
		:param filter_func:	 If provided, should be a function that takes a state and return the name
								of the stash, to which the state should be moved.

		Additionally, you can pass in any of the following keyword args for project.factory.sim_run:

		:param jumpkind:		The jumpkind of the previous exit
		:param addr:			An address to execute at instead of the state's ip.
		:param stmt_whitelist:  A list of stmt indexes to which to confine execution.
		:param last_stmt:	   A statement index at which to stop execution.
		:param thumb:		   Whether the block should be lifted in ARM's THUMB mode.
		:param backup_state:	A state to read bytes from instead of using project memory.
		:param opt_level:	   The VEX optimization level to use.
		:param insn_bytes:	  A string of bytes to use for the block instead of the project.
		:param size:			The maximum size of the block, in bytes.
		:param num_inst:		The maximum number of instructions.
		:param traceflags:	  traceflags to be passed to VEX. Default: 0

		:returns:		   The resulting SimulationManager.
		:rtype:			 SimulationManager
		"""
		l.info("Stepping %s of %s", stash, self)
		# 8<----------------- Compatibility layer -----------------
		if n is not None or until is not None:
			if once('simgr_step_n_until'):
				print "\x1b[31;1mDeprecation warning: the use of `n` and `until` arguments is deprecated. " \
						"Consider using simgr.run() with the same arguments if you want to specify " \
						"a number of steps or an additional condition on when to stop the execution.\x1b[0m"
			return self.run(stash, n, until, selector_func=selector_func, step_func=step_func,
							successor_func=successor_func, filter_func=filter_func, **run_args)
		# ------------------ Compatibility layer ---------------->8
		bucket = defaultdict(list)

		for state in self._fetch_states(stash=stash): #见31.4.2 获取一个状态，从_stashes,是一个active的队列

			goto = self.filter(state, filter_func)
			if isinstance(goto, tuple):
				goto, state = goto

			if goto not in (None, stash):
				bucket[goto].append(state)
				continue

			if not self.selector(state, selector_func):
				bucket[stash].append(state)
				continue

			pre_errored = len(self._errored)
			successors = self.step_state(state, successor_func, **run_args) #执行一个bbl，获得后继，实际是technique实现
			if not any(successors.itervalues()) and len(self._errored) == pre_errored:
				bucket['deadended'].append(state)
				continue

			for to_stash, successor_states in successors.iteritems():
				bucket[to_stash or stash].extend(successor_states)

		self._clear_states(stash=stash)
		for to_stash, states in bucket.iteritems():
			self._store_states(to_stash or stash, states) #保存下一步的状态到_stashes

		if step_func is not None:
			return step_func(self)
		return self
### 34.2.2 use_technique(Explorer<-explore
	见angr/angr/explore_techniques/explorer.py
	def complete(self, simgr):
		return len(simgr.stashes[self.find_stash]) >= self.num_find
	上面找到find就结束
	def complete(self):
		"""
		Returns whether or not this manager has reached a "completed" state.
		"""
		return self.completion_mode((tech.complete(self) for tech in self._techniques))
	上面在sim_manager.py,遍历所有的technique。
	在explore_techniques/explorer.py  filter函数中
	会返回find_stash（检查每个state）
	在sim_manager.py中的step函数中：
	goto = self.filter(state, filter_func)
	保存过滤出来的find的stash  

