<!-- TOC -->

- [1. bitmap](#1-bitmap)
	- [1.1 bitmap initial](#11-bitmap-initial)
		- [1.1.1 global variable afl/afl-fuzz.c](#111-global-variable-aflafl-fuzzc)
		- [1.1.2 setup_shm setup bitmap afl/afl-fuzz.c](#112-setup_shm-setup-bitmap-aflafl-fuzzc)
		- [1.1.3 ida _afl_maybe_log](#113-ida-_afl_maybe_log)
	- [1.2 bitmap update](#12-bitmap-update)
		- [1.2.1 ida _afl_maybe_log, see 1.1.3](#121-ida-_afl_maybe_log-see-113)
	- [1.3 bitmap use to select seeds](#13-bitmap-use-to-select-seeds)
- [2. fuzz_one](#2-fuzz_one)
	- [2.1 fuzz main call fuzz_one](#21-fuzz-main-call-fuzz_one)
	- [2.2 fuzz_one function](#22-fuzz_one-function)
		- [2.2.1 calculate_score only useful for havoc](#221-calculate_score-only-useful-for-havoc)
		- [2.2.2 common_fuzz_stuff](#222-common_fuzz_stuff)
			- [2.2.2.1 write_to_testcase](#2221-write_to_testcase)
				- [2.2.2.1.1 out_file initial](#22211-out_file-initial)
				- [2.2.2.1.2 out_dir initial](#22212-out_dir-initial)
			- [2.2.2.2 run_target](#2222-run_target)
			- [2.2.2.3 save_if_interesting](#2223-save_if_interesting)
				- [2.2.2.3.1 has_new_bits(virgin_bits)](#22231-has_new_bitsvirgin_bits)
				- [2.2.2.3.2 virgin_bits initial in read_bitmap](#22232-virgin_bits-initial-in-read_bitmap)
				- [2.2.2.3.3 caller of read_bitmap](#22233-caller-of-read_bitmap)
				- [2.2.2.3.4 setup_shm if not call read_bitmap virgin_bits initial](#22234-setup_shm-if-not-call-read_bitmap-virgin_bits-initial)
				- [2.2.2.3.5 add_to_queue](#22235-add_to_queue)
				- [2.2.2.3.6 calibrate_case](#22236-calibrate_case)
					- [2.2.2.3.6.1 update_bitmap_score](#222361-update_bitmap_score)
	- [2.3 favored](#23-favored)
		- [2.3.1 cull_queue](#231-cull_queue)
		- [2.3.2 update_bitmap_score](#232-update_bitmap_score)

<!-- /TOC -->
# 1. bitmap 
## 1.1 bitmap initial
### 1.1.1 global variable afl/afl-fuzz.c 
	struct queue_entry {

	u8* fname;                          /* File name for the test case      */
	u32 len;                            /* Input length                     */

	u8  cal_failed,                     /* Calibration failed?              */
		trim_done,                      /* Trimmed?                         */
		was_fuzzed,                     /* Had any fuzzing done yet?        */
		passed_det,                     /* Deterministic stages passed?     */
		has_new_cov,                    /* Triggers new coverage?           */
		var_behavior,                   /* Variable behavior?               */
		favored,                        /* Currently favored?               */
		fs_redundant;                   /* Marked as redundant in the fs?   */

	u32 bitmap_size,                    /* Number of bits set in bitmap     */
		exec_cksum;                     /* Checksum of the execution trace  */

	u64 exec_us,                        /* Execution time (us)              */
		handicap,                       /* Number of queue cycles behind    */
		depth;                          /* Path depth                       */

	u8* trace_mini;                     /* Trace bytes, if kept             */
	u32 tc_ref;                         /* Trace bytes ref count            */

	struct queue_entry *next,           /* Next element, if any             */
						*next_100;       /* 100 elements ahead               */

	};

	static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
							*queue_cur, /* Current offset within the queue  */
							*queue_top, /* Top of the list                  */
							*q_prev100; /* Previous 100 marker              */

	static struct queue_entry*
	top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */
	#liu global variable
	EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  */

	EXP_ST u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
			virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
			virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

	static u8  var_bytes[MAP_SIZE];       /* Bytes that appear to be variable */

	static s32 shm_id;                    /* ID of the SHM region             */
### 1.1.2 setup_shm setup bitmap afl/afl-fuzz.c
	/* Configure shared memory and virgin_bits. This is called at startup. */

	EXP_ST void setup_shm(void) {

	u8* shm_str;

	if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

	memset(virgin_tmout, 255, MAP_SIZE);
	memset(virgin_crash, 255, MAP_SIZE);

	shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600); //liu shmget() returns the identifier of the System V shared memory segment associated with the value of the argument key.  It may be used either to obtain the identifier of a previously created shared memory segment (when shmflg is zero and key does not have the value IPC_PRIVATE), or to create a new set.
	//int shmget(key_t key, size_t size, int shmflg);  //liu this api creates a new set here.

	if (shm_id < 0) PFATAL("shmget() failed");

	atexit(remove_shm);

	shm_str = alloc_printf("%d", shm_id);

	/* If somebody is asking us to fuzz instrumented binaries in dumb mode,
		we don't want them to detect instrumentation, since we won't be sending
		fork server commands. This should be replaced with better auto-detection
		later on, perhaps? */

	if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1); //liu set the env to the shm_id for other processes.

	ck_free(shm_str);

	trace_bits = shmat(shm_id, NULL, 0); //liu set trace_bits global variable.
	//shmat() attaches the shared memory segment identified by shmid to the address space of the calling process. The attaching address is specified by shmaddr with one of the following criteria.
	
	if (!trace_bits) PFATAL("shmat() failed");

	}
### 1.1.3 ida _afl_maybe_log
	#liu At the head of each bbl, there are these instructions as follows:
		mov rcx,random_short_16bit
		call _afl_maybe_log
	char __usercall _afl_maybe_log@<al>(char a1@<of>, __int64 _RAX@<rax>, __int64 a3@<rcx>, __m128i a4@<xmm0>, __m128i a5@<xmm1>, __m128i a6@<xmm2>, __m128i a7@<xmm3>, __m128i a8@<xmm4>, __m128i a9@<xmm5>, __m128i a10@<xmm6>, __m128i a11@<xmm7>, __m128i a12@<xmm8>, __m128i a13@<xmm9>, __m128i a14@<xmm10>, __m128i a15@<xmm11>, __m128i a16@<xmm12>, __m128i a17@<xmm13>, __m128i a18@<xmm14>, __m128i a19@<xmm15>, __int64 a20, __int64 a21, __int64 a22, int a23, int a24, int a25, int a26, int a27, int a28, __int64 a29, int a30, int a31, __int64 a32, int a33, int a34, __int64 a35, int a36, int a37, __int64 a38, int a39, int a40, __int64 a41, int a42, int a43, __int64 a44, int a45, int a46, __int64 a47, int a48, int a49, __int64 a50, int a51, int a52, __int64 a53, int a54, int a55, __int64 a56, int a57, int a58, __int64 a59, int a60, int a61)
	{
	__int64 v61; // rdx@1
	__int64 v62; // rcx@2
	char *v64; // rax@7
	int v65; // eax@8
	void *v66; // rax@8
	int v67; // edi@10
	__int64 v68; // rax@11
	__int64 v69; // rax@13
	__int64 v70; // [sp-10h] [bp-20h]@9
	__int64 retaddr; // [sp+10h] [bp+0h]@7
	__int64 v72; // [sp+18h] [bp+8h]@7

	__asm { lahf }
	LOBYTE(_RAX) = a1;
	v61 = _afl_area_ptr;
	if ( !_afl_area_ptr )
	{
		if ( _afl_setup_failure )
		return _RAX + 127;
		v61 = _afl_global_area_ptr;
		if ( _afl_global_area_ptr )
		{
		_afl_area_ptr = _afl_global_area_ptr;
		}
		else
		{
		retaddr = _RAX;
		v72 = a3;
		_mm_storel_epi64((__m128i *)&a31, a4);
		_mm_storel_epi64((__m128i *)&a33, a5);
		_mm_storel_epi64((__m128i *)&a35, a6);
		_mm_storel_epi64((__m128i *)&a37, a7);
		_mm_storel_epi64((__m128i *)&a39, a8);
		_mm_storel_epi64((__m128i *)&a41, a9);
		_mm_storel_epi64((__m128i *)&a43, a10);
		_mm_storel_epi64((__m128i *)&a45, a11);
		_mm_storel_epi64((__m128i *)&a47, a12);
		_mm_storel_epi64((__m128i *)&a49, a13);
		_mm_storel_epi64((__m128i *)&a51, a14);
		_mm_storel_epi64((__m128i *)&a53, a15);
		_mm_storel_epi64((__m128i *)&a55, a16);
		_mm_storel_epi64((__m128i *)&a57, a17);
		_mm_storel_epi64((__m128i *)&a59, a18);
		_mm_storel_epi64((__m128i *)&a61, a19);
		v64 = getenv("__AFL_SHM_ID"); //liu 获取共享内存map的地址，通过环境变量(afl-fuzz.c initially set it)
		if ( !v64 || (v65 = atoi(v64), v66 = shmat(v65, 0LL, 0), v66 == (void *)-1) )//liu shmat get the map
		{
			++_afl_setup_failure;
			LOBYTE(_RAX) = retaddr;
			return _RAX + 127;
		}
		_afl_area_ptr = (__int64)v66;//liu 共享内存map赋值
		_afl_global_area_ptr = v66;
		v70 = (__int64)v66;
		if ( write(199, &_afl_temp, 4uLL) == 4 ) //通知afl-fuzz父进程init_forkserver函数，已经启动forkserver
		{
			while ( 1 )
			{
				v67 = 198;
				if ( read(198, &_afl_temp, 4uLL) != 4 )//等待启动命令，run_target
					break;
				LODWORD(v68) = fork();//liu fork grandchild
				if ( v68 < 0 )
					break;
				if ( !v68 )
					goto __afl_fork_resume;//liu 孙子进程继续跑测试软件
				_afl_fork_pid = v68;
				write(199, &_afl_fork_pid, 4uLL);//forkserver将孙子进程pid发给afl-fuzz
				v67 = _afl_fork_pid;
				LODWORD(v69) = waitpid(_afl_fork_pid, &_afl_temp, 0);//https://linux.die.net/man/2/waitpid afl_temp保存exit status
				if ( v69 <= 0 )
					break;
				write(199, &_afl_temp, 4uLL);//liu forkserver将孙子进程的退出状态发给afl-fuzz
			}
			_exit(v67);
		}
	__afl_fork_resume:
		close(198);
		close(199);
		v61 = v70;
		LOBYTE(_RAX) = retaddr;
		a3 = v72;
		}
	}
	v62 = _afl_prev_loc ^ a3;//liu a3来自于编译时的随机数，代表该bbl块, rcx
	_afl_prev_loc ^= v62;//_afl_prev_loc记录前一个bbl地址
	_afl_prev_loc = (unsigned __int64)_afl_prev_loc >> 1;//但是会将前一个bbl地址移位，为的是相反方向的a->b 与b->a是不同的。
	++*(_BYTE *)(v61 + v62); // map count ++
	return _RAX + 127;
	}
	覆盖率计算

	通过在编译期间instrument一些指令来捕获branch (edge) coverage和运行时分支执行计数 
	在分支点插入的指令大概如下：

	cur_location = <COMPILE_TIME_RANDOM>;
	shared_mem[cur_location ^ prev_location]++; 
	prev_location = cur_location >> 1;
	为了简化连接复杂对象的过程和保持XOR输出平均分布，当前位置是随机产生的。

	share_mem[]数组是一个调用者传给被instrument程序的64KB的共享内存区域，数组的元素是Byte。数组中的每个元素，都被编码成一个(branch_src, branch_dst)，相当于存储路径的bitmap。这个数组的大小要应该能存2K到10K个分支节点，这样即可以减少冲突，也可以实现毫秒级别的分析。 
	这种形式的覆盖率，相对于简单的基本块覆盖率来说，对程序运行路径提供了一个更好的描述。以下面两个路径产生的tupes为例： 
	A -> B -> C -> D -> E (tuples: AB, BC, CD, DE) 
	A -> B -> D -> C -> E (tuples: AB, BD, DC, CE) 
	这更有助于发现代码的漏洞，因为大多数安全漏洞经常是一些没有预料到的状态转移，而不是因为没有覆盖那一块代码。

	最后一行右移操作是用来保持tuples的定向性。如果没有右移操作，A ^ B和B ^ A就没办法区别了，同样A ^ A和B ^ B也是一样的。Intel CPU缺少算数指令，左移可能会会导致级数重置为0，但是这种可能性很小，用左移纯粹是为了效率。

## 1.2 bitmap update
### 1.2.1 ida _afl_maybe_log, see 1.1.3
	v62 = _afl_prev_loc ^ a3;//liu a3来自于编译时的随机数，代表该bbl块, rcx
	_afl_prev_loc ^= v62;//_afl_prev_loc记录前一个bbl地址
	_afl_prev_loc = (unsigned __int64)_afl_prev_loc >> 1;//但是会将前一个bbl地址移位，为的是相反方向的a->b 与b->a是不同的。
	++*(_BYTE *)(v61 + v62); // map count ++
## 1.3 bitmap use to select seeds

# 2. fuzz_one
## 2.1 fuzz main call fuzz_one
	while (1) {

	u8 skipped_fuzz;

	cull_queue();

	if (!queue_cur) {

		queue_cycle++;
		current_entry     = 0;
		cur_skipped_paths = 0;
		queue_cur         = queue;

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

	skipped_fuzz = fuzz_one(use_argv); //liu call fuzz_one 

	if (!stop_soon && sync_id && !skipped_fuzz) {
		
		if (!(sync_interval_cnt++ % SYNC_INTERVAL))
		sync_fuzzers(use_argv);

	}

	if (!stop_soon && exit_1) stop_soon = 2;

	if (stop_soon) break;

	queue_cur = queue_cur->next; //liu queue_cur update
	current_entry++;

	}	
## 2.2 fuzz_one function
	/* Take the current entry from the queue, fuzz it for a while. This
	function is a tad too long... returns 0 if fuzzed successfully, 1 if
	skipped or bailed out. */

	static u8 fuzz_one(char** argv) {

	s32 len, fd, temp_len, i, j;
	u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
	u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
	u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

	u8  ret_val = 1, doing_det = 0;

	u8  a_collect[MAX_AUTO_EXTRA];
	u32 a_len = 0;

	#ifdef IGNORE_FINDS

	/* In IGNORE_FINDS mode, skip any entries that weren't in the
		initial data set. */

	if (queue_cur->depth > 1) return 1;

	#else

	if (pending_favored) { //liu select variable pending_favored queue_cur->was_fuzzed queue_cur->favored

		/* If we have any favored, non-fuzzed new arrivals in the queue,
		possibly skip to them at the expense of already-fuzzed or non-favored
		cases. */

		if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
			UR(100) < SKIP_TO_NEW_PROB) return 1;

	} else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

		/* Otherwise, still possibly skip non-favored cases, albeit less often.
		The odds of skipping stuff are higher for already-fuzzed inputs and
		lower for never-fuzzed entries. */

		if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

		if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

		} else {

		if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

		}

	}

	#endif /* ^IGNORE_FINDS */

	if (not_on_tty) {
		ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
			current_entry, queued_paths, unique_crashes);
		fflush(stdout);
	}

	/* Map the test case into memory. */

	fd = open(queue_cur->fname, O_RDONLY);//liu open queue_cur->fname

	if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

	len = queue_cur->len;

	orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);//liu map file

	if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

	close(fd);

	/* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
		single byte anyway, so it wouldn't give us any performance or memory usage
		benefits. */

	out_buf = ck_alloc_nozero(len); //out_buf mutate buf

	subseq_tmouts = 0;

	cur_depth = queue_cur->depth;

	/*******************************************
	* CALIBRATION (only if failed earlier on) *
	*******************************************/

	if (queue_cur->cal_failed) {

		u8 res = FAULT_TMOUT;

		if (queue_cur->cal_failed < CAL_CHANCES) {

		res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

		if (res == FAULT_ERROR)
			FATAL("Unable to execute target application");

		}

		if (stop_soon || res != crash_mode) {
		cur_skipped_paths++;
		goto abandon_entry;
		}

	}

	/************
	* TRIMMING *
	************/

	if (!dumb_mode && !queue_cur->trim_done) {

		u8 res = trim_case(argv, queue_cur, in_buf);

		if (res == FAULT_ERROR)
		FATAL("Unable to execute target application");

		if (stop_soon) {
		cur_skipped_paths++;
		goto abandon_entry;
		}

		/* Don't retry trimming, even if it failed. */

		queue_cur->trim_done = 1;

		if (len != queue_cur->len) len = queue_cur->len;

	}

	memcpy(out_buf, in_buf, len);

	/*********************
	* PERFORMANCE SCORE *
	*********************/

	orig_perf = perf_score = calculate_score(queue_cur);//liu call calculate_score

	/* Skip right away if -d is given, if we have done deterministic fuzzing on
		this entry ourselves (was_fuzzed), or if it has gone through deterministic
		testing in earlier, resumed runs (passed_det). */

	if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
		goto havoc_stage;

	/* Skip deterministic fuzzing if exec path checksum puts this out of scope
		for this master instance. */

	if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
		goto havoc_stage;

	doing_det = 1;

	/*********************************************
	* SIMPLE BITFLIP (+dictionary construction) *
	*********************************************/

	#define FLIP_BIT(_ar, _b) do { \
		u8* _arf = (u8*)(_ar); \
		u32 _bf = (_b); \
		_arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
	} while (0)

	/* Single walking bit. */

	stage_short = "flip1";
	stage_max   = len << 3;
	stage_name  = "bitflip 1/1";

	stage_val_type = STAGE_VAL_NONE;

	orig_hit_cnt = queued_paths + unique_crashes;

	prev_cksum = queue_cur->exec_cksum;

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		stage_cur_byte = stage_cur >> 3;

		FLIP_BIT(out_buf, stage_cur);//liu mutate out_buf

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry; //liu call common_fuzz_stuff

		FLIP_BIT(out_buf, stage_cur);

		/* While flipping the least significant bit in every byte, pull of an extra
		trick to detect possible syntax tokens. In essence, the idea is that if
		you have a binary blob like this:

		xxxxxxxxIHDRxxxxxxxx

		...and changing the leading and trailing bytes causes variable or no
		changes in program flow, but touching any character in the "IHDR" string
		always produces the same, distinctive path, it's highly likely that
		"IHDR" is an atomically-checked magic value of special significance to
		the fuzzed format.

		We do this here, rather than as a separate stage, because it's a nice
		way to keep the operation approximately "free" (i.e., no extra execs).
		
		Empirically, performing the check when flipping the least significant bit
		is advantageous, compared to doing it at the time of more disruptive
		changes, where the program flow may be affected in more violent ways.

		The caveat is that we won't generate dictionaries in the -d mode or -S
		mode - but that's probably a fair trade-off.

		This won't work particularly well with paths that exhibit variable
		behavior, but fails gracefully, so we'll carry out the checks anyway.

		*/

		if (!dumb_mode && (stage_cur & 7) == 7) {

		u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST); //liu hash32 trace_bits

		if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

			/* If at end of file and we are still collecting a string, grab the
			final character and force output. */

			if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
			a_len++;

			if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
			maybe_add_auto(a_collect, a_len);

		} else if (cksum != prev_cksum) {

			/* Otherwise, if the checksum has changed, see if we have something
			worthwhile queued up, and collect that if the answer is yes. */

			if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
			maybe_add_auto(a_collect, a_len);

			a_len = 0;
			prev_cksum = cksum;

		}

		/* Continue collecting string, but only if the bit flip actually made
			any difference - we don't want no-op tokens. */

		if (cksum != queue_cur->exec_cksum) {

			if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
			a_len++;

		}

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP1] += stage_max;

	/* Two walking bits. */

	stage_name  = "bitflip 2/1";
	stage_short = "flip2";
	stage_max   = (len << 3) - 1;

	orig_hit_cnt = new_hit_cnt;

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		stage_cur_byte = stage_cur >> 3;

		FLIP_BIT(out_buf, stage_cur);
		FLIP_BIT(out_buf, stage_cur + 1);

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		FLIP_BIT(out_buf, stage_cur);
		FLIP_BIT(out_buf, stage_cur + 1);

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP2] += stage_max;

	/* Four walking bits. */

	stage_name  = "bitflip 4/1";
	stage_short = "flip4";
	stage_max   = (len << 3) - 3;

	orig_hit_cnt = new_hit_cnt;

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		stage_cur_byte = stage_cur >> 3;

		FLIP_BIT(out_buf, stage_cur);
		FLIP_BIT(out_buf, stage_cur + 1);
		FLIP_BIT(out_buf, stage_cur + 2);
		FLIP_BIT(out_buf, stage_cur + 3);

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		FLIP_BIT(out_buf, stage_cur);
		FLIP_BIT(out_buf, stage_cur + 1);
		FLIP_BIT(out_buf, stage_cur + 2);
		FLIP_BIT(out_buf, stage_cur + 3);

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP4] += stage_max;

	/* Effector map setup. These macros calculate:

		EFF_APOS      - position of a particular file offset in the map.
		EFF_ALEN      - length of a map with a particular number of bytes.
		EFF_SPAN_ALEN - map span for a sequence of bytes.

	*/

	#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
	#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
	#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
	#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

	/* Initialize effector map for the next step (see comments below). Always
		flag first and last byte as doing something. */

	eff_map    = ck_alloc(EFF_ALEN(len));
	eff_map[0] = 1;

	if (EFF_APOS(len - 1) != 0) {
		eff_map[EFF_APOS(len - 1)] = 1;
		eff_cnt++;
	}

	/* Walking byte. */

	stage_name  = "bitflip 8/8";
	stage_short = "flip8";
	stage_max   = len;

	orig_hit_cnt = new_hit_cnt;

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		stage_cur_byte = stage_cur;

		out_buf[stage_cur] ^= 0xFF;

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		/* We also use this stage to pull off a simple trick: we identify
		bytes that seem to have no effect on the current execution path
		even when fully flipped - and we skip them during more expensive
		deterministic stages, such as arithmetics or known ints. */

		if (!eff_map[EFF_APOS(stage_cur)]) {

		u32 cksum;

		/* If in dumb mode or if the file is very short, just flag everything
			without wasting time on checksums. */

		if (!dumb_mode && len >= EFF_MIN_LEN)
			cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
		else
			cksum = ~queue_cur->exec_cksum;

		if (cksum != queue_cur->exec_cksum) {
			eff_map[EFF_APOS(stage_cur)] = 1;
			eff_cnt++;
		}

		}

		out_buf[stage_cur] ^= 0xFF;

	}

	/* If the effector map is more than EFF_MAX_PERC dense, just flag the
		whole thing as worth fuzzing, since we wouldn't be saving much time
		anyway. */

	if (eff_cnt != EFF_ALEN(len) &&
		eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

		memset(eff_map, 1, EFF_ALEN(len));

		blocks_eff_select += EFF_ALEN(len);

	} else {

		blocks_eff_select += eff_cnt;

	}

	blocks_eff_total += EFF_ALEN(len);

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP8] += stage_max;

	/* Two walking bytes. */

	if (len < 2) goto skip_bitflip;

	stage_name  = "bitflip 16/8";
	stage_short = "flip16";
	stage_cur   = 0;
	stage_max   = len - 1;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 1; i++) {

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
		stage_max--;
		continue;
		}

		stage_cur_byte = i;

		*(u16*)(out_buf + i) ^= 0xFFFF;

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
		stage_cur++;

		*(u16*)(out_buf + i) ^= 0xFFFF;


	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP16] += stage_max;

	if (len < 4) goto skip_bitflip;

	/* Four walking bytes. */

	stage_name  = "bitflip 32/8";
	stage_short = "flip32";
	stage_cur   = 0;
	stage_max   = len - 3;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 3; i++) {

		/* Let's consult the effector map... */
		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
			!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
		stage_max--;
		continue;
		}

		stage_cur_byte = i;

		*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
		stage_cur++;

		*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_FLIP32] += stage_max;

	skip_bitflip:

	if (no_arith) goto skip_arith;

	/**********************
	* ARITHMETIC INC/DEC *
	**********************/

	/* 8-bit arithmetics. */

	stage_name  = "arith 8/8";
	stage_short = "arith8";
	stage_cur   = 0;
	stage_max   = 2 * len * ARITH_MAX;

	stage_val_type = STAGE_VAL_LE;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len; i++) {

		u8 orig = out_buf[i];

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)]) {
		stage_max -= 2 * ARITH_MAX;
		continue;
		}

		stage_cur_byte = i;

		for (j = 1; j <= ARITH_MAX; j++) {

		u8 r = orig ^ (orig + j);

		/* Do arithmetic operations only if the result couldn't be a product
			of a bitflip. */

		if (!could_be_bitflip(r)) {

			stage_cur_val = j;
			out_buf[i] = orig + j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		r =  orig ^ (orig - j);

		if (!could_be_bitflip(r)) {

			stage_cur_val = -j;
			out_buf[i] = orig - j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		out_buf[i] = orig;

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_ARITH8] += stage_max;

	/* 16-bit arithmetics, both endians. */

	if (len < 2) goto skip_arith;

	stage_name  = "arith 16/8";
	stage_short = "arith16";
	stage_cur   = 0;
	stage_max   = 4 * (len - 1) * ARITH_MAX;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 1; i++) {

		u16 orig = *(u16*)(out_buf + i);

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
		stage_max -= 4 * ARITH_MAX;
		continue;
		}

		stage_cur_byte = i;

		for (j = 1; j <= ARITH_MAX; j++) {

		u16 r1 = orig ^ (orig + j),
			r2 = orig ^ (orig - j),
			r3 = orig ^ SWAP16(SWAP16(orig) + j),
			r4 = orig ^ SWAP16(SWAP16(orig) - j);

		/* Try little endian addition and subtraction first. Do it only
			if the operation would affect more than one byte (hence the 
			& 0xff overflow checks) and if it couldn't be a product of
			a bitflip. */

		stage_val_type = STAGE_VAL_LE; 

		if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

			stage_cur_val = j;
			*(u16*)(out_buf + i) = orig + j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;
	
		} else stage_max--;

		if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

			stage_cur_val = -j;
			*(u16*)(out_buf + i) = orig - j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		/* Big endian comes next. Same deal. */

		stage_val_type = STAGE_VAL_BE;


		if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

			stage_cur_val = j;
			*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		if ((orig >> 8) < j && !could_be_bitflip(r4)) {

			stage_cur_val = -j;
			*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		*(u16*)(out_buf + i) = orig;

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_ARITH16] += stage_max;

	/* 32-bit arithmetics, both endians. */

	if (len < 4) goto skip_arith;

	stage_name  = "arith 32/8";
	stage_short = "arith32";
	stage_cur   = 0;
	stage_max   = 4 * (len - 3) * ARITH_MAX;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 3; i++) {

		u32 orig = *(u32*)(out_buf + i);

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
			!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
		stage_max -= 4 * ARITH_MAX;
		continue;
		}

		stage_cur_byte = i;

		for (j = 1; j <= ARITH_MAX; j++) {

		u32 r1 = orig ^ (orig + j),
			r2 = orig ^ (orig - j),
			r3 = orig ^ SWAP32(SWAP32(orig) + j),
			r4 = orig ^ SWAP32(SWAP32(orig) - j);

		/* Little endian first. Same deal as with 16-bit: we only want to
			try if the operation would have effect on more than two bytes. */

		stage_val_type = STAGE_VAL_LE;

		if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

			stage_cur_val = j;
			*(u32*)(out_buf + i) = orig + j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

			stage_cur_val = -j;
			*(u32*)(out_buf + i) = orig - j;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		/* Big endian next. */

		stage_val_type = STAGE_VAL_BE;

		if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

			stage_cur_val = j;
			*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

			stage_cur_val = -j;
			*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		*(u32*)(out_buf + i) = orig;

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_ARITH32] += stage_max;

	skip_arith:

	/**********************
	* INTERESTING VALUES *
	**********************/

	stage_name  = "interest 8/8";
	stage_short = "int8";
	stage_cur   = 0;
	stage_max   = len * sizeof(interesting_8);

	stage_val_type = STAGE_VAL_LE;

	orig_hit_cnt = new_hit_cnt;

	/* Setting 8-bit integers. */

	for (i = 0; i < len; i++) {

		u8 orig = out_buf[i];

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)]) {
		stage_max -= sizeof(interesting_8);
		continue;
		}

		stage_cur_byte = i;

		for (j = 0; j < sizeof(interesting_8); j++) {

		/* Skip if the value could be a product of bitflips or arithmetics. */

		if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
			could_be_arith(orig, (u8)interesting_8[j], 1)) {
			stage_max--;
			continue;
		}

		stage_cur_val = interesting_8[j];
		out_buf[i] = interesting_8[j];

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		out_buf[i] = orig;
		stage_cur++;

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_INTEREST8] += stage_max;

	/* Setting 16-bit integers, both endians. */

	if (no_arith || len < 2) goto skip_interest;

	stage_name  = "interest 16/8";
	stage_short = "int16";
	stage_cur   = 0;
	stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 1; i++) {

		u16 orig = *(u16*)(out_buf + i);

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
		stage_max -= sizeof(interesting_16);
		continue;
		}

		stage_cur_byte = i;

		for (j = 0; j < sizeof(interesting_16) / 2; j++) {

		stage_cur_val = interesting_16[j];

		/* Skip if this could be a product of a bitflip, arithmetics,
			or single-byte interesting value insertion. */

		if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
			!could_be_arith(orig, (u16)interesting_16[j], 2) &&
			!could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

			stage_val_type = STAGE_VAL_LE;

			*(u16*)(out_buf + i) = interesting_16[j];

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
			!could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
			!could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
			!could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

			stage_val_type = STAGE_VAL_BE;

			*(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		}

		*(u16*)(out_buf + i) = orig;

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_INTEREST16] += stage_max;

	if (len < 4) goto skip_interest;

	/* Setting 32-bit integers, both endians. */

	stage_name  = "interest 32/8";
	stage_short = "int32";
	stage_cur   = 0;
	stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len - 3; i++) {

		u32 orig = *(u32*)(out_buf + i);

		/* Let's consult the effector map... */

		if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
			!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
		stage_max -= sizeof(interesting_32) >> 1;
		continue;
		}

		stage_cur_byte = i;

		for (j = 0; j < sizeof(interesting_32) / 4; j++) {

		stage_cur_val = interesting_32[j];

		/* Skip if this could be a product of a bitflip, arithmetics,
			or word interesting value insertion. */

		if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
			!could_be_arith(orig, interesting_32[j], 4) &&
			!could_be_interest(orig, interesting_32[j], 4, 0)) {

			stage_val_type = STAGE_VAL_LE;

			*(u32*)(out_buf + i) = interesting_32[j];

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
			!could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
			!could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
			!could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

			stage_val_type = STAGE_VAL_BE;

			*(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			stage_cur++;

		} else stage_max--;

		}

		*(u32*)(out_buf + i) = orig;

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_INTEREST32] += stage_max;

	skip_interest:

	/********************
	* DICTIONARY STUFF *
	********************/

	if (!extras_cnt) goto skip_user_extras;

	/* Overwrite with user-supplied extras. */

	stage_name  = "user extras (over)";
	stage_short = "ext_UO";
	stage_cur   = 0;
	stage_max   = extras_cnt * len;

	stage_val_type = STAGE_VAL_NONE;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len; i++) {

		u32 last_len = 0;

		stage_cur_byte = i;

		/* Extras are sorted by size, from smallest to largest. This means
		that we don't have to worry about restoring the buffer in
		between writes at a particular offset determined by the outer
		loop. */

		for (j = 0; j < extras_cnt; j++) {

		/* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
			skip them if there's no room to insert the payload, if the token
			is redundant, or if its entire span has no bytes set in the effector
			map. */

		if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
			extras[j].len > len - i ||
			!memcmp(extras[j].data, out_buf + i, extras[j].len) ||
			!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

			stage_max--;
			continue;

		}

		last_len = extras[j].len;
		memcpy(out_buf + i, extras[j].data, last_len);

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		stage_cur++;

		}

		/* Restore all the clobbered memory. */
		memcpy(out_buf + i, in_buf + i, last_len);

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_EXTRAS_UO] += stage_max;

	/* Insertion of user-supplied extras. */

	stage_name  = "user extras (insert)";
	stage_short = "ext_UI";
	stage_cur   = 0;
	stage_max   = extras_cnt * len;

	orig_hit_cnt = new_hit_cnt;

	ex_tmp = ck_alloc(len + MAX_DICT_FILE);

	for (i = 0; i <= len; i++) {

		stage_cur_byte = i;

		for (j = 0; j < extras_cnt; j++) {

		if (len + extras[j].len > MAX_FILE) {
			stage_max--; 
			continue;
		}

		/* Insert token */
		memcpy(ex_tmp + i, extras[j].data, extras[j].len);

		/* Copy tail */
		memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

		if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
			ck_free(ex_tmp);
			goto abandon_entry;
		}

		stage_cur++;

		}

		/* Copy head */
		ex_tmp[i] = out_buf[i];

	}

	ck_free(ex_tmp);

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_EXTRAS_UI] += stage_max;

	skip_user_extras:

	if (!a_extras_cnt) goto skip_extras;

	stage_name  = "auto extras (over)";
	stage_short = "ext_AO";
	stage_cur   = 0;
	stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

	stage_val_type = STAGE_VAL_NONE;

	orig_hit_cnt = new_hit_cnt;

	for (i = 0; i < len; i++) {

		u32 last_len = 0;

		stage_cur_byte = i;

		for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

		/* See the comment in the earlier code; extras are sorted by size. */

		if (a_extras[j].len > len - i ||
			!memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
			!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

			stage_max--;
			continue;

		}

		last_len = a_extras[j].len;
		memcpy(out_buf + i, a_extras[j].data, last_len);

		if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

		stage_cur++;

		}

		/* Restore all the clobbered memory. */
		memcpy(out_buf + i, in_buf + i, last_len);

	}

	new_hit_cnt = queued_paths + unique_crashes;

	stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
	stage_cycles[STAGE_EXTRAS_AO] += stage_max;

	skip_extras:

	/* If we made this to here without jumping to havoc_stage or abandon_entry,
		we're properly done with deterministic steps and can mark it as such
		in the .state/ directory. */

	if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

	/****************
	* RANDOM HAVOC *
	****************/

	havoc_stage:

	stage_cur_byte = -1;

	/* The havoc stage mutation code is also invoked when splicing files; if the
		splice_cycle variable is set, generate different descriptions and such. */

	if (!splice_cycle) {

		stage_name  = "havoc";
		stage_short = "havoc";
		stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
					perf_score / havoc_div / 100;

	} else {

		static u8 tmp[32];

		perf_score = orig_perf;

		sprintf(tmp, "splice %u", splice_cycle);
		stage_name  = tmp;
		stage_short = "splice";
		stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

	}

	if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

	temp_len = len;

	orig_hit_cnt = queued_paths + unique_crashes;

	havoc_queued = queued_paths;

	/* We essentially just do several thousand runs (depending on perf_score)
		where we take the input file and make random stacked tweaks. */

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

		stage_cur_val = use_stacking;
	
		for (i = 0; i < use_stacking; i++) {

		switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

			case 0:

			/* Flip a single bit somewhere. Spooky! */

			FLIP_BIT(out_buf, UR(temp_len << 3));
			break;

			case 1: 

			/* Set byte to interesting value. */

			out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
			break;

			case 2:

			/* Set word to interesting value, randomly choosing endian. */

			if (temp_len < 2) break;

			if (UR(2)) {

				*(u16*)(out_buf + UR(temp_len - 1)) =
				interesting_16[UR(sizeof(interesting_16) >> 1)];

			} else {

				*(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
				interesting_16[UR(sizeof(interesting_16) >> 1)]);

			}

			break;

			case 3:

			/* Set dword to interesting value, randomly choosing endian. */

			if (temp_len < 4) break;

			if (UR(2)) {
	
				*(u32*)(out_buf + UR(temp_len - 3)) =
				interesting_32[UR(sizeof(interesting_32) >> 2)];

			} else {

				*(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
				interesting_32[UR(sizeof(interesting_32) >> 2)]);

			}

			break;

			case 4:

			/* Randomly subtract from byte. */

			out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
			break;

			case 5:

			/* Randomly add to byte. */

			out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
			break;

			case 6:

			/* Randomly subtract from word, random endian. */

			if (temp_len < 2) break;

			if (UR(2)) {

				u32 pos = UR(temp_len - 1);

				*(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

			} else {

				u32 pos = UR(temp_len - 1);
				u16 num = 1 + UR(ARITH_MAX);

				*(u16*)(out_buf + pos) =
				SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

			}

			break;

			case 7:

			/* Randomly add to word, random endian. */

			if (temp_len < 2) break;

			if (UR(2)) {

				u32 pos = UR(temp_len - 1);

				*(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

			} else {

				u32 pos = UR(temp_len - 1);
				u16 num = 1 + UR(ARITH_MAX);

				*(u16*)(out_buf + pos) =
				SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

			}

			break;

			case 8:

			/* Randomly subtract from dword, random endian. */

			if (temp_len < 4) break;

			if (UR(2)) {

				u32 pos = UR(temp_len - 3);

				*(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

			} else {

				u32 pos = UR(temp_len - 3);
				u32 num = 1 + UR(ARITH_MAX);

				*(u32*)(out_buf + pos) =
				SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

			}

			break;

			case 9:

			/* Randomly add to dword, random endian. */

			if (temp_len < 4) break;

			if (UR(2)) {

				u32 pos = UR(temp_len - 3);

				*(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

			} else {

				u32 pos = UR(temp_len - 3);
				u32 num = 1 + UR(ARITH_MAX);

				*(u32*)(out_buf + pos) =
				SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

			}

			break;

			case 10:

			/* Just set a random byte to a random value. Because,
				why not. We use XOR with 1-255 to eliminate the
				possibility of a no-op. */

			out_buf[UR(temp_len)] ^= 1 + UR(255);
			break;

			case 11 ... 12: {

				/* Delete bytes. We're making this a bit more likely
				than insertion (the next option) in hopes of keeping
				files reasonably small. */

				u32 del_from, del_len;

				if (temp_len < 2) break;

				/* Don't delete too much. */

				del_len = choose_block_len(temp_len - 1);

				del_from = UR(temp_len - del_len + 1);

				memmove(out_buf + del_from, out_buf + del_from + del_len,
						temp_len - del_from - del_len);

				temp_len -= del_len;

				break;

			}

			case 13:

			if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

				/* Clone bytes (75%) or insert a block of constant bytes (25%). */

				u8  actually_clone = UR(4);
				u32 clone_from, clone_to, clone_len;
				u8* new_buf;

				if (actually_clone) {

				clone_len  = choose_block_len(temp_len);
				clone_from = UR(temp_len - clone_len + 1);

				} else {

				clone_len = choose_block_len(HAVOC_BLK_XL);
				clone_from = 0;

				}

				clone_to   = UR(temp_len);

				new_buf = ck_alloc_nozero(temp_len + clone_len);

				/* Head */

				memcpy(new_buf, out_buf, clone_to);

				/* Inserted part */

				if (actually_clone)
				memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
				else
				memset(new_buf + clone_to,
						UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

				/* Tail */
				memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
					temp_len - clone_to);

				ck_free(out_buf);
				out_buf = new_buf;
				temp_len += clone_len;

			}

			break;

			case 14: {

				/* Overwrite bytes with a randomly selected chunk (75%) or fixed
				bytes (25%). */

				u32 copy_from, copy_to, copy_len;

				if (temp_len < 2) break;

				copy_len  = choose_block_len(temp_len - 1);

				copy_from = UR(temp_len - copy_len + 1);
				copy_to   = UR(temp_len - copy_len + 1);

				if (UR(4)) {

				if (copy_from != copy_to)
					memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

				} else memset(out_buf + copy_to,
							UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

				break;

			}

			/* Values 15 and 16 can be selected only if there are any extras
			present in the dictionaries. */

			case 15: {

				/* Overwrite bytes with an extra. */

				if (!extras_cnt || (a_extras_cnt && UR(2))) {

				/* No user-specified extras or odds in our favor. Let's use an
					auto-detected one. */

				u32 use_extra = UR(a_extras_cnt);
				u32 extra_len = a_extras[use_extra].len;
				u32 insert_at;

				if (extra_len > temp_len) break;

				insert_at = UR(temp_len - extra_len + 1);
				memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

				} else {

				/* No auto extras or odds in our favor. Use the dictionary. */

				u32 use_extra = UR(extras_cnt);
				u32 extra_len = extras[use_extra].len;
				u32 insert_at;

				if (extra_len > temp_len) break;

				insert_at = UR(temp_len - extra_len + 1);
				memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

				}

				break;

			}

			case 16: {

				u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
				u8* new_buf;

				/* Insert an extra. Do the same dice-rolling stuff as for the
				previous case. */

				if (!extras_cnt || (a_extras_cnt && UR(2))) {

				use_extra = UR(a_extras_cnt);
				extra_len = a_extras[use_extra].len;

				if (temp_len + extra_len >= MAX_FILE) break;

				new_buf = ck_alloc_nozero(temp_len + extra_len);

				/* Head */
				memcpy(new_buf, out_buf, insert_at);

				/* Inserted part */
				memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

				} else {

				use_extra = UR(extras_cnt);
				extra_len = extras[use_extra].len;

				if (temp_len + extra_len >= MAX_FILE) break;

				new_buf = ck_alloc_nozero(temp_len + extra_len);

				/* Head */
				memcpy(new_buf, out_buf, insert_at);

				/* Inserted part */
				memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

				}

				/* Tail */
				memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
					temp_len - insert_at);

				ck_free(out_buf);
				out_buf   = new_buf;
				temp_len += extra_len;

				break;

			}

		}

		}

		if (common_fuzz_stuff(argv, out_buf, temp_len))
		goto abandon_entry;

		/* out_buf might have been mangled a bit, so let's restore it to its
		original size and shape. */

		if (temp_len < len) out_buf = ck_realloc(out_buf, len);
		temp_len = len;
		memcpy(out_buf, in_buf, len);

		/* If we're finding new stuff, let's run for a bit longer, limits
		permitting. */

		if (queued_paths != havoc_queued) {

		if (perf_score <= HAVOC_MAX_MULT * 100) {
			stage_max  *= 2;
			perf_score *= 2;
		}

		havoc_queued = queued_paths;

		}

	}

	new_hit_cnt = queued_paths + unique_crashes;

	if (!splice_cycle) {
		stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_HAVOC] += stage_max;
	} else {
		stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_SPLICE] += stage_max;
	}

	#ifndef IGNORE_FINDS

	/************
	* SPLICING *
	************/

	/* This is a last-resort strategy triggered by a full round with no findings.
		It takes the current input file, randomly selects another input, and
		splices them together at some offset, then relies on the havoc
		code to mutate that blob. */

	retry_splicing:

	if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
		queued_paths > 1 && queue_cur->len > 1) {

		struct queue_entry* target;
		u32 tid, split_at;
		u8* new_buf;
		s32 f_diff, l_diff;

		/* First of all, if we've modified in_buf for havoc, let's clean that
		up... */

		if (in_buf != orig_in) {
		ck_free(in_buf);
		in_buf = orig_in;
		len = queue_cur->len;
		}

		/* Pick a random queue entry and seek to it. Don't splice with yourself. */

		do { tid = UR(queued_paths); } while (tid == current_entry);

		splicing_with = tid;
		target = queue;

		while (tid >= 100) { target = target->next_100; tid -= 100; }
		while (tid--) target = target->next;

		/* Make sure that the target has a reasonable length. */

		while (target && (target->len < 2 || target == queue_cur)) {
		target = target->next;
		splicing_with++;
		}

		if (!target) goto retry_splicing;

		/* Read the testcase into a new buffer. */

		fd = open(target->fname, O_RDONLY);

		if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

		new_buf = ck_alloc_nozero(target->len);

		ck_read(fd, new_buf, target->len, target->fname);

		close(fd);

		/* Find a suitable splicing location, somewhere between the first and
		the last differing byte. Bail out if the difference is just a single
		byte or so. */

		locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

		if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
		ck_free(new_buf);
		goto retry_splicing;
		}

		/* Split somewhere between the first and last differing byte. */

		split_at = f_diff + UR(l_diff - f_diff);

		/* Do the thing. */

		len = target->len;
		memcpy(new_buf, in_buf, split_at);
		in_buf = new_buf;

		ck_free(out_buf);
		out_buf = ck_alloc_nozero(len);
		memcpy(out_buf, in_buf, len);

		goto havoc_stage;

	}

	#endif /* !IGNORE_FINDS */

	ret_val = 0;

	abandon_entry:

	splicing_with = -1;

	/* Update pending_not_fuzzed count if we made it through the calibration
		cycle and have not seen this entry before. */

	if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
		queue_cur->was_fuzzed = 1;
		pending_not_fuzzed--;
		if (queue_cur->favored) pending_favored--;
	}

	munmap(orig_in, queue_cur->len);

	if (in_buf != orig_in) ck_free(in_buf);
	ck_free(out_buf);
	ck_free(eff_map);

	return ret_val;

	#undef FLIP_BIT

	}
### 2.2.1 calculate_score only useful for havoc
	/* Calculate case desirability score to adjust the length of havoc fuzzing. //liu 
	A helper function for fuzz_one(). Maybe some of these constants should
	go into config.h. */

	static u32 calculate_score(struct queue_entry* q) {

	u32 avg_exec_us = total_cal_us / total_cal_cycles;
	u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
	u32 perf_score = 100;

	/* Adjust score based on execution speed of this path, compared to the
		global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
		less expensive to fuzz, so we're giving them more air time. */

	if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
	else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
	else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
	else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
	else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
	else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
	else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

	/* Adjust score based on bitmap size. The working theory is that better
		coverage translates to better targets. Multiplier from 0.25x to 3x. */

	if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
	else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
	else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
	else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
	else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
	else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

	/* Adjust score based on handicap. Handicap is proportional to how late
		in the game we learned about this path. Latecomers are allowed to run
		for a bit longer until they catch up with the rest. */

	if (q->handicap >= 4) {

		perf_score *= 4;
		q->handicap -= 4;

	} else if (q->handicap) {

		perf_score *= 2;
		q->handicap--;

	}

	/* Final adjustment based on input depth, under the assumption that fuzzing
		deeper test cases is more likely to reveal stuff that can't be
		discovered with traditional fuzzers. */

	switch (q->depth) {

		case 0 ... 3:   break;
		case 4 ... 7:   perf_score *= 2; break;
		case 8 ... 13:  perf_score *= 3; break;
		case 14 ... 25: perf_score *= 4; break;
		default:        perf_score *= 5;

	}

	/* Make sure that we don't go over limit. */

	if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

	return perf_score;

	}
### 2.2.2 common_fuzz_stuff
	/* Write a modified test case, run program, process results. Handle
	error conditions, returning 1 if it's time to bail out. This is
	a helper function for fuzz_one(). */

	EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

	u8 fault;

	if (post_handler) {

		out_buf = post_handler(out_buf, &len);
		if (!out_buf || !len) return 0;

	}

	write_to_testcase(out_buf, len);//liu call write_to_testcase

	fault = run_target(argv, exec_tmout);//liu call run_target

	if (stop_soon) return 1;

	if (fault == FAULT_TMOUT) {

		if (subseq_tmouts++ > TMOUT_LIMIT) {
		cur_skipped_paths++;
		return 1;
		}

	} else subseq_tmouts = 0;

	/* Users can hit us with SIGUSR1 to request the current input
		to be abandoned. */

	if (skip_requested) {

		skip_requested = 0;
		cur_skipped_paths++;
		return 1;

	}

	/* This handles FAULT_ERROR for us: */

	queued_discovered += save_if_interesting(argv, out_buf, len, fault);//liu call save_if_interesting

	if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
		show_stats();

	return 0;

	}
#### 2.2.2.1 write_to_testcase
	/* Write modified data to file for testing. If out_file is set, the old file
	is unlinked and a new one is created. Otherwise, out_fd is rewound and
	truncated. */

	static void write_to_testcase(void* mem, u32 len) {

	s32 fd = out_fd;

	if (out_file) {

		unlink(out_file); /* Ignore errors. */

		fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

		if (fd < 0) PFATAL("Unable to create '%s'", out_file);

	} else lseek(fd, 0, SEEK_SET);

	ck_write(fd, mem, len, out_file);//liu write

	if (!out_file) {

		if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
		lseek(fd, 0, SEEK_SET);

	} else close(fd);

	}
##### 2.2.2.1.1 out_file initial
	/* Detect @@ in args. */

	EXP_ST void detect_file_args(char** argv) {

	u32 i = 0;
	u8* cwd = getcwd(NULL, 0);

	if (!cwd) PFATAL("getcwd() failed");

	while (argv[i]) {

		u8* aa_loc = strstr(argv[i], "@@");

		if (aa_loc) {

		u8 *aa_subst, *n_arg;

		/* If we don't have a file name chosen yet, use a safe default. */

		if (!out_file)
			out_file = alloc_printf("%s/.cur_input", out_dir);//liu out_file

		/* Be sure that we're always using fully-qualified paths. */

		if (out_file[0] == '/') aa_subst = out_file;
		else aa_subst = alloc_printf("%s/%s", cwd, out_file);

		/* Construct a replacement argv value. */

		*aa_loc = 0;
		n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
		argv[i] = n_arg;
		*aa_loc = '@';

		if (out_file[0] != '/') ck_free(aa_subst);

		}

		i++;

	}

	free(cwd); /* not tracked */

	}
##### 2.2.2.1.2 out_dir initial
	case 'o': /* output dir */

			if (out_dir) FATAL("Multiple -o options not supported");
			out_dir = optarg;
			break;
#### 2.2.2.2 run_target
	/* Execute target application, monitoring for timeouts. Return status
	information. The called program will update trace_bits[]. */

	static u8 run_target(char** argv, u32 timeout) {

	static struct itimerval it;
	static u32 prev_timed_out = 0;

	int status = 0;
	u32 tb4;

	child_timed_out = 0;

	/* After this memset, trace_bits[] are effectively volatile, so we
		must prevent any earlier operations from venturing into that
		territory. */

	memset(trace_bits, 0, MAP_SIZE);//liu clear the trace_bits before running
	MEM_BARRIER();

	/* If we're running in "dumb" mode, we can't rely on the fork server
		logic compiled into the target program, so we will just keep calling
		execve(). There is a bit of code duplication between here and 
		init_forkserver(), but c'est la vie. */

	if (dumb_mode == 1 || no_forkserver) {

		child_pid = fork();

		if (child_pid < 0) PFATAL("fork() failed");

		if (!child_pid) {

		struct rlimit r;

		if (mem_limit) {

			r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

	#ifdef RLIMIT_AS

			setrlimit(RLIMIT_AS, &r); /* Ignore errors */

	#else

			setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

	#endif /* ^RLIMIT_AS */

		}

		r.rlim_max = r.rlim_cur = 0;

		setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

		/* Isolate the process and configure standard descriptors. If out_file is
			specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

		setsid();

		dup2(dev_null_fd, 1);
		dup2(dev_null_fd, 2);

		if (out_file) {

			dup2(dev_null_fd, 0);

		} else {

			dup2(out_fd, 0);
			close(out_fd);

		}

		/* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

		close(dev_null_fd);
		close(out_dir_fd);
		close(dev_urandom_fd);
		close(fileno(plot_file));

		/* Set sane defaults for ASAN if nothing else specified. */

		setenv("ASAN_OPTIONS", "abort_on_error=1:"
								"detect_leaks=0:"
								"symbolize=0:"
								"allocator_may_return_null=1", 0);

		setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
								"symbolize=0:"
								"msan_track_origins=0", 0);

		execv(target_path, argv);

		/* Use a distinctive bitmap value to tell the parent about execv()
			falling through. */

		*(u32*)trace_bits = EXEC_FAIL_SIG;
		exit(0);

		}

	} else {

		s32 res;

		/* In non-dumb mode, we have the fork server up and running, so simply
		tell it to have at it, and then read back PID. */

		if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {//liu start see 1.1.3 

		if (stop_soon) return 0;
		RPFATAL(res, "Unable to request new process from fork server (OOM?)");

		}

		if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {//liu get child_pid

		if (stop_soon) return 0;
		RPFATAL(res, "Unable to request new process from fork server (OOM?)");

		}

		if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

	}

	/* Configure timeout, as requested by user, then wait for child to terminate. */

	it.it_value.tv_sec = (timeout / 1000);
	it.it_value.tv_usec = (timeout % 1000) * 1000;

	setitimer(ITIMER_REAL, &it, NULL);//liu set timeout timer

	/* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

	if (dumb_mode == 1 || no_forkserver) {

		if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

	} else {

		s32 res;

		if ((res = read(fsrv_st_fd, &status, 4)) != 4) {//liu read exit_code

		if (stop_soon) return 0;
		RPFATAL(res, "Unable to communicate with fork server (OOM?)");

		}

	}

	if (!WIFSTOPPED(status)) child_pid = 0;

	it.it_value.tv_sec = 0;
	it.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &it, NULL);

	total_execs++;

	/* Any subsequent operations on trace_bits must not be moved by the
		compiler below this point. Past this location, trace_bits[] behave
		very normally and do not have to be treated as volatile. */

	MEM_BARRIER();

	tb4 = *(u32*)trace_bits;//liu get trace_bit for this run

	#ifdef __x86_64__
	classify_counts((u64*)trace_bits);
	#else
	classify_counts((u32*)trace_bits);
	#endif /* ^__x86_64__ */

	prev_timed_out = child_timed_out;

	/* Report outcome to caller. */
	//liu 6/18
	//if (child_timed_out) return FAULT_TMOUT;
	if (child_timed_out) return FAULT_NONE;
	if (WIFSIGNALED(status) && !stop_soon) {
		kill_signal = WTERMSIG(status);
		return FAULT_CRASH; //liu crash signal
	}

	/* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
		must use a special exit code. */

	if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
		kill_signal = 0;
		return FAULT_CRASH;
	}

	if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
		return FAULT_ERROR;

	return FAULT_NONE;

	}
#### 2.2.2.3 save_if_interesting
	//liu queued_discovered += save_if_interesting(argv, out_buf, len, fault);
	/* Check if the result of an execve() during routine fuzzing is interesting,
	save or queue the input test case for further analysis if so. Returns 1 if
	entry is saved, 0 otherwise. */

	static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {

	u8  *fn = "";
	u8  hnb;
	s32 fd;
	u8  keeping = 0, res;

	if (fault == crash_mode) {

		/* Keep only if there are new bits in the map, add to queue for
		future fuzzing, etc. */

		if (!(hnb = has_new_bits(virgin_bits))) {
		if (crash_mode) total_crashes++;
		return 0;
		}    

	#ifndef SIMPLE_FILES

		fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
						describe_op(hnb));

	#else

		fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

	#endif /* ^!SIMPLE_FILES */

		add_to_queue(fn, len, 0);//liu call add_to_queue

		if (hnb == 2) {
		queue_top->has_new_cov = 1;
		queued_with_cov++;
		}

		queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

		/* Try to calibrate inline; this also calls update_bitmap_score() when
		successful. */

		res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);//liu call calibrate_case

		if (res == FAULT_ERROR)
		FATAL("Unable to execute target application");

		fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (fd < 0) PFATAL("Unable to create '%s'", fn);
		ck_write(fd, mem, len, fn);
		close(fd);

		keeping = 1;

	}

	switch (fault) {

		case FAULT_TMOUT:

		/* Timeouts are not very interesting, but we're still obliged to keep
			a handful of samples. We use the presence of new bits in the
			hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
			just keep everything. */

		total_tmouts++;

		if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

		if (!dumb_mode) {

	#ifdef __x86_64__
			simplify_trace((u64*)trace_bits);
	#else
			simplify_trace((u32*)trace_bits);
	#endif /* ^__x86_64__ */

			if (!has_new_bits(virgin_tmout)) return keeping;

		}

		unique_tmouts++;

		/* Before saving, we make sure that it's a genuine hang by re-running
			the target with a more generous timeout (unless the default timeout
			is already generous). */

		if (exec_tmout < hang_tmout) {

			u8 new_fault;
			write_to_testcase(mem, len);
			new_fault = run_target(argv, hang_tmout);

			if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

		}

	#ifndef SIMPLE_FILES

		fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
							unique_hangs, describe_op(0));

	#else

		fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
							unique_hangs);

	#endif /* ^!SIMPLE_FILES */

		unique_hangs++;

		last_hang_time = get_cur_time();

		break;

		case FAULT_CRASH:

		/* This is handled in a manner roughly similar to timeouts,
			except for slightly different limits and no need to re-run test
			cases. */

		total_crashes++;

		if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

		if (!dumb_mode) {

	#ifdef __x86_64__
			simplify_trace((u64*)trace_bits);
	#else
			simplify_trace((u32*)trace_bits);
	#endif /* ^__x86_64__ */

			if (!has_new_bits(virgin_crash)) return keeping;

		}

		if (!unique_crashes) write_crash_readme();

	#ifndef SIMPLE_FILES

		fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
							unique_crashes, kill_signal, describe_op(0));

	#else

		fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
							kill_signal);

	#endif /* ^!SIMPLE_FILES */

		unique_crashes++;

		last_crash_time = get_cur_time();
		last_crash_execs = total_execs;

		break;

		case FAULT_ERROR: FATAL("Unable to execute target application");

		default: return keeping;

	}

	/* If we're here, we apparently want to save the crash or hang
		test case, too. */

	fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) PFATAL("Unable to create '%s'", fn);
	ck_write(fd, mem, len, fn);
	close(fd);

	ck_free(fn);

	return keeping;

	}
##### 2.2.2.3.1 has_new_bits(virgin_bits)
	/* Check if the current execution path brings anything new to the table.
	Update virgin bits to reflect the finds. Returns 1 if the only change is
	the hit-count for a particular tuple; 2 if there are new tuples seen. 
	Updates the map, so subsequent calls will always return 0.

	This function is called after every exec() on a fairly large buffer, so
	it needs to be fast. We do this in 32-bit and 64-bit flavors. */

	static inline u8 has_new_bits(u8* virgin_map) {

	#ifdef __x86_64__

	u64* current = (u64*)trace_bits;
	u64* virgin  = (u64*)virgin_map;

	u32  i = (MAP_SIZE >> 3);

	#else

	u32* current = (u32*)trace_bits;
	u32* virgin  = (u32*)virgin_map;

	u32  i = (MAP_SIZE >> 2);

	#endif /* ^__x86_64__ */

	u8   ret = 0;

	while (i--) {

		/* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
		that have not been already cleared from the virgin map - since this will
		almost always be the case. */
		//liu trace_bits is initially 0 at every run, each byte indicates the hit count.
		//liu virgin_bits is initially to 0xff, and it is accumulative at each run.
		if (unlikely(*current) && unlikely(*current & *virgin)) {

		if (likely(ret < 2)) {

			u8* cur = (u8*)current;
			u8* vir = (u8*)virgin;

			/* Looks like we have not found any new bytes yet; see if any non-zero
			bytes in current[] are pristine in virgin[]. */

	#ifdef __x86_64__

			if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
				(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
				(cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
				(cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
			else ret = 1;

	#else

			if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
				(cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
			else ret = 1;

	#endif /* ^__x86_64__ */

		}

		*virgin &= ~*current; //liu update virgin_bits accumulatively

		}

		current++;
		virgin++;

	}

	if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

	return ret;

	}
##### 2.2.2.3.2 virgin_bits initial in read_bitmap
	/* Read bitmap from file. This is for the -B option again. */

	EXP_ST void read_bitmap(u8* fname) {

	s32 fd = open(fname, O_RDONLY);

	if (fd < 0) PFATAL("Unable to open '%s'", fname);

	ck_read(fd, virgin_bits, MAP_SIZE, fname);

	close(fd);

	}
##### 2.2.2.3.3 caller of read_bitmap
	case 'B': /* load bitmap */

	/* This is a secret undocumented option! It is useful if you find
		an interesting test case during a normal fuzzing process, and want
		to mutate it without rediscovering any of the test cases already
		found during an earlier run.

		To use this mode, you need to point -B to the fuzz_bitmap produced
		by an earlier run for the exact same binary... and that's it.

		I only used this once or twice to get variants of a particular
		file, so I'm not making this an official setting. */

	if (in_bitmap) FATAL("Multiple -B options not supported");

	in_bitmap = optarg;
	read_bitmap(in_bitmap);
	break;
##### 2.2.2.3.4 setup_shm if not call read_bitmap virgin_bits initial
	/* Configure shared memory and virgin_bits. This is called at startup. */

	EXP_ST void setup_shm(void) {

	u8* shm_str;

	if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);//liu virgin_bits initial to 0xff

	memset(virgin_tmout, 255, MAP_SIZE);
	memset(virgin_crash, 255, MAP_SIZE);

	shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

	if (shm_id < 0) PFATAL("shmget() failed");

	atexit(remove_shm);

	shm_str = alloc_printf("%d", shm_id);

	/* If somebody is asking us to fuzz instrumented binaries in dumb mode,
		we don't want them to detect instrumentation, since we won't be sending
		fork server commands. This should be replaced with better auto-detection
		later on, perhaps? */

	if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

	ck_free(shm_str);

	trace_bits = shmat(shm_id, NULL, 0);
	//liu When a new shared memory segment is created, its contents are ini‐tialized to zero values
	
	if (!trace_bits) PFATAL("shmat() failed");

	}
##### 2.2.2.3.5 add_to_queue
	//add_to_queue(fn, len, 0);
	/* Append new test case to the queue. */

	static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

	struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

	q->fname        = fname;
	q->len          = len;
	q->depth        = cur_depth + 1;
	q->passed_det   = passed_det;

	if (q->depth > max_depth) max_depth = q->depth;

	if (queue_top) {

		queue_top->next = q;//liu insert to the top
		queue_top = q;

	} else q_prev100 = queue = queue_top = q;

	queued_paths++;
	pending_not_fuzzed++;

	cycles_wo_finds = 0;

	if (!(queued_paths % 100)) {

		q_prev100->next_100 = q;
		q_prev100 = q;

	}

	last_path_time = get_cur_time();

	}
##### 2.2.2.3.6 calibrate_case
	//res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);
	/* Calibrate a new test case. This is done when processing the input directory
	to warn about flaky or otherwise problematic test cases early on; and when
	new paths are discovered to detect variable behavior and so on. */

	static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
							u32 handicap, u8 from_queue) {

	static u8 first_trace[MAP_SIZE];

	u8  fault = 0, new_bits = 0, var_detected = 0,
		first_run = (q->exec_cksum == 0);

	u64 start_us, stop_us;

	s32 old_sc = stage_cur, old_sm = stage_max;
	u32 use_tmout = exec_tmout;
	u8* old_sn = stage_name;

	/* Be a bit more generous about timeouts when resuming sessions, or when
		trying to calibrate already-added finds. This helps avoid trouble due
		to intermittent latency. */

	if (!from_queue || resuming_fuzz)
		use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
						exec_tmout * CAL_TMOUT_PERC / 100);

	q->cal_failed++;

	stage_name = "calibration";
	stage_max  = CAL_CYCLES;

	/* Make sure the forkserver is up before we do anything, and let's not
		count its spin-up time toward binary calibration. */

	if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
		init_forkserver(argv);

	if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);

	start_us = get_cur_time_us();

	for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

		u32 cksum;

		if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

		write_to_testcase(use_mem, q->len);

		fault = run_target(argv, use_tmout);

		/* stop_soon is set by the handler for Ctrl+C. When it's pressed,
		we want to bail out quickly. */

		if (stop_soon || fault != crash_mode) goto abort_calibration;

		if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
		fault = FAULT_NOINST;
		goto abort_calibration;
		}

		cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

		if (q->exec_cksum != cksum) {

		u8 hnb = has_new_bits(virgin_bits);
		if (hnb > new_bits) new_bits = hnb;

		if (q->exec_cksum) {

			u32 i;

			for (i = 0; i < MAP_SIZE; i++) {

			if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

				var_bytes[i] = 1;
				stage_max    = CAL_CYCLES_LONG;

			}

			}

			var_detected = 1;

		} else {

			q->exec_cksum = cksum;
			memcpy(first_trace, trace_bits, MAP_SIZE);

		}

		}

	}

	stop_us = get_cur_time_us();

	total_cal_us     += stop_us - start_us;
	total_cal_cycles += stage_max;

	/* OK, let's collect some stats about the performance of this test case.
		This is used for fuzzing air time calculations in calculate_score(). */

	q->exec_us     = (stop_us - start_us) / stage_max;
	q->bitmap_size = count_bytes(trace_bits); //liu update bitmap_size
	q->handicap    = handicap;
	q->cal_failed  = 0;

	total_bitmap_size += q->bitmap_size;
	total_bitmap_entries++;

	update_bitmap_score(q);// liu call update_bitmap_score

	/* If this case didn't result in new output from the instrumentation, tell
		parent. This is a non-critical problem, but something to warn the user
		about. */

	if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

	abort_calibration:

	if (new_bits == 2 && !q->has_new_cov) {
		q->has_new_cov = 1;
		queued_with_cov++;
	}

	/* Mark variable paths. */

	if (var_detected) {

		var_byte_count = count_bytes(var_bytes);

		if (!q->var_behavior) {
		mark_as_variable(q);
		queued_variable++;
		}

	}

	stage_name = old_sn;
	stage_cur  = old_sc;
	stage_max  = old_sm;

	if (!first_run) show_stats();

	return fault;

	}
###### 2.2.2.3.6.1 update_bitmap_score
	/* When we bump into a new path, we call this to see if the path appears
	more "favorable" than any of the existing ones. The purpose of the
	"favorables" is to have a minimal set of paths that trigger all the bits
	seen in the bitmap so far, and focus on fuzzing them at the expense of
	the rest.

	The first step of the process is to maintain a list of top_rated[] entries
	for every byte in the bitmap. We win that slot if there is no previous
	contender, or if the contender has a more favorable speed x size factor. */

	static void update_bitmap_score(struct queue_entry* q) {

	u32 i;
	u64 fav_factor = q->exec_us * q->len;

	/* For every byte set in trace_bits[], see if there is a previous winner,
		and how it compares to us. */

	for (i = 0; i < MAP_SIZE; i++)

		if (trace_bits[i]) { //liu each edge corresponds to a queue_entry logged in top_rated[i]

		if (top_rated[i]) {

			/* Faster-executing or smaller test cases are favored. */

			if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

			/* Looks like we're going to win. Decrease ref count for the
				previous winner, discard its trace_bits[] if necessary. */

			if (!--top_rated[i]->tc_ref) {
			ck_free(top_rated[i]->trace_mini);
			top_rated[i]->trace_mini = 0;
			}

		}

		/* Insert ourselves as the new winner. */

		top_rated[i] = q;
		q->tc_ref++;

		if (!q->trace_mini) {
			q->trace_mini = ck_alloc(MAP_SIZE >> 3);
			minimize_bits(q->trace_mini, trace_bits);
		}

		score_changed = 1;

		}

	}
## 2.3 favored
### 2.3.1 cull_queue
	/* The second part of the mechanism discussed above is a routine that
	goes over top_rated[] entries, and then sequentially grabs winners for
	previously-unseen bytes (temp_v) and marks them as favored, at least
	until the next run. The favored entries are given more air time during
	all fuzzing steps. */

	static void cull_queue(void) {

	struct queue_entry* q;
	static u8 temp_v[MAP_SIZE >> 3];
	u32 i;

	if (dumb_mode || !score_changed) return;

	score_changed = 0;

	memset(temp_v, 255, MAP_SIZE >> 3);

	queued_favored  = 0;
	pending_favored = 0;

	q = queue;

	while (q) {
		q->favored = 0;
		q = q->next;
	}

	/* Let's see if anything in the bitmap isn't captured in temp_v.
		If yes, and if it has a top_rated[] contender, let's use it. */

	for (i = 0; i < MAP_SIZE; i++)
		if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

		u32 j = MAP_SIZE >> 3;

		/* Remove all bits belonging to the current entry from temp_v. */

		while (j--) 
			if (top_rated[i]->trace_mini[j])
			temp_v[j] &= ~top_rated[i]->trace_mini[j];

		top_rated[i]->favored = 1;//liu update the top_rated and assign the favored to the queue_entry
		queued_favored++;

		if (!top_rated[i]->was_fuzzed) pending_favored++;

		}

	q = queue;

	while (q) {
		mark_as_redundant(q, !q->favored);
		q = q->next;
	}

	}
### 2.3.2 update_bitmap_score
	/* When we bump into a new path, we call this to see if the path appears
	more "favorable" than any of the existing ones. The purpose of the
	"favorables" is to have a minimal set of paths that trigger all the bits
	seen in the bitmap so far, and focus on fuzzing them at the expense of
	the rest.

	The first step of the process is to maintain a list of top_rated[] entries
	for every byte in the bitmap. We win that slot if there is no previous
	contender, or if the contender has a more favorable speed x size factor. */

	static void update_bitmap_score(struct queue_entry* q) {

	u32 i;
	u64 fav_factor = q->exec_us * q->len;

	/* For every byte set in trace_bits[], see if there is a previous winner,
		and how it compares to us. */

	for (i = 0; i < MAP_SIZE; i++)

		if (trace_bits[i]) {

		if (top_rated[i]) {

			/* Faster-executing or smaller test cases are favored. */

			if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

			/* Looks like we're going to win. Decrease ref count for the
				previous winner, discard its trace_bits[] if necessary. */

			if (!--top_rated[i]->tc_ref) {
			ck_free(top_rated[i]->trace_mini);
			top_rated[i]->trace_mini = 0;
			}

		}

		/* Insert ourselves as the new winner. */

		top_rated[i] = q;
		q->tc_ref++;

		if (!q->trace_mini) {
			q->trace_mini = ck_alloc(MAP_SIZE >> 3);
			minimize_bits(q->trace_mini, trace_bits);
		}

		score_changed = 1;

		}

	}
#



