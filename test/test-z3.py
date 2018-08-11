from claripy import *

strncmp_ret_21_64 = BVS('strncmp_ret_21_64',32)

file_0_stdin_2_2_8 = BVS('file_0_stdin_2_2_8',32)

file_0_stdin_3_3_8 = BVS('file_0_stdin_3_3_8',32)
strlen_20_64 = BVS('strlen_20_64',32)
file_0_stdin_0_0_8 = BVS('file_0_stdin_0_0_8',32)

file_0_stdin_1_1_8 = BVS('file_0_stdin_1_1_8',32)




s = Solver()
s.add(Not(Not(strncmp_ret_21_64 == 0x1) ))
	#|| !(!(!(0x1 <= strlen_20_64) || (file_0_stdin_1_1_8 == 119)) || (!(!(0x2 <= strlen_20_64) || (file_0_stdin_2_2_8 == 100)) || (!(!(0x3 <= strlen_20_64) || (file_0_stdin_3_3_8 == 10)) || (!(strlen_20_64 == 0x4) || !(file_0_stdin_0_0_8 == 99)))))) 
	#|| !(!(!(0x1 <= strlen_20_64) || (file_0_stdin_1_1_8 == 119)) || (!(!(0x2 <= strlen_20_64) || (file_0_stdin_2_2_8 == 100)) || (!(!(0x3 <= strlen_20_64) || (file_0_stdin_3_3_8 == 10)) || (!(strncmp_ret_21_64 == 0x0) || (!(strlen_20_64 == 0x4) || !(file_0_stdin_0_0_8 == 99)))))))
print s.eval(file_0_stdin_2_2_8,1)[0]