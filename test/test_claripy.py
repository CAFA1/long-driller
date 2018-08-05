import claripy
s = claripy.Solver()
x = claripy.BVS('x', 8)
y = claripy.BVV(65, 8)
z = claripy.If(x == 1, x, y)
s.add(claripy.ULT(x, 5))
s.add(z % 5 != 0)
print s.eval(z, 10)