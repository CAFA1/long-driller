import angr

def main():
    p = angr.Project("r100")
    simgr = p.factory.simulation_manager(p.factory.full_init_state())
    simgr.explore(find=0x400844, avoid=0x400855)

    return simgr.found[0].posix.dumps(0).strip('\0\n')

def test():
    assert main().startswith('Code_Talkers')

if __name__ == '__main__':
    print main()
