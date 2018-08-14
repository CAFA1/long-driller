import os
import sys
import nose
import logging

import angr
import driller


l = logging.getLogger("driller.driller")


bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))


def test_vul(binary):
    """
    Test drilling on the cgc binary, palindrome.
    """

    #binary = "./vul"

    # fuzzbitmap says every transition is worth satisfying.
    d = driller.Driller(binary, "A"*120, "\xff"*65535, "whatever~")

    new_inputs = d.drill()
    i=0
    for tmp_input in new_inputs:
        print '\ninput '+str(i)+': '+repr(tmp_input)+'\n'
        # log the driller sample into the file(number.input)
        file_tmp=open(str(i)+'.input','w')
        file_tmp.write(tmp_input[1])
        file_tmp.close()
        i=i+1
    #nose.tools.assert_equal(len(new_inputs), 7)

    # Make sure driller produced a new input which hits the easter egg.
    #nose.tools.assert_true(any(filter(lambda x: x[1].startswith('^'), new_inputs)))


def test_simproc_drilling():
    """
    Test drilling on the cgc binary palindrome with simprocedures.
    """

    binary = "tests/i386/driller_simproc"
    memcmp = angr.SIM_PROCEDURES['libc']['memcmp']()
    simprocs = {0x8048200: memcmp}

    # fuzzbitmap says every transition is worth satisfying.
    d = driller.Driller(os.path.join(bin_location, binary), "A"*0x80, "\xff"*65535, "whatever~", hooks=simprocs)

    new_inputs = d.drill()

    # Make sure driller produced a new input which satisfies the memcmp.
    password = "the_secret_password_is_here_you_will_never_guess_it_especially_since_it_is_going_to_be_made_lower_case"
    nose.tools.assert_true(any(filter(lambda x: x[1].startswith(password), new_inputs)))




if __name__ == "__main__":
    l.setLevel('DEBUG')
    binary=sys.argv[1]
    test_vul(binary)
