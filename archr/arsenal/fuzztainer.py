from . import Bow
import fuzztainer as f
import os
from subprocess import Popen

class AflBow(Bow):
    """
    Returns a Runnable AFL instance connected to the target
    """

    def __init__(self, target):
        super(AflBow, self).__init__(target)

        # set a sane default
        self.fuzzdir = os.path.join(os.curdir, "fuzz")

        self.target.mount_local()
        self.runner = None

    def fire(self): #pylint:disable=arguments-differ
        """
        Returns an AFLRunner instance
        """

        # THIS IS BAD
        if hasattr(self.target, "container"):
            ft_path = "/"
        else:
            ft_path = "/tmp/"
        
        self.target.inject_path(f.get_lib_path(), ft_path)
        self.target.inject_path(f.get_qemu_path(), ft_path) 

        try:
            self.runner = f.AFL_runner(self.target.target_args, container=self.target.container)
        except:
            self.runner = f.AFL_runner(self.target.target_args)
        return self.runner

    def set_fuzz_dir(new_fuzz):
        if os.path.exists(new_fuzz):
            self.fuzzdir = new_fuzz 
        else:
            print(new_fuzz + " not found")
