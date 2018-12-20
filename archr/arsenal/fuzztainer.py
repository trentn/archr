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
        self.target.mount_local()
        self.runner = None

    def fire(self): #pylint:disable=arguments-differ
        """
        Returns an AFLRunner instance
        """

        # TODO: resolve container vs local inject_path
        if hasattr(self.target, "container"):
            ft_path = "/"
            self.target.inject_path(f.get_qemu_path(), ft_path) 
            self.runner = f.AFL_runner(self.target.target_args, 
                                       container=self.target.container)
        else:
            self.runner = f.AFL_runner(self.target.target_args)

        return self.runner
