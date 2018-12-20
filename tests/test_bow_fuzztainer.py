import archr
import time
import os

def setup_module():
    os.system("cd %s/dockers; ./build_all.sh" % os.path.dirname(__file__))

def test_container_stdio():
    with archr.targets.DockerImageTarget('archr-test:crash-on-input').build() as t:
        t.start()
        a = archr.arsenal.AflBow(t)
        r = a.fire()
        r.start_afl()
        time.sleep(20)
        r.proc.terminate()
        crashes = os.path.join(os.path.curdir, r.fuzz_dir, "out", "crashes")
        crash_count = len(os.listdir(crashes))
        os.system("rm -r " + r.fuzz_dir)
        assert(crash_count > 1)

def test_local_stdio():
    with archr.targets.LocalTarget('/bin/true').build() as t:
        t.start()
        a = archr.arsenal.AflBow(t)
        r = a.fire()
        r.start_afl()
        time.sleep(20)
        assert(r.proc.poll() == None)
        r.proc.terminate()
        os.system("rm -r " + r.fuzz_dir)
    
if __name__ == '__main__':
    os.system("echo core > /proc/sys/kernel/core_pattern")
    test_local_stdio()
    test_container_stdio()
