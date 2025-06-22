#!/usr/bin/env python3

import argparse
import inspect
import json
import os
import re
import signal
import subprocess
import sys
import time
import types

# Add the lib directory to Python path for imports
# LIBDIR is defined by Cython compilation
sys.path.insert(0, LIBDIR)

# Import lib modules
import _clearly as clearly
import _filesystem as filesystem
import _misc as misc


BUNDLE_PREFIX = ["/tmp", "/var/tmp"]
OCI_VERSION_MIN = "1.0.1"    # inclusive
OCI_VERSION_MAX = "1.0.999"  # inclusive

args = None   # CLI Namespace
state = None  # state object


def main():
   global args, state
   clearly.monkey_write_streams()
   args = args_parse()
   clearly.VERBOSE("--- starting ------------------------------------")
   clearly.VERBOSE("args: %s" % sys.argv)
   clearly.VERBOSE("environment: %s" % { k: v for (k, v) in os.environ.items()
                                  if k.startswith("CLEARLY_RUN_OCI_") })
   clearly.VERBOSE("CLI: %s" % args)
   if (args.op.__name__ == "op_" + os.getenv("CLEARLY_RUN_OCI_HANG", default="")):
      clearly.VERBOSE("hanging before %s per CLEARLY_RUN_OCI_HANG" % args.op.__name__)
      sleep_forever()
      assert False, "unreachable code reached"
   state = state_load()
   args.op()
   clearly.VERBOSE("done")


def args_parse():

   ap = argparse.ArgumentParser(description='OCI wrapper for "run".')
   ap.add_argument("-v", "--verbose", action="count", default=0,
                   help="print extra chatter (can be repeated)")
   ap.add_argument("--debug", action="store_true",
                   help="add short traceback to fatal error hints")
   ap.add_argument("--version", action=misc.Version,
                   help="print version and exit")
   sps = ap.add_subparsers()

   sp = sps.add_parser("create")
   sp.set_defaults(op=op_create)
   sp.add_argument("--bundle", required=True, metavar="DIR")
   sp.add_argument("--console-socket", metavar="PATH")
   sp.add_argument("--pid-file", required=True, metavar="FILE")
   sp.add_argument("--no-new-keyring", action="store_true")
   sp.add_argument("cid", metavar="CONTAINER_ID")

   sp = sps.add_parser("delete")
   sp.set_defaults(op=op_delete)
   sp.add_argument("cid", metavar="CONTAINER_ID")

   sp = sps.add_parser("kill")
   sp.set_defaults(op=op_kill)
   sp.add_argument("cid", metavar="CONTAINER_ID")
   sp.add_argument("signal", metavar="SIGNAL")

   sp = sps.add_parser("start")
   sp.set_defaults(op=op_start)
   sp.add_argument("cid", metavar="CONTAINER_ID")

   sp = sps.add_parser("state")
   sp.set_defaults(op=op_state)
   sp.add_argument("cid", metavar="CONTAINER_ID")

   args_ = ap.parse_args()
   args_.arch = "yolo"
   # dummy args to make charliecloud.init() happy
   args_.always_download = None
   args_.auth = None
   args_.func = abs  # needs to have __module__ attribute
   args_.no_cache = None
   args_.no_lock = False
   args_.no_xattrs = False
   args_.password_many = False
   args_.profile = False
   args_.quiet = False
   args_.storage = None
   args_.tls_no_verify = False
   args_.xattrs = False
   clearly.init(args_)

   if len(sys.argv) < 2:
      ap.print_help(file=sys.stderr)
      clearly.exit(1)

   bundle_ = bundle_from_cid(args_.cid)
   if ("bundle" in args_ and args_.bundle != bundle_):
      clearly.FATAL("bundle argument “%s” differs from inferred bundle “%s”"
               % (args_.bundle, bundle_))
   args_.bundle = bundle_

   pid_file_ = pid_file_from_bundle(args_.bundle)
   if ("pid_file" in args_ and args_.pid_file != pid_file_):
      clearly.FATAL("pid_file argument “%s” differs from inferred “%s”"
               % (args_.pid_file, pid_file_))
   args_.pid_file = pid_file_

   return args_

def bundle_from_cid(cid):
   m = re.search(r"^buildah-buildah(.+)$", cid)
   if (m is None):
      clearly.FATAL("cannot parse container ID: %s" % cid)
   paths = []
   for p in BUNDLE_PREFIX:
      paths.append("%s/buildah%s" % (p, m[1]))
      if (os.path.exists(paths[-1])):
         return paths[-1]
   clearly.FATAL("can't infer bundle path; none of these exist: %s"
            % " ".join(paths))

def debug_lines(s):
   for line in s.splitlines():
      clearly.VERBOSE(line)

def image_fixup(path):
   clearly.VERBOSE("fixing up image: %s" % path)
   # Metadata directory.
   filesystem.Path("%s/ch/bin" % path).mkdirs()
   # Mount points.
   filesystem.Path("%s/etc/hosts" % path).file_ensure_exists()
   filesystem.Path("%s/etc/resolv.conf" % path).file_ensure_exists()
   # /etc/{passwd,group}
   filesystem.Path("%s/etc/passwd" % path).file_write("""\
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/bin/false
""")
   filesystem.Path("%s/etc/group" % path).file_write("""\
root:x:0:
nogroup:x:65534:
""")
   # Kludges to work around expectations of real root, not UID 0 in a
   # unprivileged user namespace. See also the default environment.
   #
   # Debian apt/dpkg/etc. want to chown(1), chgrp(1), etc. in various ways.
   filesystem.Path(path, "ch/bin/chgrp").symlink_to("/bin/true")
   filesystem.Path(path, "ch/bin/dpkg-statoverride").symlink_to("/bin/true")
   # Debian package management also wants to mess around with users. This is
   # causing problems with /etc/gshadow and other files. These links don't
   # work if they are in /ch/bin, I think because dpkg is resetting the path?
   # For now we'll do this, but I don't like it. fakeroot(1) also solves the
   # problem (see issue #472).
   filesystem.Path(path, "bin/chown").symlink_to("/bin/true", clobber=True)
   filesystem.Path(path, "usr/sbin/groupadd").symlink_to("/bin/true", clobber=True)
   filesystem.Path(path, "usr/sbin/useradd").symlink_to("/bin/true", clobber=True)
   filesystem.Path(path, "usr/sbin/usermod").symlink_to("/bin/true", clobber=True)
   filesystem.Path(path, "usr/bin/chage").symlink_to("/bin/true", clobber=True)

def op_create():
   # Validate arguments.
   if (args.console_socket):
      clearly.FATAL("--console-socket not supported")

   # Start dummy supervisor.
   if (state.pid is not None):
      clearly.FATAL("container already created")
   pid = clearly.ossafe("can't fork", os.fork)
   if (pid == 0):
      # Child; the only reason to exist is so Buildah sees a process when it
      # looks for one. Sleep until told to exit.
      #
      # Note: I looked into changing the process title and this turns out to
      # be remarkably hairy unless you use a 3rd-party module.
      def exit_(sig, frame):
         clearly.VERBOSE("dummy supervisor: done")
         clearly.exit(0)
      signal.signal(signal.SIGTERM, exit_)
      clearly.VERBOSE("dummy supervisor: starting")
      sleep_forever()
   else:
      state.pid = pid
      with args.pid_file.open("wt") as fp:
         print("%d" % pid, file=fp)
      clearly.VERBOSE("dummy supervisor started with pid %d" % pid)

def op_delete():
   clearly.VERBOSE("delete operation is a no-op")

def op_kill():
   clearly.VERBOSE("kill operation is a no-op")

def op_start():
   # Note: Contrary to the implication of its name, the "start" operation
   # blocks until the user command is done.

   c = state.config

   # Unsupported features to barf about.
   if (state.pid is None):
      clearly.FATAL("can't start: not created yet")
   if (c["process"].get("terminal", False)):
      clearly.FATAL("not supported: pseudoterminals")
   if ("annotations" in c):
      clearly.FATAL("not supported: annotations")
   if ("hooks" in c):
      clearly.FATAL("not supported: hooks")
   for d in c["linux"]["namespaces"]:
      if ("path" in d):
         clearly.FATAL("not supported: joining existing namespaces")
   if ("intelRdt" in c["linux"]):
      clearly.FATAL("not supported: Intel RDT")

   # Environment file. This is a list of lines, not a dict.
   #
   # GNU tar, when it thinks it's running as root, tries to chown(2) and
   # chgrp(2) files to whatever's in the tarball. --no-same-owner avoids this.
   with filesystem.Path(args.bundle + "/environment").open("wt") as fp:
      for line in (  c["process"]["env"]                  # from Dockerfile
                   + [ "TAR_OPTIONS=--no-same-owner" ]):  # ours
         line = re.sub(r"^(PATH=)", "\\1/ch/bin:", line)
         clearly.VERBOSE("env: %s" % line)
         print(line, file=fp)

   # Build command line.
   cmd = LIBEXECDIR + "/run"
   ca = [cmd,
         "--cd", c["process"]["cwd"],
         "--no-passwd",
         "--gid", str(c["process"]["user"]["gid"]),
         "--uid", str(c["process"]["user"]["uid"]),
         "--unset-env=*", "--set-env=%s/environment" % args.bundle]
   if (not c["root"].get("readonly", False)):
      ca.append("--write")
   ca += [c["root"]["path"], "--"]
   ca += c["process"]["args"]

   # Fix up root filesystem.
   image_fixup(args.bundle + "/mnt/rootfs")

   # Execute user command. We can't execv(2) because we have to do cleanup
   # after it exits.
   filesystem.Path(args.bundle + "/user_started").file_ensure_exists()
   clearly.VERBOSE("user command: %s" % ca)
   # Standard output disappears, so send stdout to stderr.
   cp = subprocess.run(ca, stdout=2)
   filesystem.Path(args.bundle + "/user_done").file_ensure_exists()
   clearly.VERBOSE("user command done")

   # Stop dummy supervisor.
   if (state.pid is None):
      clearly.FATAL("no dummy supervisor PID found")
   try:
      os.kill(state.pid, signal.SIGTERM)
      state.pid = None
      os.unlink(args.pid_file)
   except OSError as x:
      clearly.FATAL("can't kill PID %d: %s (%d)" % (state.pid, x.strerror, x.errno))

   # Puke if user command failed.
   if (cp.returncode != 0):
      clearly.FATAL("user command failed: %d" % cp.returncode)

def op_state():
   def status():
      if (state.user_command_started):
         if (state.user_command_done):
            return "stopped"
         else:
            return "running"
      if (state.pid is None):
         return "creating"
      else:
         return "created"
   st = { "ociVersion": OCI_VERSION_MAX,
          "id": args.cid,
          "status": status(),
          "bundle": args.bundle }
   if (state.pid is not None):
      st["pid"] = state.pid
   out = json.dumps(st, indent=2)
   debug_lines(out)
   print(out)

def sleep_forever():
   while True:
      time.sleep(60)  # can't provide infinity here

def pid_file_from_bundle(bundle):
   return bundle + "/pid"

def state_load():
   st = types.SimpleNamespace()

   st.config = filesystem.Path(args.bundle, "config.json").json_from_file("state")
   #debug_lines(json.dumps(st.config, indent=2))

   v_min = version_parse_oci(OCI_VERSION_MIN)
   v_actual = version_parse_oci(st.config["ociVersion"])
   v_max = version_parse_oci(OCI_VERSION_MAX)
   if (not v_min <= v_actual <= v_max):
      clearly.FATAL("unsupported OCI version: %s" % st.config["ociVersion"])

   try:
      fp = open(args.pid_file, "rt")
      st.pid = int(clearly.ossafe("can't read: %s" % args.pid_file, fp.read))
      clearly.VERBOSE("found supervisor pid: %d" % st.pid)
   except FileNotFoundError:
      st.pid = None
      clearly.VERBOSE("no supervisor pid found")

   st.user_command_started = os.path.isfile(args.bundle + "/user_started")
   st.user_command_done = os.path.isfile(args.bundle + "/user_done")

   return st

def version_parse_oci(s):
   # Dead-simple version parsing for OCI; not intended for other uses.
   return tuple(re.split(r"[.-]", s)[:3])


if (__name__ == "__main__"):
   try:
      main()
   except clearly.Fatal_Error as x:
      clearly.ERROR(*x.args, **x.kwargs)
      clearly.exit(1)
