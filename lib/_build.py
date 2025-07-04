# Implementation of "clearly image build".

import os
import os.path
import re
import sys

import _clearly as _clearly
import _filesystem as _filesystem
import _grammar as _grammar
import _irtree as _irtree
import _force as _force
from _tree import Tree
import lark

## Main ##

def main(cli):
   _irtree.cli = cli

   cli_process_common(cli)

   # Process CLI. Make appropriate modifications to “cli” instance and return
   # Dockerfile text.
   text = cli_process(cli)

   tree = parse_dockerfile(text, cli)

   # Count the number of stages (i.e., FROM instructions)
   image_ct = sum(1 for i in tree.children_("from_"))

   _irtree.parse_tree_traverse(tree, image_ct, cli)

## Functions ##

# Function that processes parsed CLI, modifying the passed “cli” object
# appropriatley as it does. Returns the text of the file used for the build
# operation. Note that Python passes variables to functions by their object
# reference, so changes made to mutable objects (which “cli” is) will persist in
# the scope of the caller.'
def cli_process(cli):
   # Infer input file if needed.
   if (cli.file is None):
      cli.file = cli.context + "/Dockerfile"

   # Infer image name if needed.
   if (cli.tag is None):
      path = os.path.basename(cli.file)
      if ("." in path):
         (base, ext_all) = str(path).split(".", maxsplit=1)
         (base_all, ext_last) = str(path).rsplit(".", maxsplit=1)
      else:
         base = None
         ext_last = None
      if (base == "Dockerfile"):
         cli.tag = ext_all
         _clearly.VERBOSE("inferring name from Dockerfile extension: %s" % cli.tag)
      elif (ext_last in ("df", "dockerfile")):
         cli.tag = base_all
         _clearly.VERBOSE("inferring name from Dockerfile basename: %s" % cli.tag)
      elif (os.path.abspath(cli.context) != "/"):
         cli.tag = os.path.basename(os.path.abspath(cli.context))
         _clearly.VERBOSE("inferring name from context directory: %s" % cli.tag)
      else:
         assert (os.path.abspath(cli.context) == "/")
         cli.tag = "root"
         _clearly.VERBOSE("inferring name with root context directory: %s" % cli.tag)
      cli.tag = re.sub(r"[^a-z0-9_.-]", "", cli.tag.lower())
      _clearly.INFO("inferred image name: %s" % cli.tag)


   _clearly.DEBUG(cli)

   # Guess whether the context is a URL, and error out if so. This can be a
   # typical looking URL e.g. “https://...” or also something like
   # “git@github.com:...”. The line noise in the second line of the regex is
   # to match this second form. Username and host characters from
   # https://tools.ietf.org/html/rfc3986.
   if (re.search(r"""  ^((git|git+ssh|http|https|ssh)://
                     | ^[\w.~%!$&'\(\)\*\+,;=-]+@[\w.~%!$&'\(\)\*\+,;=-]+:)""",
                 cli.context, re.VERBOSE) is not None):
      _clearly.FATAL("not yet supported: issue #773: URL context: %s" % cli.context)
   if (os.path.exists(cli.context + "/.dockerignore")):
      _clearly.WARNING("not yet supported, ignored: issue #777: .dockerignore file")

   # Read input file.
   if (cli.file == "-" or cli.context == "-"):
      text = _clearly.ossafe("can’t read stdin", sys.stdin.read)
   elif (not os.path.isdir(cli.context)):
      _clearly.FATAL("context must be a directory: %s" % cli.context)
   else:
      fp = _filesystem.Path(cli.file).open("rt")
      text = _clearly.ossafe("can’t read: %s" % cli.file, fp.read)
      _clearly.close_(fp)

   return text

# Process common opts in build.
def cli_process_common(cli):
   # --force and friends.
   if (cli.force_cmd and cli.force == _clearly.Force_Mode.FAKEROOT):
      _clearly.FATAL("--force-cmd and --force=fakeroot are incompatible")
   if (not cli.force_cmd):
      cli.force_cmd = _force.FORCE_CMD_DEFAULT
   else:
      cli.force = _clearly.Force_Mode.SECCOMP
      # convert cli.force_cmd to parsed dict
      force_cmd = dict()
      for line in cli.force_cmd:
         (cmd, args) = _force.force_cmd_parse(line)
         force_cmd[cmd] = args
      cli.force_cmd = force_cmd
   _clearly.VERBOSE("force mode: %s" % cli.force)
   if (cli.force == _clearly.Force_Mode.SECCOMP):
      for (cmd, args) in cli.force_cmd.items():
         _clearly.VERBOSE("force command: %s" % _clearly.argv_to_string([cmd] + args))
   if (    cli.force == _clearly.Force_Mode.SECCOMP
       and _clearly.cmd([PKGLIBEXECDIR + "/run", "--feature=seccomp"],
                  fail_ok=True) != 0):
      _clearly.FATAL("run was not built with seccomp(2) support")

   # Deal with build arguments.
   def build_arg_get(arg):
      kv = arg.split("=")
      if (len(kv) == 2):
         return kv
      else:
         v = os.getenv(kv[0])
         if (v is None):
            _clearly.FATAL("--build-arg: %s: no value and not in environment" % kv[0])
         return (kv[0], v)
   cli.build_arg = dict( build_arg_get(i) for i in cli.build_arg )

def parse_dockerfile(text, cli):
   # Parse it.
   parser = lark.Lark(_grammar.GRAMMAR_DOCKERFILE, parser="earley",
                      propagate_positions=True, tree_class=Tree)
   # Avoid Lark issue #237: lark.exceptions.UnexpectedEOF if the file does not
   # end in newline.
   text += "\n"
   try:
      tree = parser.parse(text)
   except lark.exceptions.UnexpectedInput as x:
      _clearly.VERBOSE(x)  # noise about what was expected in the grammar
      _clearly.FATAL("can’t parse: %s:%d,%d\n\n%s"
               % (cli.file, x.line, x.column, x.get_context(text, 39)))
   _clearly.VERBOSE(tree.pretty()[:-1])  # rm trailing newline

   # Sometimes we exit after parsing.
   if (cli.parse_only):
      _clearly.exit(0)

   # If we use RSYNC, error out quickly if appropriate rsync(1) not present.
   if (tree.child("rsync") is not None):
      try:
         _clearly.version_check(["rsync", "--version"], _clearly.RSYNC_MIN)
      except _clearly.Fatal_Error:
         _clearly.ERROR("Dockerfile uses RSYNC, so rsync(1) is required")
         raise

   return tree