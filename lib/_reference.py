import lark
import copy
import os

import _filesystem as filesystem
import _clearly as clearly
import _grammar as grammar
from _tree import Tree


## Classes ##

class Reference:
   """Reference to an image in a remote repository.

      The constructor takes one argument, which is interpreted differently
      depending on type:

        None or omitted... Build an empty Reference (all fields None).

        string ........... Parse it; see FAQ for syntax. Can be either the
                           standard form (e.g., as in a FROM instruction) or
                           our filename form with percents replacing slashes.

        Lark parse tree .. Must be same result as parsing a string. This
                           allows the parse step to be embedded in a larger
                           parse (e.g., a Dockerfile).

     Warning: References containing a hostname without a dot and no port
     cannot be round-tripped through a string, because the hostname will be
     assumed to be a path component."""

   __slots__ = ("host",
                "port",
                "path",
                "name",
                "tag",
                "digest",
                "variables")

   # Reference parser object. Instantiating a parser took 100ms when we tested
   # it, which means we can't really put it in a loop. But, at parse time,
   # "lark" may refer to a dummy module (see above), so we can't populate the
   # parser here either. We use a class varible and populate it at the time of
   # first use.
   parser = None

   def __init__(self, src=None, variables=None):
      self.host = None
      self.port = None
      self.path = []
      self.name = None
      self.tag = None
      self.digest = None
      self.variables = dict() if variables is None else variables
      if (isinstance(src, str)):
         src = self.parse(src, self.variables)
      if (isinstance(src, lark.tree.Tree)):
         self.from_tree(src)
      elif (src is not None):
         assert False, "unsupported initialization type"

   @staticmethod
   def path_to_ref(path):
      if (isinstance(path, filesystem.Path)):
         path = path.name
      return path.replace("+", ":").replace("%", "/")

   @staticmethod
   def ref_to_pathstr(ref_str):
      return ref_str.replace("/", "%").replace(":", "+")

   @classmethod
   def glob(class_, image_glob):
      """Return a possibly-empty iterator of references in the storage
         directory matching the given glob."""
      for path in clearly.storage.unpack_base.glob(class_.ref_to_pathstr(image_glob)):
         yield class_(class_.path_to_ref(path))

   @classmethod
   def parse(class_, s, variables):
      if (class_.parser is None):
         class_.parser = lark.Lark(grammar.GRAMMAR_IMAGE_REF, parser="earley",
                                   propagate_positions=True, tree_class=Tree)
      s = s.translate(str.maketrans("%+", "/:", "&"))
      hint="https://hpc.github.io/charliecloud/faq.html#how-do-i-specify-an-image-reference"
      s = clearly.variables_sub(s, variables)
      if "$" in s:
         clearly.FATAL("image reference contains an undefined variable: %s" % s)
      try:
         tree = class_.parser.parse(s)
      except lark.exceptions.UnexpectedInput as x:
         if (x.column == -1):
            clearly.FATAL("image ref syntax, at end: %s" % s, hint);
         else:
            clearly.FATAL("image ref syntax, char %d: %s" % (x.column, s), hint)
      except lark.exceptions.UnexpectedEOF as x:
         # We get UnexpectedEOF because of Lark issue #237. This exception
         # doesn't have a column location.
         clearly.FATAL("image ref syntax, at end: %s" % s, hint)
      clearly.DEBUG(tree.pretty())
      return tree

   def __str__(self):
      out = ""
      if (self.host is not None):
         out += self.host
      if (self.port is not None):
         out += ":" + str(self.port)
      if (self.host is not None):
         out += "/"
      out += self.path_full
      if (self.tag is not None):
         out += ":" + self.tag
      if (self.digest is not None):
         out += "@sha256:" + self.digest
      return out

   @property
   def as_verbose_str(self):
      def fmt(x):
         if (x is None):
            return None
         else:
            return repr(x)
      return """\
as string:    %s
for filename: %s
fields:
  host    %s
  port    %s
  path    %s
  name    %s
  tag     %s
  digest  %s\
""" % tuple(  [str(self), self.for_path]
            + [fmt(i) for i in (self.host, self.port, self.path,
                                self.name, self.tag, self.digest)])

   @property
   def canonical(self):
      "Copy of self with all the defaults filled in."
      ref = self.copy()
      ref.defaults_add()
      return ref

   @property
   def for_path(self):
      return self.ref_to_pathstr(str(self))

   @property
   def path_full(self):
      out = ""
      if (len(self.path) > 0):
         out += "/".join(self.path) + "/"
      out += self.name
      return out

   @property
   def version(self):
      if (self.tag is not None):
         return self.tag
      if (self.digest is not None):
         return "sha256:" + self.digest
      assert False, "version invalid with no tag or digest"

   def copy(self):
      "Return an independent copy of myself."
      return copy.deepcopy(self)

   def defaults_add(self):
      "Set defaults for all empty fields."
      if (self.host is None):
         if ("CH_REGY_DEFAULT_HOST" not in os.environ):
            self.host = "registry-1.docker.io"
         else:
            self.host = os.getenv("CH_REGY_DEFAULT_HOST")
            self.port = int(os.getenv("CH_REGY_DEFAULT_PORT", 443))
            prefix = os.getenv("CH_REGY_PATH_PREFIX")
            if (prefix is not None):
               self.path = prefix.split("/") + self.path
      if (self.port is None): self.port = 443
      if (self.host == "registry-1.docker.io" and len(self.path) == 0):
         # FIXME: For Docker Hub only, images with no path need a path of
         # "library" substituted. Need to understand/document the rules here.
         self.path = ["library"]
      if (self.tag is None and self.digest is None): self.tag = "latest"

   def from_tree(self, t):
      self.host = t.child_terminal("ir_hostport", "IR_HOST")
      self.port = t.child_terminal("ir_hostport", "IR_PORT")
      if (self.port is not None):
         self.port = int(self.port)
      self.path = [    clearly.variables_sub(s, self.variables)
                   for s in t.child_terminals("ir_path", "IR_PATH_COMPONENT")]
      self.name = t.child_terminal("ir_name", "IR_PATH_COMPONENT")
      self.tag = t.child_terminal("ir_tag", "IR_TAG")
      self.digest = t.child_terminal("ir_digest", "HEX_STRING")
      for a in ("host", "port", "name", "tag", "digest"):
         setattr(self, a, clearly.variables_sub(getattr(self, a), self.variables))
      # Resolve grammar ambiguity for hostnames w/o dot or port.
      if (    self.host is not None
          and "." not in self.host
          and self.port is None):
         self.path.insert(0, self.host)
         self.host = None