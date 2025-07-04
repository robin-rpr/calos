import lark

import _clearly as _clearly

## Constants ##

# Width of token name when truncating text to fit on screen.
WIDTH_TOKEN_MAX = 10

## Classes ##

class Tree(lark.tree.Tree):

   def _pretty(self, level, istr):
      # Re-implement with less space optimization and more debugging info.
      # See: https://github.com/lark-parser/lark/blob/262ab71/lark/tree.py#L78
      pfx = "%4d %3d%s" % (self.meta.line, self.meta.column, istr*(level+1))
      yield (pfx + self._pretty_label() + "\n")
      for c in self.children:
         if (isinstance(c, Tree)):
            yield from c._pretty(level + 1, istr)
         else:
            text = c
            type_ = c.type
            width = len(pfx) + len(istr) + len(text) + len(type_) + 2
            over = width - _clearly.term_width
            if (len(type_) > WIDTH_TOKEN_MAX):
               # trim token (unconditionally for consistent alignment)
               token_rm = len(type_) - WIDTH_TOKEN_MAX
               type_ = type_[:-token_rm]
               over -= token_rm
            if (over > 0):
               # trim text (if needed)
               text = text[:-(over + 3)] + "..."
            yield "%s%s %s %s\n" % (pfx, istr, type_, text)

   def child(self, cname):
      """Locate a descendant subtree named cname using breadth-first search
         and return it. If no such subtree exists, return None."""
      return next(self.children_(cname), None)

   def child_terminal(self, cname, tname, i=0):
      """Locate a descendant subtree named cname using breadth-first search
         and return its first child terminal named tname. If no such subtree
         exists, or it doesn't have such a terminal, return None."""
      st = self.child(cname)
      if (st is not None):
         return st.terminal(tname, i)
      else:
         return None

   def child_terminals(self, cname, tname):
      """Locate a descendant substree named cname using breadth-first search
         and yield the values of its child terminals named tname. If no such
         subtree exists, or it has no such terminals, yield empty sequence."""
      for d in self.iter_subtrees_topdown():
         if (d.data == cname):
            return d.terminals(tname)
      return []

   def child_terminals_cat(self, cname, tname):
      """Return the concatenated values of all child terminals named tname as
         a string, with no delimiters. If none, return the empty string."""
      return "".join(self.child_terminals(cname, tname))

   def children_(self, cname):
      "Yield children of tree named cname using breadth-first search."
      for st in self.iter_subtrees_topdown():
         if (st.data == cname):
            yield st

   def iter_subtrees_topdown(self, *args, **kwargs):
      return super().iter_subtrees_topdown(*args, **kwargs)

   def terminal(self, tname, i=0):
      """Return the value of the ith child terminal named tname (zero-based),
         or None if not found."""
      for (j, t) in enumerate(self.terminals(tname)):
         if (j == i):
            return t
      return None

   def terminals(self, tname):
      """Yield values of all child terminals named tname, or empty list if
         none found."""
      for j in self.children:
         if (isinstance(j, lark.lexer.Token) and j.type == tname):
            yield j.value

   def terminals_cat(self, tname):
      """Return the concatenated values of all child terminals named tname as
         a string, with no delimiters. If none, return the empty string."""
      return "".join(self.terminals(tname))
