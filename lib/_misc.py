# Subcommands not exciting enough for their own module.

import argparse
import inspect
import itertools
import os
import os.path
import sys

import _clearly as _clearly
import _filesystem as _filesystem
import _build_cache as _build_cache
import _image as _image
import _reference as _reference
import _pull as _pull

import lark


## argparse “actions” ##

class Action_Exit(argparse.Action):

   def __init__(self, *args, **kwargs):
      super().__init__(nargs=0, *args, **kwargs)

class Dependencies(Action_Exit):

   def __call__(self, ap, cli, *args, **kwargs):
      # clearly.init() not yet called, so must get verbosity from arguments.
      _clearly.dependencies_check()
      if (cli.verbose >= 1):
         print("lark path: %s" % os.path.normpath(inspect.getfile(lark)))
      sys.exit(0)

## Plain functions ##

# Argument: command line arguments Namespace. Do not need to call sys.exit()
# because caller manages that.

def build_cache(cli):
   if (cli.bucache == _clearly.Build_Mode.DISABLED):
      _clearly.FATAL("build-cache subcommand invalid with build cache disabled")
   if (cli.reset):
      _build_cache.cache.reset()
   if (cli.gc):
      _build_cache.cache.garbageinate()
   if (cli.tree):
      _build_cache.cache.tree_print()
   if (cli.dot):
      _build_cache.cache.tree_dot()
   _build_cache.cache.summary_print()

def delete(cli):
   fail_ct = 0
   for ref in cli.image_ref:
      delete_ct = 0
      for img in itertools.chain(_image.Image.glob(ref),
                                 _image.Image.glob(ref + "_stage[0-9]*")):
         _build_cache.cache.unpack_delete(img)
         to_delete = _reference.Reference.ref_to_pathstr(str(img))
         _build_cache.cache.branch_delete(to_delete)
         delete_ct += 1
      if (delete_ct == 0):
         fail_ct += 1
         _clearly.ERROR("no matching image, can’t delete: %s" % ref)
   _build_cache.cache.worktrees_fix()
   if (fail_ct > 0):
      _clearly.FATAL("unable to delete %d invalid image(s)" % fail_ct)

def gestalt_bucache(cli):
   _build_cache.have_deps()

def gestalt_bucache_dot(cli):
   _build_cache.have_deps()
   _build_cache.have_dot()

def gestalt_logging(cli):
   _clearly.TRACE("trace")
   _clearly.DEBUG("debug")
   _clearly.VERBOSE("verbose")
   _clearly.INFO("info")
   _clearly.WARNING("warning")
   _clearly.ERROR("error")
   if (cli.fail):
      _clearly.FATAL("the program failed inexplicably")

def gestalt_python_path(cli):
   print(sys.executable)

def gestalt_storage_path(cli):
   print(_clearly.storage.root)

def import_(cli):
   if (not os.path.exists(cli.path)):
      _clearly.FATAL("can’t copy: not found: %s" % cli.path)
   if (_clearly.xattrs_save):
      _clearly.WARNING("--xattrs unsupported by “clearly image import” (see FAQ)")
   pathstr = _reference.Reference.ref_to_pathstr(cli.image_ref)
   if (cli.bucache == _clearly.Build_Mode.ENABLED):
      # Un-tag previously deleted branch, if it exists.
      _build_cache.cache.tag_delete(pathstr, fail_ok=True)
   dst = _image.Image(_reference.Reference(cli.image_ref))
   _clearly.INFO("importing:    %s" % cli.path)
   _clearly.INFO("destination:  %s" % dst)
   dst.unpack_clear()
   if (os.path.isdir(cli.path)):
      dst.copy_unpacked(cli.path)
   else:  # tarball, hopefully
      dst.unpack([cli.path])
   _build_cache.cache.adopt(dst)
   if (dst.metadata["history"] == []):
      dst.metadata["history"].append({ "empty_layer": False,
                                       "command":     "clearly image import"})
   dst.metadata_save()
   _clearly.done_notify()

def list_(cli):
   if (cli.undeletable):
      # list undeletable images
      imgdir = _clearly.storage.build_cache // "refs/tags"
   else:
      # list images
      imgdir = _clearly.storage.unpack_base
   if (cli.image_ref is None):
      # list all images
      if (not os.path.isdir(_clearly.storage.root)):
         _clearly.FATAL("does not exist: %s" % _clearly.storage.root)
      if (not _clearly.storage.valid_p):
         _clearly.FATAL("not a storage directory: %s" % _clearly.storage.root)
      images = sorted(imgdir.listdir())
      if (len(images) >= 1):
         img_width = max(len(ref) for ref in images)
         for ref in images:
            img = _image.Image(_reference.Reference(_filesystem.Path(ref).parts[-1]))
            if cli.long:
               print("%-*s | %s" % (img_width, img, img.last_modified.ctime()))
            else:
               print(img)
   else:
      # list specified image
      img = _image.Image(_reference.Reference(cli.image_ref))
      print("details of image:    %s" % img.ref)
      # present locally?
      if (not img.unpack_exist_p):
         stored = "no"
      else:
         img.metadata_load()
         stored = "yes (%s), modified: %s" % (img.metadata["arch"],
                                              img.last_modified.ctime())
      print("in local storage:    %s" % stored)
      # in cache?
      (sid, commit) = _build_cache.cache.find_image(img)
      if (sid is None):
         cached = "no"
      else:
         cached = "yes (state ID %s, commit %s)" % (sid.short, commit[:7])
         if (os.path.exists(img.unpack_path)):
            wdc = _build_cache.cache.worktree_head(img)
            if (wdc is None):
               _clearly.WARNING("stored image not connected to build cache")
            elif (wdc != commit):
               _clearly.WARNING("stored image doesn’t match build cache: %s" % wdc)
      print("in build cache:      %s" % cached)
      # present remotely?
      print("full remote ref:     %s" % img.ref.canonical)
      pullet = _pull.Image_Puller(img, img.ref)
      try:
         pullet.fatman_load()
         remote = "yes"
         arch_aware = "yes"
         arch_keys = sorted(pullet.architectures.keys())
         try:
            fmt_space = len(max(arch_keys,key=len))
            arch_avail = []
            for key in arch_keys:
               arch_avail.append("%-*s  %s" % (fmt_space, key,
                                               pullet.digests[key][:11]))
         except ValueError:
            # handles case where arch_keys is empty, e.g.
            # mcr.microsoft.com/windows:20H2.
            arch_avail = [None]
      except _clearly.Image_Unavailable_Error:
         remote = "no (or you are not authorized)"
         arch_aware = "n/a"
         arch_avail = ["n/a"]
      except _clearly.No_Fatman_Error:
         remote = "yes"
         arch_aware = "no"
         arch_avail = ["unknown"]
      pullet.done()
      print("available remotely:  %s" % remote)
      print("remote arch-aware:   %s" % arch_aware)
      print("host architecture:   %s" % _clearly.arch_host)
      print("archs available:     %s" % arch_avail[0])
      for arch in arch_avail[1:]:
         print((" " * 21) + arch)

def reset(cli):
   _clearly.storage.reset()

def undelete(cli):
   if (cli.bucache != _clearly.Build_Mode.ENABLED):
      _clearly.FATAL("only available when cache is enabled")
   img = _image.Image(_reference.Reference(cli.image_ref))
   if (img.unpack_exist_p):
      _clearly.FATAL("image exists; will not overwrite")
   (_, git_hash) = _build_cache.cache.find_deleted_image(img)
   if (git_hash is None):
      _clearly.FATAL("image not in cache")
   _build_cache.cache.checkout_ready(img, git_hash)
