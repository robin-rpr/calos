# Subcommands not exciting enough for their own module.

import argparse
import inspect
import itertools
import os
import os.path
import sys

import _clearly as clearly
import _build_cache as build_cache
import _filesystem as filesystem
import _image as image
import _reference as reference
import _pull as pull
import _version as version
import lark


## argparse “actions” ##

class Action_Exit(argparse.Action):

   def __init__(self, *args, **kwargs):
      super().__init__(nargs=0, *args, **kwargs)

class Dependencies(Action_Exit):

   def __call__(self, ap, cli, *args, **kwargs):
      # clearly.init() not yet called, so must get verbosity from arguments.
      clearly.dependencies_check()
      if (cli.verbose >= 1):
         print("lark path: %s" % os.path.normpath(inspect.getfile(lark)))
      sys.exit(0)

class Version(Action_Exit):

   def __call__(self, *args, **kwargs):
      print(version.VERSION)
      sys.exit(0)


## Plain functions ##

# Argument: command line arguments Namespace. Do not need to call sys.exit()
# because caller manages that.

def build_cache(cli):
   if (cli.bucache == clearly.Build_Mode.DISABLED):
      clearly.FATAL("build-cache subcommand invalid with build cache disabled")
   if (cli.reset):
      build_cache.cache.reset()
   if (cli.gc):
      build_cache.cache.garbageinate()
   if (cli.tree):
      build_cache.cache.tree_print()
   if (cli.dot):
      build_cache.cache.tree_dot()
   build_cache.cache.summary_print()

def delete(cli):
   fail_ct = 0
   for ref in cli.image_ref:
      delete_ct = 0
      for img in itertools.chain(image.Image.glob(ref),
                                 image.Image.glob(ref + "_stage[0-9]*")):
         build_cache.cache.unpack_delete(img)
         to_delete = reference.Reference.ref_to_pathstr(str(img))
         build_cache.cache.branch_delete(to_delete)
         delete_ct += 1
      if (delete_ct == 0):
         fail_ct += 1
         clearly.ERROR("no matching image, can’t delete: %s" % ref)
   build_cache.cache.worktrees_fix()
   if (fail_ct > 0):
      clearly.FATAL("unable to delete %d invalid image(s)" % fail_ct)

def gestalt_bucache(cli):
   build_cache.have_deps()

def gestalt_bucache_dot(cli):
   build_cache.have_deps()
   build_cache.have_dot()

def gestalt_logging(cli):
   clearly.TRACE("trace")
   clearly.DEBUG("debug")
   clearly.VERBOSE("verbose")
   clearly.INFO("info")
   clearly.WARNING("warning")
   clearly.ERROR("error")
   if (cli.fail):
      clearly.FATAL("the program failed inexplicably")

def gestalt_python_path(cli):
   print(sys.executable)

def gestalt_storage_path(cli):
   print(clearly.storage.root)

def import_(cli):
   if (not os.path.exists(cli.path)):
      clearly.FATAL("can’t copy: not found: %s" % cli.path)
   if (clearly.xattrs_save):
      clearly.WARNING("--xattrs unsupported by “clearly image import” (see FAQ)")
   pathstr = reference.Reference.ref_to_pathstr(cli.image_ref)
   if (cli.bucache == clearly.Build_Mode.ENABLED):
      # Un-tag previously deleted branch, if it exists.
      build_cache.cache.tag_delete(pathstr, fail_ok=True)
   dst = image.Image(reference.Reference(cli.image_ref))
   clearly.INFO("importing:    %s" % cli.path)
   clearly.INFO("destination:  %s" % dst)
   dst.unpack_clear()
   if (os.path.isdir(cli.path)):
      dst.copy_unpacked(cli.path)
   else:  # tarball, hopefully
      dst.unpack([cli.path])
   build_cache.cache.adopt(dst)
   if (dst.metadata["history"] == []):
      dst.metadata["history"].append({ "empty_layer": False,
                                       "command":     "clearly image import"})
   dst.metadata_save()
   clearly.done_notify()

def list_(cli):
   if (cli.undeletable):
      # list undeletable images
      imgdir = clearly.storage.build_cache // "refs/tags"
   else:
      # list images
      imgdir = clearly.storage.unpack_base
   if (cli.image_ref is None):
      # list all images
      if (not os.path.isdir(clearly.storage.root)):
         clearly.FATAL("does not exist: %s" % clearly.storage.root)
      if (not clearly.storage.valid_p):
         clearly.FATAL("not a storage directory: %s" % clearly.storage.root)
      images = sorted(imgdir.listdir())
      if (len(images) >= 1):
         img_width = max(len(ref) for ref in images)
         for ref in images:
            img = image.Image(reference.Reference(filesystem.Path(ref).parts[-1]))
            if cli.long:
               print("%-*s | %s" % (img_width, img, img.last_modified.ctime()))
            else:
               print(img)
   else:
      # list specified image
      img = image.Image(reference.Reference(cli.image_ref))
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
      (sid, commit) = build_cache.cache.find_image(img)
      if (sid is None):
         cached = "no"
      else:
         cached = "yes (state ID %s, commit %s)" % (sid.short, commit[:7])
         if (os.path.exists(img.unpack_path)):
            wdc = build_cache.cache.worktree_head(img)
            if (wdc is None):
               clearly.WARNING("stored image not connected to build cache")
            elif (wdc != commit):
               clearly.WARNING("stored image doesn’t match build cache: %s" % wdc)
      print("in build cache:      %s" % cached)
      # present remotely?
      print("full remote ref:     %s" % img.ref.canonical)
      pullet = pull.Image_Puller(img, img.ref)
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
      except clearly.Image_Unavailable_Error:
         remote = "no (or you are not authorized)"
         arch_aware = "n/a"
         arch_avail = ["n/a"]
      except clearly.No_Fatman_Error:
         remote = "yes"
         arch_aware = "no"
         arch_avail = ["unknown"]
      pullet.done()
      print("available remotely:  %s" % remote)
      print("remote arch-aware:   %s" % arch_aware)
      print("host architecture:   %s" % clearly.arch_host)
      print("archs available:     %s" % arch_avail[0])
      for arch in arch_avail[1:]:
         print((" " * 21) + arch)

def reset(cli):
   clearly.storage.reset()

def undelete(cli):
   if (cli.bucache != clearly.Build_Mode.ENABLED):
      clearly.FATAL("only available when cache is enabled")
   img = image.Image(reference.Reference(cli.image_ref))
   if (img.unpack_exist_p):
      clearly.FATAL("image exists; will not overwrite")
   (_, git_hash) = build_cache.cache.find_deleted_image(img)
   if (git_hash is None):
      clearly.FATAL("image not in cache")
   build_cache.cache.checkout_ready(img, git_hash)
