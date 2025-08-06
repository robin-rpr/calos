import collections
import copy
import datetime
import json
import os
import re
import sys
import tarfile

import _clearly as _clearly
import _filesystem as _filesystem
import _reference as _reference


## Hairy Imports ##

# Lark is bundled or provided by package dependencies, so assume it's always
# importable. There used to be a conflicting package on PyPI called "lark",
# but it's gone now [1]. However, verify the version we got.
#
# [1]: https://github.com/lark-parser/lark/issues/505
import lark
LARK_MIN = (0, 9, 0)
LARK_MAX = (99, 0, 0)
lark_version = tuple(int(i) for i in lark.__version__.split("."))
if (not LARK_MIN <= lark_version <= LARK_MAX):
   _clearly.depfails.append(("bad", 'found Python module "lark" version %d.%d.%d but need between %d.%d.%d and %d.%d.%d inclusive' % (lark_version + LARK_MIN + LARK_MAX)))


## Constants ##

# ARGs that are "magic": always available, don't cause cache misses, not saved
# with the image.
ARGS_MAGIC = { "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY",
               "http_proxy", "https_proxy", "ftp_proxy", "no_proxy",
               "SSH_AUTH_SOCK", "USER" }
# FIXME: clearly.user() not yet defined
ARG_DEFAULTS_MAGIC = { k:v for (k,v) in ((m, os.environ.get(m))
                                          for m in ARGS_MAGIC)
                       if v is not None }

# ARGs with pre-defined default values that *are* saved with the image.
ARG_DEFAULTS = \
   { # calls to chown/fchown withn a user namespace will fail with EINVAL for
     # UID/GIDs besides the current one. This env var tells fakeroot to not
     # try. Credit to Dave Dykstra for pointing us to this.
     "FAKEROOTDONTTRYCHOWN": "1",
     "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
     # GNU tar, when it thinks it's running as root, tries to chown(2) and
     # chgrp(2) files to whatever is in the tarball.
     "TAR_OPTIONS": "--no-same-owner" }

# Top-level directories we create if not present.
STANDARD_DIRS = { "bin", "dev", "etc", "mnt", "proc", "sys", "tmp", "usr" }

# Where the .git "directory" in the image is located. (Normally it's a
# directory, and that's what the Git docs call it, but it's a file for
# worktrees.) We deliberately do not call it ".git" because that makes it
# hidden, but also more importantly it confuses Git into thinking /clearly is a
# different Git repo.
GIT_DIR = "clearly/git"

## Classes ##

class Image:
   """Container image object.

      Constructor arguments:

        ref........... Reference object to identify the image.

        unpack_path .. Directory to unpack the image in; if None, infer path
                       in storage dir from ref."""

   __slots__ = ("metadata",
                "ref",
                "unpack_path")

   def __init__(self, ref, unpack_path=None):
      if (isinstance(ref, str)):
         ref = _reference.Reference(ref)
      assert isinstance(ref, _reference.Reference)
      self.ref = ref
      if (unpack_path is not None):
         assert isinstance(unpack_path, _filesystem.Path)
         self.unpack_path = unpack_path
      else:
         self.unpack_path = _clearly.storage.unpack(self.ref)
      self.metadata_init()

   @classmethod
   def glob(class_, image_glob):
      """Return a possibly-empty iterator of images in the storage directory
         matching the given glob."""
      for ref in _reference.Reference.glob(image_glob):
         yield class_(ref)

   def __str__(self):
      return str(self.ref)

   @property
   def deleteable(self):
      """True if it's OK to delete me, either my unpack directory (a) is at
         the expected location within the storage directory xor (b) is not not
         but it looks like an image; False otherwise."""
      if (self.unpack_path == _clearly.storage.unpack_base // self.unpack_path.name):
         return True
      else:
         if (all(os.path.isdir(self.unpack_path // i)
                for i in ("bin", "dev", "usr"))):
            return True
      return False

   @property
   def last_modified(self):
      # Return the last modified time of self as a datetime.datetime object in
      # the local time zone.
      return datetime.datetime.fromtimestamp(
                 (self.metadata_path // "metadata.json").stat(False).st_mtime,
                 datetime.timezone.utc).astimezone()

   @property
   def metadata_path(self):
      return self.unpack_path // "clearly"

   @property
   def unpack_cache_linked(self):
      return (self.unpack_path // GIT_DIR).exists()

   @property
   def unpack_exist_p(self):
      return os.path.exists(self.unpack_path)

   def commit(self):
      "Commit the current unpack directory into the layer cache."
      assert False, "unimplemented"

   def copy_unpacked(self, other):
      """Copy image other to my unpack directory, which may not exist. other
         can be either a path (string or filesystem.Path object) or an Image object;
         in the latter case other.unpack_path is used. other need not be a
         valid image; the essentials will be created if needed."""
      if (isinstance(other, str) or isinstance(other, _filesystem.Path)):
         src_path = other
      else:
         src_path = other.unpack_path
      _clearly.VERBOSE("copying image: %s -> %s" % (src_path, self.unpack_path))
      _filesystem.Path(src_path).copytree(self.unpack_path, symlinks=True)
      # Simpler to copy this file then delete it, rather than filter it out.
      (self.unpack_path // GIT_DIR).unlink(missing_ok=True)
      self.unpack_init()

   def layers_open(self, layer_tars):
      """Open the layer tarballs and read some metadata (which unfortunately
         means reading the entirety of every file). Return an OrderedDict:

           keys:    layer hash (full)
           values:  namedtuple with two fields:
                      fp:       open TarFile object
                      members:  sequence of members (OrderedSet)

         Empty layers are skipped.

         Important note: TarFile.extractall() extracts the given members in
         the order they are specified, so we need to preserve their order from
         the file, as returned by getmembers(). We also need to quickly remove
         members we don't want from this sequence. Thus, we use the OrderedSet
         class defined in this module."""
      TT = collections.namedtuple("TT", ["fp", "members"])
      layers = collections.OrderedDict()
      # Schema version one (v1) allows one or more empty layers for Dockerfile
      # entries like CMD (https://github.com/containers/skopeo/issues/393).
      # Unpacking an empty layer doesn't accomplish anything, so ignore them.
      empty_cnt = 0
      for (i, path) in enumerate(layer_tars, start=1):
         lh = os.path.basename(path).split(".", 1)[0]
         lh_short = lh[:7]
         _clearly.INFO("layer %d/%d: %s: listing" % (i, len(layer_tars), lh_short))
         try:
            fp = _filesystem.TarFile.open(path)
            members = _clearly.OrderedSet(fp.getmembers())  # reads whole file :(
         except tarfile.TarError as x:
            _clearly.FATAL("cannot open: %s: %s" % (path, x))
         if (lh in layers and len(members) > 0):
            _clearly.WARNING("ignoring duplicate non-empty layer: %s" % lh_short)
         if (len(members) > 0):
            layers[lh] = TT(fp, members)
         else:
            _clearly.WARNING("ignoring empty layer: %s" % lh_short)
            empty_cnt += 1
      _clearly.VERBOSE("skipped %d empty layers" % empty_cnt)
      return layers

   def metadata_init(self):
      "Initialize empty metadata structure."
      # Elsewhere can assume the existence and types of everything here.
      self.metadata = { "arch": _clearly.arch_host.split("/")[0],  # no variant
                        "arg": { **ARG_DEFAULTS_MAGIC, **ARG_DEFAULTS },
                        "cwd": "/",
                        "env": dict(),
                        "history": list(),
                        "labels": dict(),
                        "shell": ["/bin/sh", "-c"],
                        "volumes": list() }  # set isn't JSON-serializable

   def metadata_load(self, target_img=None):
      """Load metadata file, replacing the existing metadata object. If
         metadata doesn't exist, warn and use defaults. If target_img is
         non-None, use that image's metadata instead of self's."""
      if (target_img is not None):
         path = target_img.metadata_path
      else:
         path = self.metadata_path
      path //= "metadata.json"
      if (path.exists()):
         _clearly.VERBOSE("loading metadata")
      else:
         _clearly.WARNING("no metadata to load; using defaults")
         self.metadata_init()
         return
      self.metadata = path.json_from_file("metadata")
      # upgrade old metadata
      self.metadata.setdefault("arg", dict())
      self.metadata.setdefault("history", list())
      # add default ARG variables
      self.metadata["arg"].update({ **ARG_DEFAULTS_MAGIC, **ARG_DEFAULTS })

   def metadata_merge_from_config(self, config):
      """Interpret all the crap in the config data structure that is
         meaningful to us, and add it to self.metadata. Ignore anything we
         expect in config that's missing."""
      def get(*keys):
         d = config
         keys = list(keys)
         while (len(keys) > 1):
            try:
               d = d[keys.pop(0)]
            except KeyError:
               return None
         assert (len(keys) == 1)
         return d.get(keys[0])
      def set_(dst_key, *src_keys):
         v = get(*src_keys)
         if (v is not None and v != ""):
            self.metadata[dst_key] = v
      if ("config" not in config):
         _clearly.FATAL("config missing key 'config'")
      # architecture
      set_("arch", "architecture")
      # $CWD
      set_("cwd", "config", "WorkingDir")
      # environment
      env = get("config", "Env")
      if (env is not None):
         for line in env:
            try:
               (k,v) = line.split("=", maxsplit=1)
            except AttributeError:
               _clearly.FATAL("can't parse config: bad Env line: %s" % line)
            self.metadata["env"][k] = v
      # History.
      if ("history" not in config):
         _clearly.FATAL("invalid config: missing history")
      self.metadata["history"] = config["history"]
      # labels
      set_("labels", "config", "Labels")  # copy reference
      # shell
      set_("shell", "config", "Shell")
      # Volumes. FIXME: Why is this a dict with empty dicts as values?
      vols = get("config", "Volumes")
      if (vols is not None):
         for k in config["config"]["Volumes"].keys():
            self.metadata["volumes"].append(k)

   def metadata_replace(self, config_json):
      self.metadata_init()
      if (config_json is None):
         _clearly.INFO("no config found; initializing empty metadata")
      else:
         # Copy pulled config file into the image so we still have it.
         path = self.metadata_path // "config.pulled.json"
         config_json.copy(path)
         _clearly.VERBOSE("pulled config path: %s" % path)
         self.metadata_merge_from_config(path.json_from_file("config"))
      self.metadata_save()

   def metadata_save(self):
      """Dump image's metadata to disk, including the main data structure but
         also all auxiliary files, e.g. clearly/environment."""
      # Adjust since we don't save everything.
      metadata = copy.deepcopy(self.metadata)
      for k in ARGS_MAGIC:
         metadata["arg"].pop(k, None)
      # Serialize. We take care to pretty-print this so it can (sometimes) be
      # parsed by simple things like grep and sed.
      out = json.dumps(metadata, indent=2, sort_keys=True)
      _clearly.DEBUG("metadata:\n%s" % out)
      # Main metadata file.
      path = self.metadata_path // "metadata.json"
      _clearly.VERBOSE("writing metadata file: %s" % path)
      path.file_write(out + "\n")
      # /clearly/environment
      path = self.metadata_path // "environment"
      _clearly.VERBOSE("writing environment file: %s" % path)
      path.file_write( (  "\n".join("%s=%s" % (k,v) for (k,v)
                                    in sorted(metadata["env"].items()))
                        + "\n"))
      # mkdir volumes
      _clearly.VERBOSE("ensuring volume directories exist")
      for path in metadata["volumes"]:
         (self.unpack_path // path).mkdirs()

   def tarballs_write(self, tarball_dir):
      """Write one uncompressed tarball per layer to tarball_dir. Return a
         sequence of tarball basenames, with the lowest layer first."""
      # FIXME: Yes, there is only one layer for now and we'll need to update
      # it when (if) we have multiple layers. But, I wanted the interface to
      # support multiple layers.
      base = "%s.tar" % self.ref.for_path
      path = tarball_dir // base
      try:
         _clearly.INFO("layer 1/1: gathering")
         _clearly.VERBOSE("writing tarball: %s" % path)
         fp = _filesystem.TarFile.open(path, "w", format=tarfile.PAX_FORMAT)
         unpack_path = self.unpack_path.resolve()  # aliases use symlinks
         _clearly.VERBOSE("canonicalized unpack path: %s" % unpack_path)
         fp.add_(unpack_path, arcname=".")
         fp.close()
      except OSError as x:
         _clearly.FATAL("can't write tarball: %s" % x.strerror)
      return [base]

   def unpack(self, layer_tars, last_layer=None):
      """Unpack config_json (path to JSON config file) and layer_tars
         (sequence of paths to tarballs, with lowest layer first) into the
         unpack directory, validating layer contents and dealing with
         whiteouts. Empty layers are ignored. The unpack directory must not
         exist."""
      if (last_layer is None):
         last_layer = sys.maxsize
      _clearly.INFO("flattening image")
      self.unpack_layers(layer_tars, last_layer)
      self.unpack_init()

   def unpack_cache_unlink(self):
      (self.unpack_path // ".git").unlink()

   def unpack_clear(self):
      """If the unpack directory does not exist, do nothing. If the unpack
         directory is already an image, remove it. Otherwise, error."""
      if (not os.path.exists(self.unpack_path)):
         _clearly.VERBOSE("no image found: %s" % self.unpack_path)
      else:
         if (not os.path.isdir(self.unpack_path)):
            _clearly.FATAL("can't flatten: %s exists but is not a directory"
                  % self.unpack_path)
         if (not self.deleteable):
            _clearly.FATAL("can't flatten: %s exists but does not appear to be an image"
                     % self.unpack_path)
         _clearly.VERBOSE("removing image: %s" % self.unpack_path)
         t = _clearly.Timer()
         self.unpack_path.rmtree()
         t.log("removed image")

   def unpack_delete(self):
      _clearly.VERBOSE("unpack path: %s" % self.unpack_path)
      if (not self.unpack_exist_p):
         _clearly.FATAL("image not found, can't delete: %s" % self.ref)
      if (self.deleteable):
         _clearly.INFO("deleting image: %s" % self.ref)
         self.unpack_path.chmod_min()
         for (dir_, subdirs, _) in os.walk(self.unpack_path):
            # must fix as subdirs so we can traverse into them
            for subdir in subdirs:
               (_filesystem.Path(dir_) // subdir).chmod_min()
         self.unpack_path.rmtree()
      else:
         _clearly.FATAL("storage directory seems broken: not an image: %s" % self.ref)

   def unpack_init(self):
      """Initialize the unpack directory, which must exist. Any setup already
         present will be left unchanged. After this, self.unpack_path is a
         valid Clearly image directory."""
      # Metadata directory.
      (self.unpack_path // "clearly").mkdir()
      (self.unpack_path // "clearly/environment").file_ensure_exists()
      # Essential directories & mount points. Do nothing if something already
      # exists, without dereferencing, in case it's a symlink, which will work
      # for bind-mount later but won't resolve correctly now outside the
      # container (e.g. linuxcontainers.org images; issue #1015).
      #
      # WARNING: Keep in sync with shell scripts.
      for d in list(STANDARD_DIRS) + ["mnt/%d" % i for i in range(10)]:
         d = self.unpack_path // d
         if (not os.path.lexists(d)):
            d.mkdirs()
      (self.unpack_path // "etc/hosts").file_ensure_exists()
      (self.unpack_path // "etc/resolv.conf").file_ensure_exists()

   def unpack_layers(self, layer_tars, last_layer):
      layers = self.layers_open(layer_tars)
      self.validate_members(layers)
      self.whiteouts_resolve(layers)
      self.unpack_path.mkdir()  # create directory in case no layers
      for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
         lh_short = lh[:7]
         if (i > last_layer):
            _clearly.INFO("layer %d/%d: %s: skipping per --last-layer"
                 % (i, len(layers), lh_short))
         else:
            _clearly.INFO("layer %d/%d: %s: extracting" % (i, len(layers), lh_short))
            try:
               fp.extractall(path=self.unpack_path, members=members)
            except OSError as x:
               _clearly.FATAL("can't extract layer %d: %s" % (i, x.strerror))

   def validate_members(self, layers):
      _clearly.INFO("validating tarball members")
      top_dirs = set()
      _clearly.VERBOSE("pass 1: canonicalizing member paths")
      for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
         abs_ct = 0
         for m in list(members):   # copy b/c we remove items from the set
            # Remove members with empty paths.
            if (len(m.name) == 0):
               _clearly.WARNING("layer %d/%d: %s: skipping member with empty path"
                       % (i, len(layers), lh[:7]))
               members.remove(m)
            # Convert member paths to filesystem.Path objects for easier processing.
            # Note: In my testing, parsing a string into a filesystem.Path object took
            # about 2.5µs, so this should be plenty fast.
            m.name = _filesystem.Path(m.name)
            # Reject members with up-levels.
            if (".." in m.name.parts):
               _clearly.FATAL("rejecting up-level member: %s: %s" % (fp.name, m.name))
            # Correct absolute paths.
            if (m.name.is_absolute()):
               m.name = m.name.relative_to("/")
               abs_ct += 1
            # Record top-level directory.
            if (len(m.name.parts) > 1 or m.isdir()):
               top_dirs.add(m.name.first)
         if (abs_ct > 0):
            _clearly.WARNING("layer %d/%d: %s: fixed %d absolute member paths"
                    % (i, len(layers), lh[:7], abs_ct))
      top_dirs.discard(None)  # ignore "."
      # Convert to tarbomb if (1) there is a single enclosing directory and
      # (2) that directory is not one of the standard directories, e.g. to
      # allow images containing just "/bin/fooprog".
      if (len(top_dirs) != 1 or not top_dirs.isdisjoint(STANDARD_DIRS)):
         _clearly.VERBOSE("pass 2: conversion to tarbomb not needed")
      else:
         _clearly.VERBOSE("pass 2: converting to tarbomb")
         for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
            for m in members:
               if (len(m.name.parts) > 0):  # ignore "."
                  m.name = _filesystem.Path(*m.name.parts[1:])  # strip first component
      _clearly.VERBOSE("pass 3: analyzing members")
      for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
         dev_ct = 0
         link_fix_ct = 0
         for m in list(members):  # copy again
            m.name = str(m.name)  # other code assumes strings
            if (m.isdev()):
               # Device or FIFO: Ignore.
               dev_ct += 1
               _clearly.VERBOSE("ignoring device file: %s" % m.name)
               members.remove(m)
               continue
            elif (m.issym() or m.islnk()):
               link_fix_ct += _filesystem.TarFile.fix_link_target(m, fp.name)
            elif (m.isdir()):
               # Directory: Fix bad permissions (hello, Red Hat).
               m.mode |= 0o700
            elif (m.isfile()):
               # Regular file: Fix bad permissions (HELLO RED HAT!!).
               m.mode |= 0o600
            else:
               _clearly.FATAL("unknown member type: %s" % m.name)
            # Discard Git metadata (files that begin with ".git").
            if (re.search(r"^(\./)?\.git", m.name)):
               _clearly.WARNING("ignoring member: %s" % m.name)
               members.remove(m)
               continue
            # Discard anything under /dev. Docker puts regular files and
            # directories in here on "docker export". Note leading slashes
            # already taken care of in TarFile.fix_member_path() above.
            if (re.search(r"^(\./)?dev/.", m.name)):
               _clearly.VERBOSE("ignoring member under /dev: %s" % m.name)
               members.remove(m)
               continue
            _filesystem.TarFile.fix_member_uidgid(m)
         if (dev_ct > 0):
            _clearly.WARNING("layer %d/%d: %s: ignored %d devices and/or FIFOs"
                    % (i, len(layers), lh[:7], dev_ct))
         if (link_fix_ct > 0):
            _clearly.INFO("layer %d/%d: %s: changed %d absolute symbolic and/or hard links to relative"
                    % (i, len(layers), lh[:7], link_fix_ct))

   def whiteout_rm_prefix(self, layers, max_i, prefix):
      """Ignore members of all layers from 1 to max_i inclusive that have path
         prefix of prefix. For example, if prefix is foo/bar, then ignore
         foo/bar and foo/bar/baz but not foo/barbaz. Return count of members
         ignored."""
      _clearly.TRACE("finding members with prefix: %s" % prefix)
      prefix = os.path.normpath(prefix)  # "./foo" == "foo"
      ignore_ct = 0
      for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
         if (i > max_i): break
         members2 = list(members)  # copy b/c we'll alter members
         for m in members2:
            if (_clearly.prefix_path(prefix, m.name)):
               ignore_ct += 1
               members.remove(m)
               _clearly.TRACE("layer %d/%d: %s: ignoring %s"
                     % (i, len(layers), lh[:7], m.name))
      return ignore_ct

   def whiteouts_resolve(self, layers):
      """Resolve whiteouts. See:
         https://github.com/opencontainers/image-spec/blob/master/layer.md"""
      _clearly.INFO("resolving whiteouts")
      for (i, (lh, (fp, members))) in enumerate(layers.items(), start=1):
         wo_ct = 0
         ig_ct = 0
         members2 = list(members)  # copy b/c we'll alter members
         for m in members2:
            dir_ = os.path.dirname(m.name)
            filename = os.path.basename(m.name)
            if (filename.startswith(".wh.")):
               wo_ct += 1
               members.remove(m)
               if (filename == ".wh..wh..opq"):
                  # "Opaque whiteout": remove contents of dir_.
                  _clearly.DEBUG("found opaque whiteout: %s" % m.name)
                  ig_ct += self.whiteout_rm_prefix(layers, i - 1, dir_)
               else:
                  # "Explicit whiteout": remove same-name file without ".wh.".
                  _clearly.DEBUG("found explicit whiteout: %s" % m.name)
                  ig_ct += self.whiteout_rm_prefix(layers, i - 1,
                                                   dir_ + "/" + filename[4:])
         if (wo_ct > 0):
            _clearly.VERBOSE("layer %d/%d: %s: %d whiteouts; %d members ignored"
                    % (i, len(layers), lh[:7], wo_ct, ig_ct))