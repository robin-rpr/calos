import json
import os
import os.path

import _clearly as _clearly
import _build_cache as _build_cache
import _reference as _reference
import _registry as _registry
import _image as _image


## Constants ##

# Internal library of manifests, e.g. for “FROM scratch” (issue #1013).
manifests_internal = {
   "scratch": {  # magic empty image
      "schemaVersion": 2,
      "config": { "digest": None },
      "layers": []
   }
}


## Main ##

def main(cli):
   # Set things up.
   src_ref = _reference.Reference(cli.source_ref)
   dst_ref = src_ref if cli.dest_ref is None else _reference.Reference(cli.dest_ref)
   if (cli.parse_only):
      print(src_ref.as_verbose_str)
      _clearly.exit(0)
   if (_clearly.xattrs_save):
      _clearly.WARNING("--xattrs unsupported for “clearly image pull” (see FAQ)")
   dst_img = _image.Image(dst_ref)
   _clearly.INFO("pulling image:    %s" % src_ref)
   if (src_ref != dst_ref):
      _clearly.INFO("destination:      %s" % dst_ref)
   _clearly.INFO("requesting arch:  %s" % _clearly.arch)
   _build_cache.cache.pull_eager(dst_img, src_ref, cli.last_layer)
   _clearly.done_notify()


## Classes ##

class Image_Puller:

   __slots__ = ("architectures",  # key: architecture, value: manifest digest
                "config_hash",
                "digests",
                "image",
                "layer_hashes",
                "registry",
                "sid_input",
                "src_ref")

   def __init__(self, image, src_ref):
      self.architectures = None
      self.config_hash = None
      self.digests = dict()
      self.image = image
      self.layer_hashes = None
      self.registry = _registry.HTTP(src_ref)
      self.sid_input = None
      self.src_ref = src_ref

   @property
   def config_path(self):
      if (self.config_hash is None):
         return None
      else:
         return _clearly.storage.download_cache // (self.config_hash + ".json")

   @property
   def fatman_path(self):
      return _clearly.storage.fatman_for_download(self.image.ref)

   @property
   def manifest_path(self):
      if (str(self.image.ref) in manifests_internal):
         return "[internal library]"
      else:
         if (_clearly.arch == "yolo" or self.architectures is None):
            digest = None
         else:
            digest = self.architectures[_clearly.arch]
         return _clearly.storage.manifest_for_download(self.image.ref, digest)

   def done(self):
      self.registry.close()

   def download(self):
      "Download image metadata and layers and put them in the download cache."
      # Spec: https://docs.docker.com/registry/spec/manifest-v2-2/
      _clearly.VERBOSE("downloading image: %s" % self.image)
      have_skinny = False
      try:
         # fat manifest
         if (_clearly.arch != "yolo"):
            try:
               self.fatman_load()
               if (not self.architectures.in_warn(_clearly.arch)):
                  _clearly.FATAL("requested arch unavailable: %s" % _clearly.arch,
                           ("available: %s"
                            % " ".join(sorted(self.architectures.keys()))))
            except _clearly.No_Fatman_Error:
               # currently, this error is only raised if we’ve downloaded the
               # skinny manifest.
               have_skinny = True
               if (_clearly.arch == "amd64"):
                  # We’re guessing that enough arch-unaware images are amd64 to
                  # barge ahead if requested architecture is amd64.
                  _clearly.arch = "yolo"
                  _clearly.WARNING("image is architecture-unaware")
                  _clearly.WARNING("requested arch is amd64; using --arch=yolo")
               else:
                  _clearly.FATAL("image is architecture-unaware",
                           "consider --arch=yolo")
         # manifest
         self.manifest_load(have_skinny)
      except _clearly.Image_Unavailable_Error:
         if (_clearly.user() == "qwofford"):
            h = "Quincy, use --auth!!"
         else:
            h = "if your registry needs authentication, use --auth"
         _clearly.FATAL("unauthorized or not in registry: %s" % self.registry.ref, h)
      # config
      _clearly.VERBOSE("config path: %s" % self.config_path)
      if (self.config_path is not None):
         if (os.path.exists(self.config_path) and _clearly.dlcache_p):
            _clearly.INFO("config: using existing file")
         else:
            self.registry.blob_to_file(self.config_hash, self.config_path,
                                       "config: downloading")
      # layers
      for (i, lh) in enumerate(self.layer_hashes, start=1):
         path = self.layer_path(lh)
         _clearly.VERBOSE("layer path: %s" % path)
         msg = "layer %d/%d: %s" % (i, len(self.layer_hashes), lh[:7])
         if (os.path.exists(path) and _clearly.dlcache_p):
            _clearly.INFO("%s: using existing file" % msg)
         else:
            self.registry.blob_to_file(lh, path, "%s: downloading" % msg)
      # done
      self.registry.close()

   def error_decode(self, data):
      """Decode first error message in registry error blob and return a tuple
         (code, message)."""
      try:
         code = data["errors"][0]["code"]
         msg = data["errors"][0]["message"]
      except (IndexError, KeyError):
         _clearly.FATAL("malformed error data", "yes, this is ironic")
      return (code, msg)

   def fatman_load(self):
      """Download the fat manifest and load it. If the image has a fat manifest
         populate self.architectures; this may be an empty dictionary if no
         valid architectures were found.

         Raises:

           * Image_Unavailable_Error if the image does not exist or we are not
             authorized to have it.

           * No_Fatman_Error if the image exists but has no fat manifest,
             i.e., is architecture-unaware. In this case self.architectures is
             set to None."""
      self.architectures = None
      if (str(self.src_ref) in manifests_internal):
         # cheat; internal manifest library matches every architecture
         self.architectures = _clearly.Arch_Dict({ _clearly.arch_host: None })
         # Assume that image has no digest. This is a kludge, but it makes my
         # solution to issue #1365 work so ¯\_(ツ)_/¯
         self.digests[_clearly.arch_host] = "no digest"
         return
      # raises Image_Unavailable_Error if needed
      self.registry.fatman_to_file(self.fatman_path,
                                   "manifest list: downloading")
      fm = self.fatman_path.json_from_file("fat manifest")
      if ("layers" in fm or "fsLayers" in fm):
         # Check for skinny manifest. If not present, create a symlink to the
         # “fat manifest” with the conventional name for a skinny manifest.
         # This works because the file we just saved as the “fat manifest” is
         # actually a misleadingly named skinny manifest. Link is relative to
         # avoid embedding the storage directory path within the storage
         # directory (see PR #1657).
         if (not self.manifest_path.exists()):
            self.manifest_path.symlink_to(self.fatman_path.name)
         raise _clearly.No_Fatman_Error()
      if ("errors" in fm):
         # fm is an error blob.
         (code, msg) = self.error_decode(fm)
         if (code == "MANIFEST_UNKNOWN"):
            _clearly.INFO("manifest list: no such image")
            return
         else:
            _clearly.FATAL("manifest list: error: %s" % msg)
      self.architectures = _clearly.Arch_Dict()
      if ("manifests" not in fm):
         _clearly.FATAL("manifest list has no key 'manifests'")
      for m in fm["manifests"]:
         try:
            if (m["platform"]["os"] != "linux"):
               continue
            arch = m["platform"]["architecture"]
            if ("variant" in m["platform"]):
               arch = "%s/%s" % (arch, m["platform"]["variant"])
            digest = m["digest"]
         except KeyError:
            _clearly.FATAL("manifest lists missing a required key")
         if (arch in self.architectures):
            _clearly.FATAL("manifest list: duplicate architecture: %s" % arch)
         self.architectures[arch] = _clearly.digest_trim(digest)
         self.digests[arch] = digest.split(":")[1]
      if (len(self.architectures) == 0):
         _clearly.WARNING("no valid architectures found")

   def layer_path(self, layer_hash):
      "Return the path to tarball for layer layer_hash."
      return _clearly.storage.download_cache // (layer_hash + ".tar.gz")

   def manifest_digest_by_arch(self):
      "Return skinny manifest digest for target architecture."
      fatman  = self.fat_manifest_path.json_from_file()
      arch    = None
      digest  = None
      variant = None
      try:
         arch, variant = _clearly.arch.split("/", maxsplit=1)
      except ValueError:
         arch = _clearly.arch
      if ("manifests" not in fatman):
         _clearly.FATAL("manifest list has no manifests")
      for k in fatman["manifests"]:
         if (k.get('platform').get('os') != 'linux'):
            continue
         elif (    k.get('platform').get('architecture') == arch
               and (   variant is None
                    or k.get('platform').get('variant') == variant)):
            digest = k.get('digest')
      if (digest is None):
         _clearly.FATAL("arch not found for image: %s" % arch,
                  'try "clearly image list IMAGE_REF"')
      return digest

   def manifest_load(self, have_skinny=False):
      """Download the manifest file, parse it, and set self.config_hash and
         self.layer_hashes. If the image does not exist,
         exit with error."""
      def bad_key(key):
         _clearly.FATAL("manifest: %s: no key: %s" % (self.manifest_path, key))
      self.config_hash = None
      self.layer_hashes = None
      # obtain the manifest
      try:
         # internal manifest library, e.g. for “FROM scratch”
         manifest = manifests_internal[str(self.src_ref)]
         _clearly.INFO("manifest: using internal library")
      except KeyError:
         # download the file and parse it
         if (_clearly.arch == "yolo" or self.architectures is None):
            digest = None
         else:
            digest = self.architectures[_clearly.arch]
         _clearly.DEBUG("manifest digest: %s" % digest)
         if (not have_skinny):
            self.registry.manifest_to_file(self.manifest_path,
                                          "manifest: downloading",
                                          digest=digest)
         manifest = self.manifest_path.json_from_file("manifest")
      # validate schema version
      try:
         version = manifest['schemaVersion']
      except KeyError:
         bad_key("schemaVersion")
      if (version not in {1,2}):
         _clearly.FATAL("unsupported manifest schema version: %s" % repr(version))
      # load config hash
      #
      # FIXME: Manifest version 1 does not list a config blob. It does have
      # things (plural) that look like a config at history/v1Compatibility as
      # an embedded JSON string :P but I haven’t dug into it.
      if (version == 1):
         _clearly.VERBOSE("no config; manifest schema version 1")
         self.config_hash = None
      else:  # version == 2
         try:
            self.config_hash = manifest["config"]["digest"]
            if (self.config_hash is not None):
               self.config_hash = _clearly.digest_trim(self.config_hash)
         except KeyError:
            bad_key("config/digest")
      # load layer hashes
      if (version == 1):
         key1 = "fsLayers"
         key2 = "blobSum"
      else:  # version == 2
         key1 = "layers"
         key2 = "digest"
      if (key1 not in manifest):
         bad_key(key1)
      self.layer_hashes = list()
      for i in manifest[key1]:
         if (key2 not in i):
            bad_key("%s/%s" % (key1, key2))
         self.layer_hashes.append(_clearly.digest_trim(i[key2]))
      if (version == 1):
         self.layer_hashes.reverse()
      # Remember State_ID input. We can’t rely on the manifest existing in
      # serialized form (e.g. for internal manifests), so re-serialize.
      self.sid_input = json.dumps(manifest, sort_keys=True)

   def unpack(self, last_layer=None):
      layer_paths = [self.layer_path(h) for h in self.layer_hashes]
      _build_cache.cache.unpack_delete(self.image, missing_ok=True)
      self.image.unpack(layer_paths, last_layer)
      self.image.metadata_replace(self.config_path)
      # Check architecture we got. This is limited because image metadata does
      # not store the variant. Move fast and break things, I guess.
      arch_image = self.image.metadata["arch"] or "unknown"
      arch_short = _clearly.arch.split("/")[0]
      arch_host_short = _clearly.arch_host.split("/")[0]
      if (arch_image != "unknown" and arch_image != arch_host_short):
         host_mismatch = " (may not match host %s)" % _clearly.arch_host
      else:
         host_mismatch = ""
      _clearly.INFO("image arch: %s%s" % (arch_image, host_mismatch))
      if (_clearly.arch != "yolo" and arch_short != arch_image):
         _clearly.WARNING("image architecture does not match requested: %s ≠ %s"
                    % (_clearly.arch, arch_image))
