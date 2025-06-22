import json
import os.path

import _image as image
import _clearly as clearly
import _registry as registry
import _version as version
import _reference as reference

## Main ##

def main(cli):
   src_ref = reference.Reference(cli.source_ref)
   clearly.INFO("pushing image:   %s" % src_ref)
   img = image.Image(src_ref, cli.image)
   # FIXME: validate it's an image using Megan's new function (PR #908)
   if (not os.path.isdir(img.unpack_path)):
      if (cli.image is not None):
         clearly.FATAL("can’t push: %s does not appear to be an image" % cli.image)
      else:
         clearly.FATAL("can’t push: no image %s" % src_ref)
   if (cli.image is not None):
      clearly.INFO("image path:      %s" % img.unpack_path)
   else:
      clearly.VERBOSE("image path:      %s" % img.unpack_path)
   if (cli.dest_ref is not None):
      dst_ref = reference.Reference(cli.dest_ref)
      clearly.INFO("destination:     %s" % dst_ref)
   else:
      dst_ref = reference.Reference(cli.source_ref)
   up = Image_Pusher(img, dst_ref)
   up.push()
   clearly.done_notify()


## Classes ##

class Image_Pusher:

   # Note; We use functions to create the blank config and manifest to to
   # avoid copy/deepcopy complexity from just copying a default dict.

   __slots__ = ("config",    # sequence of bytes
                "dst_ref",   # destination of upload
                "image",     # Image object we are uploading
                "layers",    # list of (digest, .tar.gz path), lowest first
                "manifest",  # sequence of bytes
                "registry")  # destination registry

   def __init__(self, image, dst_ref):
      self.config = None
      self.dst_ref = dst_ref
      self.image = image
      self.layers = None
      self.manifest = None
      self.registry = None

   @classmethod
   def config_new(class_):
      "Return an empty config, ready to be filled in."
      # FIXME: URL of relevant docs?
      # FIXME: tidy blank/empty fields?
      return { "architecture": clearly.arch_host_get(),
               "charliecloud_version": version.VERSION,
               "comment": "pushed with Clearstack",
               "config": {},
               "container_config": {},
               "created": clearly.now_utc_iso8601(),
               "history": [],
               "os": "linux",
               "rootfs": { "diff_ids": [], "type": "layers" },
               "weirdal": "yankovic" }

   @classmethod
   def manifest_new(class_):
      "Return an empty manifest, ready to be filled in."
      return { "schemaVersion": 2,
               "mediaType": registry.TYPES_MANIFEST["docker2"],
               "config": { "mediaType": registry.TYPE_CONFIG,
                           "size": None,
                           "digest": None },
               "layers": [],
               "weirdal": "yankovic" }

   def cleanup(self):
      clearly.INFO("cleaning up")
      # Delete the tarballs since we can’t yet cache them.
      for (_, tar_c) in self.layers:
         clearly.VERBOSE("deleting tarball: %s" % tar_c)
         tar_c.unlink()

   def prepare(self):
      """Prepare self.image for pushing to self.dst_ref. Return tuple: (list
         of gzipped layer tarball paths, config as a sequence of bytes,
         manifest as a sequence of bytes).

         There is not currently any support for re-using any previously
         prepared files already in the upload cache, because we don’t yet have
         a way to know if these have changed until they are already build."""
      # Initializing an HTTP instance for the registry and doing a 'GET'
      # request right out the gate ensures the user needs to authenticate
      # before we prepare the image for upload (#1426).
      self.registry = registry.HTTP(self.dst_ref)
      self.registry.request("GET", self.registry._url_base)
      tars_uc = self.image.tarballs_write(clearly.storage.upload_cache)
      tars_c = list()
      config = self.config_new()
      manifest = self.manifest_new()
      # Prepare layers.
      for (i, tar_uc) in enumerate(tars_uc, start=1):
         clearly.INFO("layer %d/%d: preparing" % (i, len(tars_uc)))
         path_uc = clearly.storage.upload_cache // tar_uc
         hash_uc = path_uc.file_hash()
         config["rootfs"]["diff_ids"].append("sha256:" + hash_uc)
         size_uc = path_uc.file_size()
         path_c = path_uc.file_gzip(["-9", "--no-name"])
         tar_c = path_c.name
         hash_c = path_c.file_hash()
         size_c = path_c.file_size()
         tars_c.append((hash_c, path_c))
         manifest["layers"].append({ "mediaType": registry.TYPE_LAYER,
                                     "size": size_c,
                                     "digest": "sha256:" + hash_c })
      # Prepare metadata.
      clearly.INFO("preparing metadata")
      self.image.metadata_load()
      # Environment. Note that this is *not* a dictionary for some reason but
      # a list of name/value pairs separated by equals [1], with no quoting.
      #
      # [1]: https://github.com/opencontainers/image-spec/blob/main/config.md
      config['config']['Env'] = ["%s=%s" % (k, v)
                                 for k, v
                                 in self.image.metadata.get("env", {}).items()]
      # History. Some registries, e.g., Quay, use history metadata for simple
      # sanity checks. For example, when an image’s number of "empty_layer"
      # history entries doesn’t match the number of layers being uploaded,
      # Quay will reject the image upload.
      #
      # This type of error checking is odd as the empty_layer key is optional
      # (https://github.com/opencontainers/image-spec/blob/main/config.md).
      #
      # Thus, to push images built (or pulled) with Clearstack we ensure the
      # the total number of non-empty layers always totals one (1). To do this
      # we iterate over the history entires backward searching for the first
      # non-empty entry and preserve it; all others are set to empty.
      hist = self.image.metadata["history"]
      non_empty_winner = None
      for i in range(len(hist) - 1, -1, -1):
         if (   "empty_layer" not in hist[i].keys()
             or (    "empty_layer" in hist[i].keys()
                 and not hist[i]["empty_layer"])):
            non_empty_winner = i
            break
      assert(non_empty_winner is not None)
      for i in range(len(hist) - 1):
         if (i != non_empty_winner):
            hist[i]["empty_layer"] = True
      config["history"] = hist
      # Pack it up to go.
      config_bytes = json.dumps(config, indent=2).encode("UTF-8")
      config_hash = clearly.bytes_hash(config_bytes)
      manifest["config"]["size"] = len(config_bytes)
      manifest["config"]["digest"] = "sha256:" + config_hash
      clearly.DEBUG("config: %s\n%s" % (config_hash, config_bytes.decode("UTF-8")))
      manifest_bytes = json.dumps(manifest, indent=2).encode("UTF-8")
      clearly.DEBUG("manifest:\n%s" % manifest_bytes.decode("UTF-8"))
      # Store for the next steps.
      self.layers = tars_c
      self.config = config_bytes
      self.manifest = manifest_bytes

   def push(self):
      self.prepare()
      self.upload()
      self.cleanup()

   def upload(self):
      clearly.INFO("starting upload")
      for (i, (digest, tarball)) in enumerate(self.layers, start=1):
         self.registry.layer_from_file(digest, tarball,
                                 "layer %d/%d: " % (i, len(self.layers)))
      self.registry.config_upload(self.config)
      self.registry.manifest_upload(self.manifest)
      self.registry.close()
