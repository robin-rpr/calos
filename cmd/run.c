/* Copyright © Triad National Security, LLC, and others. */

/* Note: This program does not bother to free memory allocations, since they
   are modest and the program is short-lived. */

#define _GNU_SOURCE
#include <argp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <json-c/json.h>

#include "config.h"
#include "core.h"
#include "misc.h"


/** Constants and macros **/

/* Environment variables used by --join parameters. */
char *JOIN_CT_ENV[] =  { "OMPI_COMM_WORLD_LOCAL_SIZE",
                         "SLURM_STEP_TASKS_PER_NODE",
                         "SLURM_CPUS_ON_NODE",
                         NULL };
char *JOIN_TAG_ENV[] = { "SLURM_STEP_ID",
                         NULL };

/* Default overlaid tmpfs size. */
char *WRITE_FAKE_DEFAULT = "12%";


/** Command line options **/

const char usage[] = "\
\n\
Run a command in a Clearly container.\n\
\v\
Example:\n\
\n\
  $ clearly run /data/foo -- echo hello\n\
  hello\n\
\n\
You cannot use this program to actually change your UID.\n";

const char args_doc[] = "IMAGE -- COMMAND [ARG...]";

/* Note: Long option numbers, once issued, are permanent; i.e., if you remove
   one, don’t re-number the others. */
const struct argp_option options[] = {
   { "allow",         'a', "DST",           0, "allow egress traffic to peer container DST" },
   { "bind",          'b', "SRC[:DST]",     0, "mount SRC at guest DST (default: same as SRC)" },
   { "cd",            'c', "DIR",           0, "initial working directory in container" },
   { "detach",        'd', 0,               0, "detach the container into the background" },
   { "env-no-expand", -8,  0,               0, "don't expand $ in --env input" },
   { "feature",       -9, "FEAT",           0, "exit successfully if FEAT is enabled" },
   { "gid",           'g', "GID",           0, "run as GID within container" },
   { "home",          -10, 0,               0, "mount host $HOME at guest /home/$USER" },
   { "host",          'h', "SRC:DST",       0, "map SRC at guest DST (e.g. google.com:1.2.3.4)" },
   { "join",          'j', 0,               0, "use same container as peer clearly run" },
   { "join-pid",       -5, "PID",           0, "join a namespace using a PID" },
   { "join-ct",        -3, "N",             0, "number of join peers (implies --join)" },
   { "join-tag",       -4, "TAG",           0, "label for peer group (implies --join)" },
   { "test",          -13, "TEST",          0, "do 'clearly test' TEST" },
   { "mount",         'm', "DIR",           0, "SquashFS mount point" },
   { "name",          -18, "NAME",          0, "assign a name to the container" },
   { "passwd",         -7, 0,               0, "bind-mount /etc/{passwd,group}" },
   { "overlay-size",  'o', "SIZE", OPTION_ARG_OPTIONAL,
                           "overlay read-write tmpfs size on top of image" },
   { "publish",       'p', "[NET:]SRC:DST", 0,
                           "forward host port [NET:]SRC to container port DST" },
   { "pids-max",      -14, "N",             0, "maximum number of PIDs" },
   { "cpu-weight",    -15, "WEIGHT",        0, "CPU weight" },
   { "memory-max",    -16, "BYTES",         0, "memory limit" },
   { "cpus",          -17, "N",             0, "number of CPUs" },
   { "private-tmp",   't', 0,               0, "use container-private /tmp" },
   { "quiet",         'q', 0,               0, "print less output (can be repeated)" },
   { "env",           'e', "ARG",           0,
                           "set env. variables per ARG (newline-delimited)" },
   { "runtime",       'r', "DIR",           0, "set DIR as runtime directory" },
   { "storage",       's', "DIR",           0, "set DIR as storage directory" },
   { "uid",           'u', "UID",           0, "run as UID within container" },
   { "unsafe",        -11, 0,               0, "do unsafe things (internal use only)" },
   { "unset-env",      -6, "GLOB",          0, "unset environment variable(s)" },
   { "verbose",       'v', 0,               0, "be more verbose (can be repeated)" },
   { "warnings",      -12, "NUM",           0, "log NUM warnings and exit" },
   { "write",         'w', 0,               0, "mount image read-write (avoid)"},
   { 0 }
};


/** Types **/

struct args {
   struct container c;
   struct json_object *pulled_config;
   struct env_delta *env_deltas;
   struct env_var *env_vars;
   char *initial_dir;
   char *runtime_dir;
   char *storage_dir;
   bool unsafe;
};


/** Function prototypes **/

void fix_environment(struct args *args);
bool get_first_env(char **array, char **name, char **value);
void img_directory_verify(const char *img_path, const struct args *args);
int join_ct(int cli_ct);
char *join_tag(char *cli_tag);
int uid(struct json_object *config);
char **command(struct json_object *config);
char *initial_dir(struct json_object *config);
struct env_var *env_vars(struct json_object *config);
int parse_int(char *s, bool extra_ok, char *error_tag);
static error_t parse_opt(int key, char *arg, struct argp_state *state);
void parse_set_env(struct args *args, char *arg, int delim);
struct json_object *parse_config(const char *image_path);
void privs_verify_invoking();
char *runtime_default(void);
char *storage_default(void);
extern void warnings_reprint(void);


/** Global variables **/

const struct argp argp = { options, parse_opt, args_doc, usage };
extern char **environ; // see environ(7)
extern char *warnings;


/** Main **/

int main(int argc, char *argv[])
{
   bool argp_help_fmt_set;
   struct args args;
   int arg_next;
   char ** c_argv;

   // initialize “warnings” buffer
   warnings = mmap(NULL, WARNINGS_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   T_ (warnings != MAP_FAILED);

   privs_verify_invoking();
   username_set();

   // Create cgroup parent directory if it doesn't exist
   if (mkdir("/sys/fs/cgroup/clearly", 0755) && errno != EEXIST)
      Zf(1, "can't create cgroup parent directory");

   // Create runtime directory if it doesn't exist
   char *runtime_dir = runtime_default();
   if (mkdir(runtime_dir, 0755) && errno != EEXIST)
      Zf(1, "can't create runtime directory: %s", runtime_dir);

   Z_ (atexit(warnings_reprint));

#ifdef ENABLE_SYSLOG
   syslog(LOG_USER|LOG_INFO, "uid=%u args=%d: %s", getuid(), argc,
          argv_to_string(argv));
#endif

   verbose = LL_INFO;  // in misc.c
   args = (struct args){
      .c = (struct container){ .cgroup_pids_max = 0,
                               .cgroup_cpu_weight = NULL,
                               .cgroup_memory_max = NULL,
                               .cgroup_cpu_max = NULL,
                               .allow_map_strs = list_new(sizeof(char *), 0),
                               .binds = list_new(sizeof(struct bind), 0),
                               .gid = getegid(),
                               .uid = geteuid(),
                               .command = NULL,
                               .detached = false,
                               .name = NULL,
                               .env_expand = true,
                               .host_home = NULL,
                               .host_map_strs = list_new(sizeof(char *), 0),
                               .img_ref = NULL,
                               .newroot = NULL,
                               .join = false,
                               .join_ct = 0,
                               .join_pid = 0,
                               .join_tag = NULL,
                               .overlay_size = WRITE_FAKE_DEFAULT,
                               .publish_map_strs = list_new(sizeof(char *), 0),
                               .public_passwd = false,
                               .private_tmp = false,
                               .type = IMG_NONE,
                               .writable = false },
      .pulled_config = json_object_new_object(),
      .env_deltas = list_new(sizeof(struct env_delta), 0),
      .env_vars = NULL,
      .initial_dir = NULL,
      .runtime_dir = runtime_default(),
      .storage_dir = storage_default(),
      .unsafe = false };

   /* I couldn't find a way to set argp help defaults other than this
      environment variable. Kludge sets/unsets only if not already set. */
   if (getenv("ARGP_HELP_FMT"))
      argp_help_fmt_set = true;
   else {
      argp_help_fmt_set = false;
      Z_ (setenv("ARGP_HELP_FMT", "opt-doc-col=27,no-dup-args-note", 0));
   }
   Z_ (argp_parse(&argp, argc, argv, 0, &arg_next, &args));
   if (!argp_help_fmt_set)
      Z_ (unsetenv("ARGP_HELP_FMT"));

   if (args.c.detached) {
      Tf(args.c.name, "--detach requires --name to be set");
      char *state_dir_path;
      T_ (1 <= asprintf(&state_dir_path, "/var/lib/clearly/containers/%s", args.c.name));
      if (path_exists(state_dir_path, NULL, false)) {
         FATAL(0, "container with name '%s' already exists", args.c.name);
      }
      free(state_dir_path);
   }

   if (arg_next >= argc) {
      printf("Usage: run [OPTION...] IMAGE -- COMMAND [ARG...]\n");
      FATAL(0, "IMAGE not specified");
   }
   args.c.img_ref = argv[arg_next++];
   args.c.newroot = realpath_(args.c.newroot, true);
   args.storage_dir = realpath_(args.storage_dir, true);
   args.runtime_dir = realpath_(args.runtime_dir, true);
   args.c.type = image_type(args.c.img_ref, args.storage_dir);

   switch (args.c.type) {
   case IMG_DIRECTORY:
      if (args.c.newroot != NULL)  // --mount was set
         WARNING("--mount invalid with directory image, ignoring");
      args.c.newroot = realpath_(args.c.img_ref, false);
      img_directory_verify(args.c.newroot, &args);
      break;
   case IMG_NAME:
      args.c.newroot = img_name2path(args.c.img_ref, args.storage_dir);
      Tf (!args.c.writable || args.unsafe,
          "--write invalid when running by name");
      break;
   case IMG_SQUASH:
#ifndef HAVE_LIBSQUASHFUSE
      FATAL(0, "this run does not support internal SquashFS mounts");
#endif
      break;
   case IMG_NONE:
      FATAL(0, "unknown image type: %s", args.c.img_ref);
      break;
   }

   // Parse the config file from the image.
   args.pulled_config = parse_config(args.c.newroot);

   if (args.pulled_config) {
      // Set the container UID and GID.
      args.c.uid = uid(args.pulled_config);
      args.c.gid = args.c.uid;

      // Set the container command.
      args.c.command = command(args.pulled_config);

      // Set the container workdir.
      args.initial_dir = initial_dir(args.pulled_config);

      // Set the container environment variables.
      args.env_vars = env_vars(args.pulled_config);
   }

   if (args.c.join) {
      args.c.join_ct = join_ct(args.c.join_ct);
      args.c.join_tag = join_tag(args.c.join_tag);
   }

   if (getenv("TMPDIR") != NULL)
      host_tmp = getenv("TMPDIR");
   else
      host_tmp = "/tmp";

   if (arg_next >= argc) {
      // Use default command from image metadata
      char **default_cmd = args.c.command;
      Zf(default_cmd == NULL, "no command specified");
      c_argv = default_cmd;
   } else {
      // Use command from command line
      c_argv = list_new(sizeof(char *), argc - arg_next);
      for (int i = 0; i < argc - arg_next; i++)
         c_argv[i] = argv[i + arg_next];
   }

   VERBOSE("verbosity: %d", verbose);
   VERBOSE("image: %s", args.c.img_ref);
   VERBOSE("storage: %s", args.storage_dir);
   VERBOSE("runtime: %s", args.runtime_dir);
   VERBOSE("newroot: %s", args.c.newroot);
   VERBOSE("container uid: %u", args.c.uid);
   VERBOSE("container gid: %u", args.c.gid);
   VERBOSE("join: %d %d %s %d", args.c.join, args.c.join_ct, args.c.join_tag,
           args.c.join_pid);
   VERBOSE("private /tmp: %d", args.c.private_tmp);
   VERBOSE("unsafe: %d", args.unsafe);

   containerize(&args.c, args.runtime_dir);
   fix_environment(&args);
#ifdef HAVE_SECCOMP
   seccomp_install();
#endif
   run_command(c_argv, args.initial_dir);
   exit(EXIT_FAILURE);
}


/** Supporting functions **/

void fix_environment(struct args *args)
{
   char *old_value, *new_value;

   // $HOME: If --home, set to “/home/$USER”.
   if (args->c.host_home) {
      Z_ (setenv("HOME", cat("/home/", username), 1));
   } else if (path_exists("/root", NULL, true)) {
      Z_ (setenv("HOME", "/root", 1));
   } else
      Z_ (setenv("HOME", "/", 1));

   // $PATH: Append /bin if not already present.
   old_value = getenv("PATH");
   if (old_value == NULL) {
      WARNING("$PATH not set");
   } else if (   strstr(old_value, "/bin") != old_value
              && !strstr(old_value, ":/bin")) {
      T_ (1 <= asprintf(&new_value, "%s:/bin", old_value));
      Z_ (setenv("PATH", new_value, 1));
      VERBOSE("new $PATH: %s", new_value);
   }

   // $TMPDIR: Unset.
   Z_ (unsetenv("TMPDIR"));

   // Environment variables from config.
   if (args->env_vars) {
      for (size_t i = 0; args->env_vars[i].name != NULL; i++) {
         env_set(args->env_vars[i].name, args->env_vars[i].value,
                 args->c.env_expand);
      }
   }

   // --env and --unset-env.
   for (size_t i = 0; args->env_deltas[i].action != ENV_END; i++) {
      struct env_delta ed = args->env_deltas[i];
      switch (ed.action) {
      case ENV_END:
         Te (false, "unreachable code reached");
         break;
      case ENV_SET_DEFAULT:
         ed.arg.vars = env_file_read("/clearly/environment", ed.arg.delim);
         // fall through
      case ENV_SET_VARS:
         for (size_t j = 0; ed.arg.vars[j].name != NULL; j++)
            env_set(ed.arg.vars[j].name, ed.arg.vars[j].value,
                    args->c.env_expand);
         break;
      case ENV_UNSET_GLOB:
         env_unset(ed.arg.glob);
         break;
      }
   }

   // $CLEARLY_RUNNING is not affected by --unset-env or --env.
   Z_ (setenv("CLEARLY_RUNNING", "Weird Al Yankovic", 1));
}

/* Find the first environment variable in array that is set; put its name in
   *name and its value in *value, and return true. If none are set, return
   false, and *name and *value are undefined. */
bool get_first_env(char **array, char **name, char **value)
{
   for (int i = 0; array[i] != NULL; i++) {
      *name = array[i];
      *value = getenv(*name);
      if (*value != NULL)
         return true;
   }

   return false;
}

/* Validate that it’s OK to run the IMG_DIRECTORY format image at path; if
   not, exit with error. */
void img_directory_verify(const char *newroot, const struct args *args)
{
   Te (args->c.newroot != NULL, "can't find image: %s", args->c.newroot);
   Te (args->unsafe || !path_subdir_p(args->storage_dir, args->c.newroot),
       "can't run directory images from storage (hint: run by name)");
}

/* Find an appropriate join count; assumes --join was specified or implied.
   Exit with error if no valid value is available. */
int join_ct(int cli_ct)
{
   int j = 0;
   char *ev_name, *ev_value;

   if (cli_ct != 0) {
      VERBOSE("join: peer group size from command line");
      j = cli_ct;
      goto end;
   }

   if (get_first_env(JOIN_CT_ENV, &ev_name, &ev_value)) {
      VERBOSE("join: peer group size from %s", ev_name);
      j = parse_int(ev_value, true, ev_name);
      goto end;
   }

end:
   Te(j > 0, "join: no valid peer group size found");
   return j;
}

/* Find an appropriate join tag; assumes --join was specified or implied. Exit
   with error if no valid value is found. */
char *join_tag(char *cli_tag)
{
   char *tag;
   char *ev_name, *ev_value;

   if (cli_tag != NULL) {
      VERBOSE("join: peer group tag from command line");
      tag = cli_tag;
      goto end;
   }

   if (get_first_env(JOIN_TAG_ENV, &ev_name, &ev_value)) {
      VERBOSE("join: peer group tag from %s", ev_name);
      tag = ev_value;
      goto end;
   }

   VERBOSE("join: peer group tag from getppid(2)");
   T_ (1 <= asprintf(&tag, "%d", getppid()));

end:
   Te(tag[0] != '\0', "join: peer group tag cannot be empty string");
   return tag;
}

/* Get the container UID */
int uid(struct json_object *config)
{
   struct json_object *user = NULL;
   json_object_object_get_ex(config, "User", &user);
   return json_object_get_int(user);
}

/* Get the container command */
char **command(struct json_object *config)
{
    struct json_object *ep = NULL, *cmd = NULL;
    json_object_object_get_ex(config, "Entrypoint", &ep);
    json_object_object_get_ex(config, "Cmd", &cmd);

    size_t n = ep ? json_object_array_length(ep) : 0;
    size_t m = cmd ? json_object_array_length(cmd) : 0;

    char **result = list_new(sizeof(char *), n + m + 1);
    for (size_t i = 0; i < n; i++)
        result[i] = strdup(json_object_get_string(json_object_array_get_idx(ep, i)));
    for (size_t i = 0; i < m; i++)
        result[n + i] = strdup(json_object_get_string(json_object_array_get_idx(cmd, i)));

    result[n + m] = NULL;
    return result;
}

/* Get the container workdir */
char *initial_dir(struct json_object *config)
{
    struct json_object *wd = NULL;
    json_object_object_get_ex(config, "WorkingDir", &wd);
    return (char *)json_object_get_string(wd);
}

/* Get environment variables from config */
struct env_var *env_vars(struct json_object *config)
{
    struct json_object *env = NULL;
    if (!json_object_object_get_ex(config, "Env", &env) || !env) {
        return NULL;
    }

    size_t env_count = json_object_array_length(env);
    struct env_var *result = list_new(sizeof(struct env_var), env_count + 1);

    for (size_t i = 0; i < env_count; i++) {
        const char *env_str = json_object_get_string(json_object_array_get_idx(env, i));
        char *name = NULL, *value = NULL;

        if (env_str && strchr(env_str, '=')) {
            split(&name, &value, (char *)env_str, '=');
        }

        result[i].name = name ? strdup(name) : NULL;
        result[i].value = value ? strdup(value) : NULL;
    }

    result[env_count].name = NULL;
    return result;
}

/* Parse an integer string arg and return the result. If an error occurs,
   print a message prefixed by error_tag and exit. If not extra_ok, additional
   characters remaining after the integer are an error. */
int parse_int(char *s, bool extra_ok, char *error_tag)
{
   char *end;
   long l;

   errno = 0;
   l = strtol(s, &end, 10);
   Ze (end == s, "%s: no digits found", error_tag);
   Ze (errno == ERANGE || l < INT_MIN || l > INT_MAX,
       "%s: out of range", error_tag);
   Tf (errno == 0, error_tag);
   if (!extra_ok)
      Te (*end == 0, "%s: extra characters after digits", error_tag);
   return (int)l;
}

/* Parse one command line option. Called by argp_parse(). */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
   struct args *args = state->input;
   int i;

   switch (key) {
   case -3: // --join-ct
      args->c.join = true;
      args->c.join_ct = parse_int(arg, false, "--join-ct");
      break;
   case -4: // --join-tag
      args->c.join = true;
      args->c.join_tag = arg;
      break;
   case -5: // --join-pid
      args->c.join_pid = parse_int(arg, false, "--join-pid");
      break;
   case -6: { // --unset-env
        struct env_delta ed;
        Te (strlen(arg) > 0, "--unset-env: GLOB must have non-zero length");
        ed.action = ENV_UNSET_GLOB;
        ed.arg.glob = arg;
        list_append((void **)&(args->env_deltas), &ed, sizeof(ed));
      } break;
   case -7: // --passwd
      args->c.public_passwd = true;
      break;
   case -8: // --env-no-expand
      args->c.env_expand = false;
      break;
   case -9: // --feature
      if (!strcmp(arg, "extglob")) {
#ifdef HAVE_FNM_EXTMATCH
         exit(0);
#else
         exit(EXIT_MISC_ERR);
#endif
      } else if (!strcmp(arg, "overlayfs")) {
#ifdef HAVE_OVERLAYFS
         exit(0);
#else
         exit(1);
#endif
      } else if (!strcmp(arg, "seccomp")) {
#ifdef HAVE_SECCOMP
         exit(0);
#else
         exit(EXIT_MISC_ERR);
#endif
      } else if (!strcmp(arg, "squash")) {
#ifdef HAVE_LIBSQUASHFUSE
         exit(0);
#else
         exit(EXIT_MISC_ERR);
#endif
      } else if (!strcmp(arg, "tmpfs-xattrs")) {
#ifdef HAVE_TMPFS_XATTRS
         exit(0);
#else
         exit(1);
#endif
      }
      else
         FATAL(0, "unknown feature: %s", arg);
      break;
   case -10: // --home
      Tf (args->c.host_home = getenv("HOME"), "--home failed: $HOME not set");
      break;
   case -11: // --unsafe
      args->unsafe = true;
      break;
   case -12: // --warnings
      for (int i = 1; i <= parse_int(arg, false, "--warnings"); i++)
         WARNING("this is warning %d!", i);
      exit(0);
      break;
   case -13: // --test
      if (!strcmp(arg, "log"))
         test_logging(false);
      else if (!strcmp(arg, "log-fail"))
         test_logging(true);
      else
         FATAL(0, "invalid --test argument: %s; see source code", arg);
      break;
   case -14: // --pids-max
      args->c.cgroup_pids_max = parse_int(arg, false, "--pids-max");
      break;
   case -15: // --cpu-weight
      args->c.cgroup_cpu_weight = arg;
      break;
   case -16: // --memory-max
      args->c.cgroup_memory_max = arg;
      break;
   case -17: // --cpus
      args->c.cgroup_cpu_max = arg;
      break;
   case -18: // --name
      args->c.name = arg;
      break;
   case 'a': // --allow
      Ze(arg[0] == '\0', "allow mapping can't be empty string");
      list_append((void **)&(args->c.allow_map_strs), &arg, sizeof(char *));
      break;
   case 'b': { // --bind
         char *src, *dst;
         for (i = 0; args->c.binds[i].src != NULL; i++) // count existing binds
            ;
         T_ (args->c.binds = realloc(args->c.binds,
                                     (i+2) * sizeof(struct bind)));
         args->c.binds[i+1].src = NULL;                 // terminating zero
         args->c.binds[i].dep = BD_MAKE_DST;
         // source
         src = strsep(&arg, ":");
         T_ (src != NULL);
         Te (src[0] != 0, "--bind: no source provided");
         args->c.binds[i].src = src;
         // destination
         dst = arg ? arg : src;
         Te (dst[0] != 0, "--bind: no destination provided");
         Te (strcmp(dst, "/"), "--bind: destination can't be /");
         Te (dst[0] == '/', "--bind: destination must be absolute");
         args->c.binds[i].dst = dst;
      }
      break;
   case 'c':  // --cd
      args->initial_dir = arg;
      break;
   case 'd': // --detach
      args->c.detached = true;
      break;
   case 'e': // --env
      if (arg == NULL && state->next < state->argc && 
          strchr(state->argv[state->next], '=') != NULL) {
         arg = state->argv[state->next++];
      }
      parse_set_env(args, arg, '\n');
      break;
   case 'g':  // --gid
      i = parse_int(arg, false, "--gid");
      Te (i >= 0, "--gid: must be non-negative");
      args->c.gid = (gid_t) i;
      break;
   case 'h':  // --host
      Ze(arg[0] == '\0', "host mapping can't be empty string");
      list_append((void **)&(args->c.host_map_strs), &arg, sizeof(char *));
      break;
   case 'j':  // --join
      args->c.join = true;
      break;
   case 'm':  // --mount
      Ze ((arg[0] == '\0'), "mount point can't be empty string");
      args->c.newroot = arg;
      break;
   case 'r':  // --runtime
      args->runtime_dir = arg;
      if (!path_exists(arg, NULL, false))
         WARNING("runtime directory not found: %s", arg);
      break;
   case 's':  // --storage
      args->storage_dir = arg;
      if (!path_exists(arg, NULL, false))
         WARNING("storage directory not found: %s", arg);
      break;
   case 'q':  // --quiet
      Te(verbose <= 0, "--quiet incompatible with --verbose");
      verbose--;
      Te(verbose >= -3, "--quiet can be specified at most trice");
      break;
   case 't':  // --private-tmp
      args->c.private_tmp = true;
      break;
   case 'u':  // --uid
      i = parse_int(arg, false, "--uid");
      Te (i >= 0, "--uid: must be non-negative");
      args->c.uid = (uid_t) i;
      break;
   case 'v':  // --verbose
      Te(verbose >= 0, "--verbose incompatible with --quiet");
      verbose++;
      Te(verbose <= 3, "--verbose can be specified at most trice");
      break;
   case 'w':  // --write
      args->c.writable = true;
      break;
   case 'o':  // --overlay-size
      Ze(arg[0] == '\0', "overlay size can't be empty string");
      args->c.overlay_size = arg;
      break;
   case 'p':  // --publish
      Ze(arg[0] == '\0', "publish mapping can't be empty string");
      list_append((void **)&(args->c.publish_map_strs), &arg, sizeof(char *));
      break;
   case ARGP_KEY_NO_ARGS:
      argp_state_help(state, stderr, (  ARGP_HELP_SHORT_USAGE
                                      | ARGP_HELP_PRE_DOC
                                      | ARGP_HELP_LONG
                                      | ARGP_HELP_POST_DOC));
      exit(EXIT_FAILURE);
   default:
      return ARGP_ERR_UNKNOWN;
   };

   return 0;
}

void parse_set_env(struct args *args, char *arg, int delim)
{
   struct env_delta ed;

   if (arg == NULL) {
      ed.action = ENV_SET_DEFAULT;
      ed.arg.delim = delim;
   } else {
      ed.action = ENV_SET_VARS;
      if (strchr(arg, '=') == NULL)
         ed.arg.vars = env_file_read(arg, delim);
      else {
         ed.arg.vars = list_new(sizeof(struct env_var), 1);
         ed.arg.vars[0] = env_var_parse(arg, NULL, 0);
      }
   }
   list_append((void **)&(args->env_deltas), &ed, sizeof(ed));
}

struct json_object *parse_config(const char *image_path)
{
    char *config_path = NULL;
    FILE *fp;
    long len;
    char *json_buf = NULL;
    struct json_object *root = NULL;
    struct json_object *config = NULL;

    if (asprintf(&config_path, "%s/clearly/config.pulled.json", image_path) < 0)
        return NULL;
    fp = fopen(config_path, "r");
    free(config_path);    
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    json_buf = malloc(len + 1);
    if (!json_buf) {
        fclose(fp);
        return NULL;
    }
    if (fread(json_buf, 1, (size_t)len, fp) != (size_t)len) {
        fclose(fp);
        free(json_buf);
        return NULL;
    }
    json_buf[len] = '\0';
    fclose(fp);

    root = json_tokener_parse(json_buf);
    free(json_buf);

    if (!root)
        return NULL;

    json_object_object_get_ex(root, "config", &config);

    if (!config)
        return NULL;

    return config;
}


/* Validate that the UIDs and GIDs are appropriate for program start, and
   abort if not.

   Note: If the binary is setuid, then the real UID will be the invoking user
   and the effective and saved UIDs will be the owner of the binary.
   Otherwise, all three IDs are that of the invoking user. */
void privs_verify_invoking()
{
   uid_t ruid, euid, suid;
   gid_t rgid, egid, sgid;

   Z_ (getresuid(&ruid, &euid, &suid));
   Z_ (getresgid(&rgid, &egid, &sgid));

   // Calling the program if user is really root is OK.
   if (   ruid == 0 && euid == 0 && suid == 0
       && rgid == 0 && egid == 0 && sgid == 0)
      return;

   // Now that we know user isn't root, no GID privilege is allowed.
   T_ (egid != 0);                           // no privilege
   T_ (egid == rgid && egid == sgid);        // no setuid or funny business

   // No UID privilege allowed either.
   T_ (euid != 0);                           // no privilege
   T_ (euid == ruid && euid == suid);        // no setuid or funny business
}

/* Return path to the runtime directory, if -r is not specified. */
char *runtime_default(void)
{
   char *runtime = getenv("CLEARLY_RUNTIME_STORAGE");

   if (runtime == NULL)
      T_ (1 <= asprintf(&runtime, "/run/clearly"));

   return runtime;
}

/* Return path to the storage directory, if -s is not specified. */
char *storage_default(void)
{
   char *storage = getenv("CLEARLY_IMAGE_STORAGE");

   if (storage == NULL)
      T_ (1 <= asprintf(&storage, "/var/tmp/clearly"));

   return storage;
}