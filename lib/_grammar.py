# Common rules for all grammars.
GRAMMAR_COMMON = r"""
// Matching lines in the face of continuations is surprisingly hairy. Notes:
//
//   1. The underscore prefix means the rule is always inlined (i.e., removed
//      and children become children of its parent).
//
//   2. LINE_CHUNK must not match any characters that _LINE_CONTINUE does.
//
//   3. This is very sensitive to the location of repetition. Moving the plus
//      either to the entire regex (i.e., "/(...)+/") or outside the regex
//      (i.e., "/.../+") gave parse errors.
//
_line: ( _LINE_CONTINUE | LINE_CHUNK )+
LINE_CHUNK: /[^\\\n]+|(\\(?![ \t]+\n))+/

HEX_STRING: /[0-9A-Fa-f]+/
WORD: /[^ \t\n=]/+
WORDE: /[^ \t\n]/+

IR_PATH_COMPONENT: /[a-z0-9_.-]+/

_string_list: "[" _WS? STRING_QUOTED ( "," _WS? STRING_QUOTED )* _WS? "]"

_WSH: /[ \t]/+                   // sequence of horizontal whitespace
_LINE_CONTINUE: "\\" _WSH? "\n"  // line continuation
_WS: ( _WSH | _LINE_CONTINUE )+  // horizontal whitespace w/ line continuations
_NEWLINES: ( _WS? "\n" )+        // sequence of newlines

%import common.ESCAPED_STRING -> STRING_QUOTED
"""

# Dockerfile grammar. Note image references are not parsed during Dockerfile
# parsing.
GRAMMAR_DOCKERFILE = r"""
start: dockerfile

// First instruction must be ARG or FROM, but that is not a syntax error.
dockerfile: _NEWLINES? ( arg_first | directive | comment )* ( instruction | comment )*

?instruction: _WS? ( arg | copy | env | from_ | label | rsync | run | shell | workdir | uns_forever | uns_yet )

directive.2: _WS? "#" _WS? DIRECTIVE_NAME "=" _line _NEWLINES
DIRECTIVE_NAME: ( "escape" | "syntax" )

comment: _WS? _COMMENT_BODY _NEWLINES
_COMMENT_BODY: /#[^\n]*/

arg: "ARG"i _WS ( arg_bare | arg_equals ) _NEWLINES
arg_bare: WORD
arg_equals: WORD "=" ( WORD | STRING_QUOTED )

arg_first.2: "ARG"i _WS ( arg_first_bare | arg_first_equals ) _NEWLINES
arg_first_bare: WORD
arg_first_equals: WORD "=" ( WORD | STRING_QUOTED )

copy: "COPY"i ( _WS option )* _WS ( copy_list | copy_shell ) _NEWLINES
copy_list.2: _string_list
copy_shell: WORD ( _WS WORD )+

env: "ENV"i _WS ( env_space | env_equalses ) _NEWLINES
env_space: WORD _WS _line
env_equalses: env_equals ( _WS env_equals )*
env_equals: WORD "=" ( WORD | STRING_QUOTED )

from_: "FROM"i ( _WS ( option | option_keypair ) )* _WS image_ref ( _WS from_alias )? _NEWLINES
from_alias: "AS"i _WS IR_PATH_COMPONENT  // FIXME: undocumented; this is guess

label: "LABEL"i _WS ( label_space | label_equalses ) _NEWLINES
label_space: WORD _WS _line
label_equalses: label_equals ( _WS label_equals )*
label_equals: WORD "=" ( WORD | STRING_QUOTED )

rsync: ( "RSYNC"i | "NSYNC"i ) ( _WS option_plus )? _WS WORDE ( _WS WORDE )+ _NEWLINES

run: "RUN"i _WS ( run_exec | run_shell ) _NEWLINES
run_exec.2: _string_list
run_shell: _line

shell: "SHELL"i _WS _string_list _NEWLINES

workdir: "WORKDIR"i _WS _line _NEWLINES

uns_forever: UNS_FOREVER _WS _line _NEWLINES
UNS_FOREVER: ( "EXPOSE"i | "HEALTHCHECK"i | "MAINTAINER"i | "STOPSIGNAL"i | "USER"i | "VOLUME"i )

uns_yet: UNS_YET _WS _line _NEWLINES
UNS_YET: ( "ADD"i | "CMD"i | "ENTRYPOINT"i | "ONBUILD"i )

/// Common ///

option: "--" OPTION_KEY "=" OPTION_VALUE
option_keypair: "--" OPTION_KEY "=" OPTION_VAR "=" OPTION_VALUE
option_plus: "+" OPTION_LETTER
OPTION_KEY: /[a-z]+/
OPTION_LETTER: /[a-z]/
OPTION_VALUE: /[^= \t\n]+/
OPTION_VAR: /[a-z]+/

image_ref: IMAGE_REF
IMAGE_REF: /[${}A-Za-z0-9:._\/-]+/  // variable substitution chars ${} added
""" + GRAMMAR_COMMON

# Grammar for image references.
GRAMMAR_IMAGE_REF = r"""
// Note: Hostnames with no dot and no port get parsed as a hostname, which
// is wrong; it should be the first path component. We patch this error later.
// FIXME: Supposedly this can be fixed with priorities, but I couldn't get it
// to work with brief trying.

start: image_ref

image_ref: ir_hostport? ir_path? ir_name ( ir_tag | ir_digest )?
ir_hostport: IR_HOST ( ":" IR_PORT )? "/"
ir_path: ( IR_PATH_COMPONENT "/" )+
ir_name: IR_PATH_COMPONENT
ir_tag: ":" IR_TAG
ir_digest: "@sha256:" HEX_STRING
IR_HOST: /[A-Za-z0-9_.-]+/
IR_PORT: /[0-9]+/
IR_TAG: /[A-Za-z0-9_.-]+/
""" + GRAMMAR_COMMON