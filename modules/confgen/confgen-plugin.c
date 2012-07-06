/*
 * Copyright (c) 2002-2010 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 1998-2010 Balázs Scheidler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#include "confgen.h"
#include "cfg.h"
#include "cfg-lexer.h"
#include "cfg-grammar.h"
#include "messages.h"
#include "plugin.h"

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

gboolean
confgen_generate(CfgLexer *lexer, gint type, const gchar *name, CfgArgs *args, gpointer user_data)
{
  gchar *value;
  gsize value_len = 0;
  FILE *out;
  gchar *exec = (gchar *) user_data;
  gsize res;
  gchar buf[256];

  g_snprintf(buf, sizeof(buf), "%s confgen %s", cfg_lexer_lookup_context_name_by_type(type), name);
  if (!cfg_args_validate(args, NULL, buf))
    {
      msg_error("confgen: confgen invocations do not process arguments, but your argument list is not empty",
                evt_tag_str("context", cfg_lexer_lookup_context_name_by_type(type)),
                evt_tag_str("block", name),
                NULL);
      return FALSE;
    }

  out = popen((gchar *) user_data, "r");
  if (!out)
    {
      msg_error("confgen: Error executing generator program",
                evt_tag_str("context", cfg_lexer_lookup_context_name_by_type(type)),
                evt_tag_str("block", name),
                evt_tag_str("exec", exec),
                evt_tag_errno("error", errno),
                NULL);
      return FALSE;
    }
  value = g_malloc(1024);
  while ((res = fread(value + value_len, 1, 1024, out)) > 0)
    {
      value_len += res;
      value = g_realloc(value, value_len + 1024);
    }
  res = pclose(out);
  if (res != 0)
    {
      msg_error("confgen: Generator program returned with non-zero exit code",
                evt_tag_str("block", name),
                evt_tag_str("exec", exec),
                evt_tag_int("rc", res),
                NULL);
      g_free(value);
      return FALSE;
    }
  if (!cfg_lexer_include_buffer(lexer, buf, value, value_len))
    {
      g_free(value);
      return FALSE;
    }
  return TRUE;
}

static void
confgen_sysblock_add_unix_dgram(GString *sysblock, const gchar *path,
                                const gchar *perms)
{
  g_string_append_printf(sysblock, "unix-dgram(\"%s\"", path);
  if (perms)
    g_string_append_printf(sysblock, " perms(%s)", perms);
  g_string_append(sysblock, ");\n");
}

static void
confgen_sysblock_add_file(GString *sysblock, const gchar *path,
                          gint follow_freq, const gchar *prg_override,
                          const gchar *flags)
{
  g_string_append_printf(sysblock, "file(\"%s\"", path);
  if (follow_freq >= 0)
    g_string_append_printf(sysblock, " follow-freq(%d)", follow_freq);
  if (prg_override)
    g_string_append_printf(sysblock, " program-override(\"%s\")", prg_override);
  if (flags)
    g_string_append_printf(sysblock, " flags(%s)", flags);
  g_string_append(sysblock, ");\n");
}

static void
confgen_sysblock_add_module(GString *sysblock, const gchar *mod)
{
  g_string_append_printf(sysblock, "@module %s\n", mod);
}

static void
confgen_sysblock_add_sun_streams(GString *sysblock, const gchar *path,
                                 const gchar *door)
{
  g_string_append_printf(sysblock, "sun-streams(\"%s\"", path);
  if (door)
    g_string_append_printf(sysblock, " door(\"%s\")", door);
  g_string_append(sysblock, ");\n");
}

static void
confgen_sysblock_add_pipe(GString *sysblock, const gchar *path, gint pad_size)
{
  g_string_append_printf(sysblock, "pipe(\"%s\"", path);
  if (pad_size >= 0)
    g_string_append_printf(sysblock, " pad_size(%d)", pad_size);
  g_string_append(sysblock, ");\n");
}

gboolean
confgen_generate_system(CfgLexer *lexer, gint type, const gchar *name,
                        CfgArgs *args, gpointer user_data)
{
  gchar buf[256];
  GString *sysblock;
  struct utsname u;

  g_snprintf(buf, sizeof(buf), "%s confgen %s", cfg_lexer_lookup_context_name_by_type(type), name);
  if (!cfg_args_validate(args, NULL, buf))
    {
      msg_error("confgen: confgen invocations do not process arguments, but your argument list is not empty",
                evt_tag_str("context", cfg_lexer_lookup_context_name_by_type(type)),
                evt_tag_str("block", name),
                NULL);
      return FALSE;
    }

  sysblock = g_string_sized_new(1024);

  if (uname(&u) != 0)
    {
      msg_error("confgen: Cannot get information about the running kernel",
                evt_tag_errno("error", errno),
                NULL);
      return FALSE;
    }

  if (strcmp(u.sysname, "Linux") == 0)
    {
      char *log = "/dev/log";

      if (getenv("LISTEN_FDS") != NULL)
        {
          struct stat sbuf;

          if (stat("/run/systemd/journal/syslog", &sbuf) == 0)
            {
              if (S_ISSOCK(sbuf.st_mode))
                log = "/run/systemd/journal/syslog";
            }
        }

      confgen_sysblock_add_unix_dgram(sysblock, log, NULL);
      confgen_sysblock_add_file(sysblock, "/proc/kmsg", -1, "kernel", "kernel");
    }
  else if (strcmp(u.sysname, "SunOS") == 0)
    {
      confgen_sysblock_add_module(sysblock, "afstreams");

      if (strcmp(u.release, "5.8") == 0)
        confgen_sysblock_add_sun_streams(sysblock, "/dev/log", NULL);
      else if (strcmp(u.release, "5.9") == 0)
        confgen_sysblock_add_sun_streams(sysblock, "/dev/log", "/etc/.syslog_door");
      else
        confgen_sysblock_add_sun_streams(sysblock, "/dev/log", "/var/run/syslog_door");
    }
  else if (strcmp(u.sysname, "FreeBSD") == 0)
    {
      confgen_sysblock_add_unix_dgram(sysblock, "/var/run/log", NULL);
      confgen_sysblock_add_unix_dgram(sysblock, "/var/run/logpriv", "0600");
      confgen_sysblock_add_file(sysblock, "/dev/klog", 0, "kernel", "no-parse");
    }
  else if (strcmp(u.sysname, "GNU/kFreeBSD") == 0)
    {
      confgen_sysblock_add_unix_dgram(sysblock, "/var/run/log", NULL);
      confgen_sysblock_add_file(sysblock, "/dev/klog", 0, "kernel", NULL);
    }
  else if (strcmp(u.sysname, "HP-UX") == 0)
    {
      confgen_sysblock_add_pipe(sysblock, "/dev/pipe", 2048);
    }
  else if (strcmp(u.sysname, "AIX") == 0 ||
           strcmp(u.sysname, "OSF1") == 0 ||
           strncmp(u.sysname, "CYGWIN", 6) == 0)
    {
      confgen_sysblock_add_unix_dgram(sysblock, "/dev/log", NULL);
    }
  else
    {
      msg_error("system(): Error detecting platform, unable to define the system() source. "
                "Please send your system information to the developers!",
                evt_tag_str("sysname", u.sysname),
                evt_tag_str("release", u.release),
                NULL);
      return FALSE;
    }

  if (!cfg_lexer_include_buffer(lexer, buf, sysblock->str, sysblock->len))
    {
      g_string_free(sysblock, TRUE);
      return FALSE;
    }

  return TRUE;
}

gboolean
confgen_module_init(GlobalConfig *cfg, CfgArgs *args)
{
  const gchar *name, *context, *exec, *sys;

  name = cfg_args_get(args, "name");
  if (!name)
    {
      msg_error("confgen: name argument expected",
                NULL);
      return FALSE;
    }
  context = cfg_args_get(args, "context");
  if (!context)
    {
      msg_error("confgen: context argument expected",
                NULL);
      return FALSE;
    }
  exec = cfg_args_get(args, "exec");
  sys = cfg_args_get(args, "system");

  if (!exec && !sys)
    {
      msg_error("confgen: exec or system argument expected",
                NULL);
      return FALSE;
    }

  if (exec && sys)
    {
      msg_error("confgen: exec and system arguments are mutually excluse",
                NULL);
      return FALSE;
    }

  if (exec)
    cfg_lexer_register_block_generator(cfg->lexer, cfg_lexer_lookup_context_type_by_name(context), name, confgen_generate, g_strdup(exec), g_free);
  if (sys)
    cfg_lexer_register_block_generator(cfg->lexer, cfg_lexer_lookup_context_type_by_name(context),
                                       name, confgen_generate_system, NULL, NULL);
  return TRUE;
}

const ModuleInfo module_info =
{
  .canonical_name = "confgen",
  .version = VERSION,
  .description = "The confgen module provides support for dynamically generated configuration file snippets for syslog-ng, used for the SCL system() driver for example",
  .core_revision = SOURCE_REVISION,
  .plugins = NULL,
  .plugins_len = 0,
};
