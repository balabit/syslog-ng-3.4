/*
 * Copyright (c) 2011-2012 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 2011 Balint Kovacs <blint@balabit.hu>
 * Copyright (c) 2011-2012 Gergely Nagy <algernon@balabit.hu>
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
 */

#include "plugin.h"
#include "templates.h"
#include "filter.h"
#include "filter-expr-parser.h"
#include "cfg.h"
#include "value-pairs.h"

typedef struct _TFJsonState
{
  TFSimpleFuncState super;
  ValuePairs *vp;
} TFJsonState;

static gboolean
tf_json_prepare(LogTemplateFunction *self, gpointer s, LogTemplate *parent,
		gint argc, gchar *argv[],
		GError **error)
{
  TFJsonState *state = (TFJsonState *)s;

  state->vp = value_pairs_new_from_cmdline (parent->cfg, argc, argv, error);
  if (!state->vp)
    return FALSE;

  return TRUE;
}

typedef struct
{
  gboolean need_comma;
  GString *buffer;
} json_state_t;

static inline void
g_string_append_escaped(GString *dest, const char *str)
{
  /* Assumes ASCII!  Keep in sync with the switch! */
  static const unsigned char json_exceptions[UCHAR_MAX + 1] =
    {
      [0x01] = 1, [0x02] = 1, [0x03] = 1, [0x04] = 1, [0x05] = 1, [0x06] = 1,
      [0x07] = 1, [0x08] = 1, [0x09] = 1, [0x0a] = 1, [0x0b] = 1, [0x0c] = 1,
      [0x0d] = 1, [0x0e] = 1, [0x0f] = 1, [0x10] = 1, [0x11] = 1, [0x12] = 1,
      [0x13] = 1, [0x14] = 1, [0x15] = 1, [0x16] = 1, [0x17] = 1, [0x18] = 1,
      [0x19] = 1, [0x1a] = 1, [0x1b] = 1, [0x1c] = 1, [0x1d] = 1, [0x1e] = 1,
      [0x1f] = 1, ['\\'] = 1, ['"'] = 1
    };

  const unsigned char *p;

  p = (unsigned char *)str;

  while (*p)
    {
      if (json_exceptions[*p] == 0)
        g_string_append_c(dest, *p);
      else
        {
          /* Keep in sync with json_exceptions! */
          switch (*p)
            {
            case '\b':
              g_string_append(dest, "\\b");
              break;
            case '\n':
              g_string_append(dest, "\\n");
              break;
            case '\r':
              g_string_append(dest, "\\r");
              break;
            case '\t':
              g_string_append(dest, "\\t");
              break;
            case '\\':
              g_string_append(dest, "\\\\");
              break;
            case '"':
              g_string_append(dest, "\\\"");
              break;
            default:
              {
                static const char json_hex_chars[16] = "0123456789abcdef";

                g_string_append(dest, "\\u00");
                g_string_append_c(dest, json_hex_chars[(*p) >> 4]);
                g_string_append_c(dest, json_hex_chars[(*p) & 0xf]);
                break;
              }
            }
        }
      p++;
    }
}

static gboolean
tf_json_obj_start(const gchar *name,
                  const gchar *prefix, gpointer *prefix_data,
                  const gchar *prev, gpointer *prev_data,
                  gpointer user_data)
{
  json_state_t *state = (json_state_t *)user_data;
  gboolean need_comma = FALSE;

  if (prefix_data)
    need_comma = GPOINTER_TO_INT(*prefix_data);
  else
    need_comma = state->need_comma;

  if (need_comma)
    g_string_append_c(state->buffer, ',');

  if (name)
    {
      g_string_append_c(state->buffer, '"');
      g_string_append_escaped(state->buffer, name);
      g_string_append(state->buffer, "\":{");
      state->need_comma = TRUE;
    }
  else
    g_string_append_c(state->buffer, '{');

  if (prefix_data)
    *prefix_data=GINT_TO_POINTER(0);

  return FALSE;
}

static gboolean
tf_json_obj_end(const gchar *name,
                const gchar *prefix, gpointer *prefix_data,
                const gchar *prev, gpointer *prev_data,
                gpointer user_data)
{
  json_state_t *state = (json_state_t *)user_data;

  if (prev_data)
    *prev_data = GINT_TO_POINTER(1);

  g_string_append_c(state->buffer, '}');

  return FALSE;
}

static gboolean
tf_json_value(const gchar *name, const gchar *prefix, const gchar *value,
              gpointer *prefix_data, gpointer user_data)
{
  gboolean need_comma = FALSE;
  json_state_t *state = (json_state_t *)user_data;

  if (prefix_data)
    need_comma = GPOINTER_TO_INT(*prefix_data);
  else
    need_comma = state->need_comma;

  if (need_comma)
    g_string_append_c(state->buffer, ',');
  else if (prefix_data)
    *prefix_data = GINT_TO_POINTER(1);

  g_string_append_c(state->buffer, '"');
  g_string_append_escaped(state->buffer, name);
  g_string_append(state->buffer, "\":\"");
  g_string_append_escaped(state->buffer, value);
  g_string_append_c(state->buffer, '"');

  state->need_comma = TRUE;

  return FALSE;
}

static void
tf_json_append(GString *result, ValuePairs *vp, LogMessage *msg)
{
  json_state_t state;

  state.need_comma = FALSE;
  state.buffer = result;

  value_pairs_walk(vp,
                   tf_json_obj_start, tf_json_value, tf_json_obj_end,
                   msg, 0, &state);
}

static void
tf_json_call(LogTemplateFunction *self, gpointer s,
	     const LogTemplateInvokeArgs *args, GString *result)
{
  TFJsonState *state = (TFJsonState *)s;
  gint i;

  for (i = 0; i < args->num_messages; i++)
    tf_json_append(result, state->vp, args->messages[i]);
}

static void
tf_json_free_state(gpointer s)
{
  TFJsonState *state = (TFJsonState *)s;

  if (state->vp)
    value_pairs_free(state->vp);
  tf_simple_func_free_state(&state->super);
}

TEMPLATE_FUNCTION(TFJsonState, tf_json, tf_json_prepare, NULL, tf_json_call,
		  tf_json_free_state, NULL);

extern CfgParser jsonparser_parser;

static Plugin json_plugins[] =
  {
    {
      .type = LL_CONTEXT_PARSER,
      .name = "json-parser",
      .parser = &jsonparser_parser,
    },
    TEMPLATE_FUNCTION_PLUGIN(tf_json, "format_json"),
  };

gboolean
json_module_init(GlobalConfig *cfg, CfgArgs *args)
{
  plugin_register(cfg, json_plugins, G_N_ELEMENTS(json_plugins));
  return TRUE;
}

const ModuleInfo module_info =
{
  .canonical_name = "json",
  .version = VERSION,
  .description = "The json module provides JSON parsing & formatting support for syslog-ng.",
  .core_revision = SOURCE_REVISION,
  .plugins = json_plugins,
  .plugins_len = G_N_ELEMENTS(json_plugins),
};
