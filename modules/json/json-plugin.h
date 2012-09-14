/*
 * Copyright (c) 2011-2012 BalaBit IT Ltd, Budapest, Hungary
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
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 */

#ifndef JSON_PLUGIN_H_INCLUDED
#define JSON_PLUGIN_H_INCLUDED

#include "logparser.h"

typedef struct _LogJSONParser LogJSONParser;

void log_json_parser_set_prefix(LogParser *p, const gchar *prefix);
void log_json_parser_set_marker(LogParser *p, const gchar *marker);
LogJSONParser *log_json_parser_new(void);

gboolean tfjson_module_init(GlobalConfig *cfg);

#endif
