/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008 - 2013 Dan Williams <dcbw@redhat.com> and Red Hat, Inc.
 *
 **************************************************************************/

#include "nm-default.h"

#include "import-export.h"

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

const char *_nmovpn_test_temp_path = NULL;

/*****************************************************************************/

static const char *
_arg_is_set (const char *value)
{
	return (value && value[0]) ? value : NULL;
}

static void
_auto_free_gstring_p (GString **ptr)
{
	if (*ptr)
		g_string_free (*ptr, TRUE);
}

static gboolean
_is_utf8 (const char *str)
{
	g_return_val_if_fail (str, FALSE);

	return g_utf8_validate (str, -1, NULL);
}

/*****************************************************************************/

static void
__attribute__((__format__ (__printf__, 3, 4)))
setting_vpn_add_data_item_v (NMSettingVpn *setting,
                             const char *key,
                             const char *format,
                             ...)
{
	char buf[256];
	char *s;
	int l;
	va_list ap, ap2;

	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);

	/* let's first try with a stack allocated buffer,
	 * it's large enough for most cases. */
	va_start (ap, format);
	va_copy (ap2, ap);
	l = g_vsnprintf (buf, sizeof (buf), format, ap2);
	va_end (ap2);

	if (l < sizeof (buf) - 1) {
		va_end (ap);
		nm_setting_vpn_add_data_item (setting, key, buf);
		return;
	}

	s = g_strdup_vprintf (format, ap);
	va_end (ap);
	nm_setting_vpn_add_data_item (setting, key, s);
	g_free (s);
}

static void
setting_vpn_add_data_item_int64 (NMSettingVpn *setting,
                                 const char *key,
                                 gint64 value)
{
	setting_vpn_add_data_item_v (setting, key, "%"G_GINT64_FORMAT, value);
}

static void
setting_vpn_add_data_item (NMSettingVpn *setting,
                           const char *key,
                           const char *value)
{
	g_return_if_fail (NM_IS_SETTING_VPN (setting));
	g_return_if_fail (key && key[0]);
	g_return_if_fail (value && value[0]);
	g_return_if_fail (_is_utf8 (value));

	nm_setting_vpn_add_data_item (setting, key, value);
}

/*****************************************************************************/

static char
_ch_step_1 (const char **str, gsize *len)
{
	char ch;
	g_assert (str);
	g_assert (len && *len > 0);

	ch = (*str)[0];

	(*str)++;
	(*len)--;
	return ch;
}

static void
_ch_skip_over_leading_whitespace (const char **str, gsize *len)
{
	while (*len > 0 && g_ascii_isspace ((*str)[0]))
		_ch_step_1 (str, len);
}

static void
_strbuf_append_c (char **buf, gsize *len, char ch)
{
	nm_assert (buf);
	nm_assert (len);

	g_return_if_fail (*len > 0);

	(*buf)[0] = ch;
	(*len)--;
	*buf = &(*buf)[1];
}

// split the line into an array of strings
static gboolean
args_parse_line (const char *line,
                 gsize line_len,
                 const char ***out_p,
                 char **out_error)
{
	gs_unref_array GArray *index = NULL;
	gs_free char *str_buf_orig = NULL;
	char *str_buf;
	gsize str_buf_len;
	gsize i;
	const char *line_start = line;
	char **data;
	char *pdata;

	/* reimplement openvpn's parse_line(). */

	g_return_val_if_fail (line, FALSE);
	g_return_val_if_fail (out_p && !*out_p, FALSE);
	g_return_val_if_fail (out_error && !*out_error, FALSE);

	*out_p = NULL;

	/* we expect no newline during the first line_len chars. */
	for (i = 0; i < line_len; i++) {
		if (NM_IN_SET (line[i], '\0', '\n'))
			g_return_val_if_reached (FALSE);
	}

	/* if the line ends with '\r', drop that right way (covers \r\n). */
	if (line_len > 0 && line[line_len - 1] == '\r')
		line_len--;

	/* skip over leading space. */
	_ch_skip_over_leading_whitespace (&line, &line_len);

	if (line_len == 0)
		return TRUE;

	if (NM_IN_SET (line[0], ';', '#')) {
		/* comment. Note that als openvpn allows for leading spaces
		 * *before* the comment starts */
		return TRUE;
	}

	/* the maximum required buffer is @line_len+1 characters. We don't produce
	 * *more* characters then given in the input (plus trailing '\0'). */
	str_buf_len = line_len + 1;
	str_buf_orig = g_malloc (str_buf_len);
	str_buf = str_buf_orig;

	index = g_array_new (FALSE, FALSE, sizeof (gsize));

	for (;;) {
		char quote, ch0;
		gssize word_start = line - line_start;
		gsize index_i;

		index_i = str_buf - str_buf_orig;
		g_array_append_val (index, index_i);

		switch ((ch0 = _ch_step_1 (&line, &line_len))) {
		case '"':
		case '\'':
			quote = ch0;

			while (line_len > 0 && line[0] != quote) {
				if (quote == '"' && line[0] == '\\') {
					_ch_step_1 (&line, &line_len);
					if (line_len <= 0)
						break;
				}
				_strbuf_append_c (&str_buf, &str_buf_len, _ch_step_1 (&line, &line_len));
			}

			if (line_len <= 0) {
				*out_error = g_strdup_printf (_("unterminated %s at position %lld"),
				                              quote == '"' ? _("double quote") : _("single quote"),
				                              (long long) word_start);
				return FALSE;
			}

			/* openvpn terminates parsing of quoted paramaters after the closing quote.
			 * E.g. "'a'b" gives "a", "b". */
			_ch_step_1 (&line, &line_len);
			break;
		default:
			/* once openvpn encounters a non-quoted word, it doesn't consider quoting
			 * inside the word.
			 * E.g. "a'b'" gives "a'b'". */
			for (;;) {
				if (ch0 == '\\') {
					if (line_len <= 0) {
						*out_error = g_strdup_printf (_("trailing escaping backslash at position %lld"),
						                              (long long) word_start);
						return FALSE;
					}
					ch0 = _ch_step_1 (&line, &line_len);
				}
				_strbuf_append_c (&str_buf, &str_buf_len, ch0);
				if (line_len <= 0)
					break;
				ch0 = _ch_step_1 (&line, &line_len);
				if (g_ascii_isspace (ch0))
					break;
			}
			break;
		}

		/* the current word is complete.*/
		_strbuf_append_c (&str_buf, &str_buf_len, '\0');
		_ch_skip_over_leading_whitespace (&line, &line_len);

		if (line_len <= 0)
			break;

		if (NM_IN_SET (line[0], ';', '#')) {
			/* comments are allowed to start at the beginning of the next word. */
			break;
		}
	}

	str_buf_len = str_buf - str_buf_orig;

	/* pack the result in a strv array */
	data = g_malloc ((sizeof (const char *) * (index->len + 1)) + str_buf_len);

	pdata = (char *) &data[index->len + 1];
	memcpy (pdata, str_buf_orig, str_buf_len);

	for (i = 0; i < index->len; i++)
		data[i] = &pdata[g_array_index (index, gsize, i)];
	data[i] = NULL;

	*out_p = (const char **) data;

	return TRUE;
}

gboolean
_nmovpn_test_args_parse_line (const char *line,
                              gsize line_len,
                              const char ***out_p,
                              char **out_error)
{
	return args_parse_line (line, line_len, out_p, out_error);
}

// return the next line of the content
// and adjust the content pointer to start at the line after the current one
static gboolean
args_next_line (const char **content,
                gsize *content_len,
                const char **cur_line,
                gsize *cur_line_len,
                const char **cur_line_delimiter)
{
	const char *s;
	gsize l, offset;

	g_return_val_if_fail (content, FALSE);
	g_return_val_if_fail (content_len, FALSE);
	g_return_val_if_fail (cur_line, FALSE);
	g_return_val_if_fail (cur_line_len, FALSE);
	g_return_val_if_fail (cur_line_delimiter, FALSE);

	l = *content_len;

	if (l <= 0)
		return FALSE;

	*cur_line = s = *content;

	while (l > 0 && !NM_IN_SET (s[0], '\0', '\n'))
		_ch_step_1 (&s, &l);

	offset = s - *content;
	*cur_line_len = offset;

	/* cur_line_delimiter will point to a (static) string
	 * containing the dropped character.
	 * Or NULL if we reached the end of content. */
	if (l > 0) {
		if (s[0] == '\0') {
			*cur_line_delimiter = "\0";
		} else {
			*cur_line_delimiter = "\n";
		}
		offset++;
	} else {
		*cur_line_delimiter = NULL;
	}

	*content_len -= offset;
	*content += offset;

	return TRUE;
}

NMConnection *
do_import (const char *path, const char *contents, gsize contents_len, GError **error)
{
	return NULL;
}

gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	return FALSE;
}
