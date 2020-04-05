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

/*****************************************************************************/

// take an array of strings, which is basically the read line split at specific tokens
// (here, it's most likely split at each white-space)
// "search" for the first index of the equals sign and store that index in the argument 'idx'
static gboolean
_parse_common (const char **line, int *idx, char **out_error)
{
	int len = 0;
	while(line && line[len]){
		len++;
	}

	// TODO fix scenario when we have "KEY=VALUE" and not "KEY = VALUE"

	if(!line[0]){
		*out_error = g_strdup_printf("Nothing found in the line");
		return FALSE;
	}
	else if(!line[1]){
		*out_error = g_strdup_printf("No value found for setting '%s'", line[0]);
		return FALSE;
	}
	else if(!g_strcmp0("=", line[1])){
		// we have an equals sign included
		// KEY = VALUE
		if(!line[2]){
			*out_error = g_strdup_printf("Expected line to be of form KEY = VALUE");
			return FALSE;
		}

		*idx = 2;
	}
	else{
		// we don't have an equals sign included
		// KEY VALUE
		*idx = 1;
	}

	return TRUE;
}

// parse the endpoint (can be just about anything)
static gboolean
parse_endpoint(const char **line, char **endpoint, char **out_error)
{
	int idx = 0;
	if(!_parse_common(line, &idx, out_error)){
		*endpoint = NULL;
		return FALSE;
	}

	// TODO maybe restrict to IPs?

	*endpoint = g_strdup(line[idx]);
	return TRUE;
}

// parse the local listen port (integer with range [0 - 65535])
static gboolean
parse_listen_port(const char **line, guint64 *port, char **out_error)
{
	int idx = 0;
	char *tmp = NULL;
	gboolean success = TRUE;

	if(!_parse_common(line, &idx, out_error)){
		return FALSE;
	}

	tmp = g_strdup(line[idx]);
	if(!g_ascii_string_to_unsigned(tmp, 10, 0, 65535, port, NULL)){
		*out_error = g_strdup_printf("'%s' is not a valid port assignment!", tmp);
		*port = -1;
		success = FALSE;
	}

	g_free(tmp);
	return success;
}

// parse the private key
static gboolean
parse_private_key(const char **line, char **key, char **out_error)
{
	int idx = 0;
	if(!_parse_common(line, &idx, out_error)){
		*key = NULL;
		return FALSE;
	}

	*key = g_strdup(line[idx]);

	// TODO check if base64?
	// TOOD check length?

	return TRUE;
}

#define parse_public_key(line, key, out_error) parse_private_key(line, key, out_error)

// parse the pre-shared key
static gboolean
parse_preshared_key(const char **line, char **key, char **out_error)
{
	int idx = 0;
	if(!_parse_common(line, &idx, out_error)){
		*key = NULL;
		return FALSE;
	}

	*key = g_strdup(line[idx]);

	// TODO any checks?

	return TRUE;
}

// check if the string contains a valid IP4 address (also, remove a trailing comma if there is one)
static char *
_parse_ip4_address(const char *address)
{
	char *ip4 = g_strdup(address);
	size_t len = strlen(ip4);

	// if there is a trailing comma, remove it
	// -- might be, because the config can have an IP4 and IP6
	if(ip4[len - 1] == ','){
		ip4[len - 1] = '\0';
	}

	if(!is_ip4(ip4)){
		g_free(ip4);
		ip4 = NULL;
	}

	return ip4;
}

// analogous to the ip4 variant above
static char *
_parse_ip6_address(const char *address)
{
	char *ip6 = g_strdup(address);
	size_t len = strlen(ip6);

	// same as for IP4
	if(ip6[len - 1] == ','){
		ip6[len - 1] = '\0';
	}

	if(!is_ip6(ip6)){
		g_free(ip6);
		ip6 = NULL;
	}

	return ip6;
}

// parse an IP (4 or 6) address from the line
static gboolean
parse_dns(const char **line, char **dns, char **out_error)
{
	int idx = 0;
	char *tmp = NULL;

	if(!_parse_common(line, &idx, out_error)){
		*dns = NULL;
		return FALSE;
	}

	tmp = _parse_ip4_address(line[idx]);
	if(!tmp){
		// if the DNS isn't an IPv4 address, let's try IPv6...
		tmp = _parse_ip6_address(line[idx]);
		if(tmp){
			*dns = tmp;
			return TRUE;
		}

		*out_error = g_strdup_printf("'%s' is not a valid DNS address!", line[idx]);
		*dns = NULL;
		return FALSE;
	}

	*dns = tmp;
	return TRUE;
}

// parse an MTU from the line (integer with range [0 - 1500])
static gboolean
parse_mtu(const char **line, guint64 *mtu, char **out_error)
{
	int idx = 0;
	char *tmp = NULL;
	gboolean success = TRUE;

	if(!_parse_common(line, &idx, out_error)){
		return FALSE;
	}

	tmp = g_strdup(line[idx]);
	if(!g_ascii_string_to_unsigned(tmp, 10, 0, 1500, mtu, NULL)){
		*out_error = g_strdup_printf("'%s' is not a valid MTU assignment!", tmp);
		*mtu = -1;
		success = FALSE;
	}

	g_free(tmp);
	return success;
}


// parse Persistent Keep Alive value (max 0-5min? (450))
static gboolean
parse_persistent_keep_alive(const char **line, guint64 *pka, char **out_error)
{
	int idx = 0;
	char *tmp = NULL;
	gboolean success = TRUE;

	if(!_parse_common(line, &idx, out_error)){
		return FALSE;
	}

	tmp = g_strdup(line[idx]);
	if(!g_ascii_string_to_unsigned(tmp, 10, 0, 450, pka, NULL)){
		*out_error = g_strdup_printf("'%s' is not a valid Persistent Keep Alive assignment! (max '%d')", tmp, 450);
		*pka = -1;
		success = FALSE;
	}

	g_free(tmp);
	return success;
}

// parse the line and check if there were any IP4 and IP6 included
// (if there are more than just one IP4, the later take precedence; same for IP6)
//
// ip4_address: either the string that was recognised as an IP4 address or NULL if none was found
// ip6_address: pretty much the same, just for IP6
static gboolean
parse_address(const char **line, char **ip4_address, char **ip6_address, char **out_error)
{
	int idx = 0;
	char *ip4 = NULL;
	char *ip6 = NULL;
	gboolean success = FALSE;

	if(!_parse_common(line, &idx, out_error)){
		*ip4_address = NULL;
		*ip6_address = NULL;
		return FALSE;
	}

	while(line && line[idx]){
		ip4 = _parse_ip4_address(line[idx]);
		if(ip4){
			*ip4_address = ip4;
			idx++;
			success = TRUE;
			continue;
		}

		ip6 = _parse_ip6_address(line[idx]);
		if(ip6){
			*ip6_address = ip6;
			success = TRUE;
		}
		
		idx++;
	}

	if(!success)
	{
		*out_error = g_strdup_printf("Assignment of Addresses was invalid (requires at least one valid IPv4 or IPv6 address)!");
	}

	return success;
}

// parse IPs (v4 and v6) from a line and save them in a GArray
static gboolean
parse_allowed_ips(const char **line, GArray **addresses, char **out_error)
{
	int idx = 0;
	char *ip4 = NULL;
	char *ip6 = NULL;
	gboolean success = FALSE;

	if(!_parse_common(line, &idx, out_error)){
		*addresses = NULL;
		return FALSE;
	}

	*addresses = g_array_new(TRUE, TRUE, sizeof(char *));
	while(line && line[idx]){
		// check if we have an IP4 or IP6 at our hands and if so,
		// add them to our array of Allowed Addresses
		ip4 = _parse_ip4_address(line[idx]);
		if(ip4){
			g_array_append_val(*addresses, ip4);
			success = TRUE;
			goto ip4next;
		}

		ip6 = _parse_ip6_address(line[idx]);
		if(ip6){
			g_array_append_val(*addresses, ip6);
			success = TRUE;
		}

ip4next:
		idx++;
	}

	if(!success){
		*out_error = g_strdup_printf("Assignment of Allowed IPs was invalid (requires at least one valid IPv4 or IPv6 address)!");
		g_array_free(*addresses, TRUE);
	}
	return success;
}

// parse a script: just concatenate the parts of the read line after the equals sign
static gboolean
parse_script(const char **line, char **script, char **out_error)
{
	int idx = 0;
	char *tmp = NULL;
	int len = 0;
	int idx2 = 0;

	if(!_parse_common(line, &idx, out_error)){
		*script = NULL;
		return FALSE;
	}

	// calculate how much space we are going to need
	idx2 = idx;
	while(line && line[idx2]){
		// one extra character for the space between the commands
		len += strlen(line[idx2]) + 1;
		idx2++;
	}

	// the last extra slot isn't taken by a space, but by a NULL-byte
	*script = g_malloc(len);
	tmp = g_stpcpy(*script, "");
	while(line && line[idx]){
		tmp = g_stpcpy(tmp, line[idx]);
		if(line[idx+1]){
			tmp = g_stpcpy(tmp, " ");
		}
		idx++;
	}

	return TRUE;
}

// create a single string from the contents of a GArray
static gchar *
concatenate_strings(const GArray *string_array, char *separator)
{
	int i = 0;
	int len = 0;
	int sep_len = 0;
	char *result;
	char *tmp;

	if(!string_array){
		return NULL;
	}

	if(!separator){
		separator = ",";
	}

	// check how much space we are going to need
	sep_len = strlen(separator);
	for(i = 0; i < string_array->len; i++){
		len += strlen(g_array_index(string_array, char *, i));
		if(i < (string_array->len - 1)){
			len += sep_len;
		}
	}

	// space for the trailing NULL-byte
	len += 1;

	// allocate memory and do the appending
	result = g_malloc(len);
	tmp = g_stpcpy(result, "");
	for(i = 0; i < string_array->len; i++){
		tmp = g_stpcpy(tmp, g_array_index(string_array, char *, i));
		if(i < (string_array->len - 1)){
			tmp = g_stpcpy(tmp, separator);
		}
	}

	return result;
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
