/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-softethervpn-editor.h : GNOME UI dialogs for configuring softethervpn VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifndef __NM_SOFTETHERVPN_EDITOR_H__
#define __NM_SOFTETHERVPN_EDITOR_H__

#define SOFTETHERVPN_TYPE_EDITOR            (softethervpn_editor_plugin_widget_get_type ())
#define SOFTETHERVPN_EDITOR(obj)                      (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOFTETHERVPN_TYPE_EDITOR, SoftetherVPNEditor))
#define SOFTETHERVPN_EDITOR_CLASS(klass)              (G_TYPE_CHECK_CLASS_CAST ((klass), SOFTETHERVPN_TYPE_EDITOR, SoftetherVPNEditorClass))
#define SOFTETHERVPN_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOFTETHERVPN_TYPE_EDITOR))
#define SOFTETHERVPN_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOFTETHERVPN_TYPE_EDITOR))
#define SOFTETHERVPN_EDITOR_GET_CLASS(obj)            (G_TYPE_INSTANCE_GET_CLASS ((obj), SOFTETHERVPN_TYPE_EDITOR, SoftetherVPNEditorClass))

typedef struct _SoftetherVPNEditor SoftetherVPNEditor;
typedef struct _SoftetherVPNEditorClass SoftetherVPNEditorClass;

struct _SoftetherVPNEditor {
	GObject parent;
};

struct _SoftetherVPNEditorClass {
	GObjectClass parent;
};

GType softethervpn_editor_plugin_widget_get_type (void);

NMVpnEditor *softethervpn_editor_new (NMConnection *connection, GError **error);

#endif	/* __NM_SOFTETHERVPN_EDITOR_H__ */

