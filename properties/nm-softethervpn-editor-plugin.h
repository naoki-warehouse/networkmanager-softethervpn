/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-softethervpn-editor-plugin.h : GNOME UI dialogs for configuring SoftEtherVPN VPN connections
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

#ifndef __NM_SOFTETHERVPN_EDITOR_PLUGIN_H__
#define __NM_SOFTETHERVPN_EDITOR_PLUGIN_H__

#define SOFTETHERVPN_TYPE_EDITOR_PLUGIN                (softethervpn_editor_plugin_get_type ())
#define SOFTETHERVPN_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOFTETHERVPN_TYPE_EDITOR_PLUGIN, SoftetherVPNEditorPlugin))
#define SOFTETHERVPN_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOFTETHERVPN_TYPE_EDITOR_PLUGIN, SoftetherVPNEditorPluginClass))
#define SOFTETHERVPN_IS_EDITOR_PLUGIN(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOFTETHERVPN_TYPE_EDITOR_PLUGIN))
#define SOFTETHERVPN_IS_EDITOR_PLUGIN_CLASS(klass)     (G_TYPE_CHECK_CLASS_TYPE ((klass), SOFTETHERVPN_TYPE_EDITOR_PLUGIN))
#define SOFTETHERVPN_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOFTETHERVPN_TYPE_EDITOR_PLUGIN, SoftetherVPNEditorPluginClass))

typedef struct _SoftetherVPNEditorPlugin SoftetherVPNEditorPlugin;
typedef struct _SoftetherVPNEditorPluginClass SoftetherVPNEditorPluginClass;

struct _SoftetherVPNEditorPlugin {
	GObject parent;
};

struct _SoftetherVPNEditorPluginClass {
	GObjectClass parent;
};

GType softethervpn_editor_plugin_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

NMVpnEditor *
nm_vpn_editor_factory_softethervpn (NMVpnEditorPlugin *editor_plugin,
                               NMConnection *connection,
                               GError **error);

#endif /* __NM_SOFTETHERVPN_EDITOR_PLUGIN_H__ */

