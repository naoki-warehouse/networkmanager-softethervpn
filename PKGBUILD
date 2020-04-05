# Maintaier: Naoki Matsumoto <naoki@pibvt.net>

pkgname=networkmanager-softethervpn
pkgver=0.0.1
pkgrel=1
pkgdesc="NetworkManager VPN plugin for SoftEtherVPN"
arch=(x86_64)
license=(GPL)
depends=()
makedepends=(libnm intltool git gcc make automake autoconf libnm-glib libtool)

prepare() {
  cd "$startdir"
  ./autogen.sh
}

build() {
  cd "$startdir"
  ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
  --libexecdir=/usr/lib --disable-static 
  make
}

package() {
  cd "$startdir"
  make DESTDIR="$pkgdir" install dbusservicedir=/usr/share/dbus-1/system.d
  echo 'u nm-softethervpn - "NetworkManager SoftEtherVPN"' |
  install -Dm644 /dev/stdin "$pkgdir/usr/lib/sysusers.d/$pkgname.conf"
}
