//
//   Copyright 2014 QuarksLab
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

#include "binmap/version.hpp"
#include <boost/regex.hpp>
#include <cstring>

namespace {

static char const *entries[][2] = {
  { "ssh", "^OpenSSH_(\\d+\\.\\d+(p\\d+)?) " },
  { "luatex", "^beta-((\\d+\\.)+\\d+)" },
  { "html2text", "html2text,\\sversion\\s((\\d+\\.)+\\d+\\w?)" },
  { "Xorg", "xorg-server\\s(?:\\d+:)?((\\d+\\.)+\\d+-\\d+)" },
  { "lsusb", "lsusb.+(\\d+)" }, { "acpi_listen", "acpid-(\\d+)" },
  { "sane-find-scanner", "sane-backends\\s(\\d+\\.\\d+\\.\\d+)" },
  { "inkview", "(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+r" },
  { "gtk-update-icon-cache", "gtk\\+(\\d+\\.\\d+\\-\\d+\\.\\d+\\.\\d+)" },
  { "dbus-daemon", "libdbus\\s(\\d+\\.\\d+\\.\\d+)" },
  { "libkeyutils", "keyutils-(\\d+\\.\\d+\\.\\d+)" },
  { "libkrb", "^KRB\\d_BRAND:\\s+[^ ]+\\s+(\\d+\\.\\d+\\.\\d+) " },
  { "ntfs-3g.secaudit", "secaudit\\s((\\d+\\.)+\\d+)" },
  { "sleep", "@(\\d+\\.\\d+)" }, { "stty", "^(\\d\\.\\d+)$" },
  { "rpcinfo", "^(\\d\\.\\d+)$" }, { "df", "^(\\d\\.\\d+)$" },
  { "udhcpd", "^(\\d\\.\\d+\\.\\d+)$" },
  { "mutt-org", "^(\\d\\.\\d+\\.\\d+)$" },
  { "strace", "^(\\d\\.\\d+\\.\\d+)$" }, { "wbinfo", "^(\\d\\.\\d+\\.\\d+)$" },
  { "net.samba3", "^(\\d\\.\\d+\\.\\d+)$" },
  { "derb", "^(\\d\\.\\d+\\.\\d+\\.\\d+)$" },
  { "genrb", "^(\\d\\.\\d+\\.\\d+\\.\\d+)$" },
  { "sed", "^(\\d+\\.\\d+.\\d+)$" }, { "dd", "A(\\d+\\.\\d+)" },
  { "tar", "^tar.*(\\d+\\.\\d+)$" }, { "ss", "^(\\d{6})$" },
  { "ip", "^(\\d{6})$" }, { "ping", "s(\\d{8})" }, { "ping6", "s(\\d{8})" },
  { "ntfs-3g.usermap", "\\sv\\s((\\d+[\\.-])*\\d+)" },
  { "lessecho", "Revision:\\s((\\d+\\.)+\\d+)" },
  { "vim.basic", "VIM\\s-\\sVi\\sIMproved\\s((\\d+\\.)+\\d+)" },
  { "mkdosfs", "%s\\s((\\d+\\.)+\\d+)" }, { "awk", "Awk\\s((\\d+\\.)+\\d+)" },
  { "gawk", "Awk\\s((\\d+\\.)+\\d+)" }, { "dgawk", "Awk\\s((\\d+\\.)+\\d+)" },
  { "lnstat", "\\d+\\.\\d+\\s\\d{6}" }, { "kcachegrind", "(\\d+\\.\\d+)kde" },
  { "grub-mkfont", "(\\d+\\.\\d+-\\d+)" },
  { "grub-mkimage", "(\\d+\\.\\d+-\\d+)" },
  { "grub-mkrelpath", "(\\d+\\.\\d+-\\d+)" },
  { "grub-mklayout", "(\\d+\\.\\d+-\\d+)" },
  { "grub-mkpasswd-pbkdf2", "(\\d+\\.\\d+-\\d+)" },
  { "grub-script-check", "(\\d+\\.\\d+-\\d+)" },
  { "grub-editenv", "(\\d+\\.\\d+-\\d+)" },
  { "grub-fstest", "(\\d+\\.\\d+-\\d+)" },
  { "grub-mount", "(\\d+\\.\\d+-\\d+)" },
  { "grub-bin2h", "(\\d+\\.\\d+-\\d+)" }, { "python2.7", "^(2\\.7\\.\\d+)$" },
  { "python3.1", "^(3\\.1\\.\\d+)$" }, { "python3.2mu", "^(3\\.2\\.\\d+)$" },

#define PROCPS_NG_VERSION(name)                                                \
  { #name, "procps-ng\\s(\\d+\\.\\d+.\\d+)" }
  PROCPS_NG_VERSION(kill), PROCPS_NG_VERSION(sysctl), PROCPS_NG_VERSION(uptime),
  PROCPS_NG_VERSION(w.procps), PROCPS_NG_VERSION(pmap),
  PROCPS_NG_VERSION(pgrep), PROCPS_NG_VERSION(pwdx), PROCPS_NG_VERSION(slabtop),
  PROCPS_NG_VERSION(vmstat), PROCPS_NG_VERSION(tload), PROCPS_NG_VERSION(skill),
  PROCPS_NG_VERSION(free), PROCPS_NG_VERSION(watch),
#undef PROCPS_NG_VERSION
  { "pacat", "^(\\d+\\.\\d+)$" }, { "pacmd", "^(\\d+\\.\\d+)$" },
  { "pasuspender", "^(\\d+\\.\\d+)$" }, { "grops", "^(\\d+\\.\\d+)$" },
  { "m4", "M4\\s(\\d+\\.\\d+\\.\\d+)$" },
  { "ufraw-batch", "UFRaw\\s(\\d+\\.\\d+)$" },
  { "xdvi-xaw", "^(\\d+\\.\\d+)$" }, { "debugfs", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "msmtp", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "icuinfo", "^(\\d+\\.\\d+\\.\\d+\\.\\d+)$" },
  { "ntlm_auth", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "msgfmt", "^(\\d+\\.\\d+\\.\\d+)$" }, { "lefty", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "msginit", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "nmblookup.samba3", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "sudo", "^(\\d+\\.\\d+\\.\\d+(p\\d+)?)$" },
  { "sudoreplay", "^(\\d+\\.\\d+\\.\\d+(p\\d+)?)$" },
  { "sudoedit", "^(\\d+\\.\\d+\\.\\d+(p\\d+)?)$" },
  { "dirname", "(?:^|\\.)(\\d+\\.\\d+)$" }, { "exim4", "^(\\d+\\.\\d+)$" },
  { "pactl", "^(\\d+\\.\\d+)$" }, { "gpgsplit", "^(\\d+\\.\\d+\\.\\d+)$" },
  { "awesome", "(\\d+\\.\\d+\\.\\d+-\\d+)" },
  { "cjpeg", "(\\d+\\w)\\s+\\d+-\\w+-\\d{4}" },
  { "djpeg", "(\\d+\\w)\\s+\\d+-\\w+-\\d{4}" },
  { "jpegtran", "(\\d+\\w)\\s+\\d+-\\w+-\\d{4}" },
  { "md5sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "sha1sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "sha224sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "sha256sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "sha384sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "sha512sum", "0123456789abcdef(\\d+\\.\\d+)" },
  { "dpkg", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|hurd-i386|"
            "i386|kfreebsd-amd64|kfreebsd-i386|m68k|mips|mipsel|powerpc|"
            "powerpcspe|ppc64|s390x|sparc64|x32)\\)" },
  { "dpkg-divert", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|hurd-"
                   "i386|i386|kfreebsd-amd64|kfreebsd-i386|m68k|mips|mipsel|"
                   "powerpc|powerpcspe|ppc64|s390x|sparc64|x32)\\)" },
  { "dpkg-statoverride", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|"
                         "hurd-i386|i386|kfreebsd-amd64|kfreebsd-i386|m68k|"
                         "mips|mipsel|powerpc|powerpcspe|ppc64|s390x|sparc64|"
                         "x32)\\)" },
  { "dpkg-deb", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|hurd-i386|"
                "i386|kfreebsd-amd64|kfreebsd-i386|m68k|mips|mipsel|powerpc|"
                "powerpcspe|ppc64|s390x|sparc64|x32)\\)" },
  { "dpkg-query", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|hurd-"
                  "i386|i386|kfreebsd-amd64|kfreebsd-i386|m68k|mips|mipsel|"
                  "powerpc|powerpcspe|ppc64|s390x|sparc64|x32)\\)" },
  { "dpkg-trigger", "((\\d+\\.)+\\d+)\\s\\((alpha|amd64|armel|armhf|hppa|hurd-"
                    "i386|i386|kfreebsd-amd64|kfreebsd-i386|m68k|mips|mipsel|"
                    "powerpc|powerpcspe|ppc64|s390x|sparc64|x32)\\)" },
  { "grotty", "\\?(\\d+\\.\\d+)$" }, { "wc", "\\?(\\d+\\.\\d+)$" },
  { "tail", "\\?(\\d+\\.\\d+)$" }, { "seq", "\\?(\\d+\\.\\d+)$" },
  { "aptitude-curses", "^aptitude\\s((\\d+\\.)+\\d+)$" },
  { "afm2tfm", "afm2tfm.*\\s((\\d+\\.)+\\d+)$" },
  { "dvipdfmx", "dvipdfmx-(\\d{8})" }, { "xml2ag", "xml2ag\\s.*(\\d+\\.\\d+)" },
  { "cmake", "cmake-(\\d+\\.\\d+\\.\\d+)$" },
  { "ctest", "cmake-(\\d+\\.\\d+\\.\\d+)$" },
  { "cpack", "cmake-(\\d+\\.\\d+\\.\\d+)$" },
  { "gccxml", "(?:gccxml-(\\d+\\.\\d+\\.\\d+))|(?:(\\d+\\.\\d+\\.\\d+)\\s\\("
              "gccxml.org\\))" },
  { "gccxml_cc1plus", "(\\d+\\.\\d+\\.\\d+)\\s\\(gccxml.org\\)" },
  { "sort", "\\?((\\d+\\.)+\\d+)" },
  { "testparm.samba3", "^((\\d+\\.){2}\\d+)$" },
  { "git", "^((\\d+\\.){3}\\d+)$" },
  { "dvilj4", "version\\s((\\d+\\.)+\\d+(p\\d+)?)" },
  { "dvilj4l", "version\\s((\\d+\\.)+\\d+(p\\d+)?)" },
  { "dvi2tty", "dvi2tty\\.c\\s((\\d+\\.)+\\d+)" },
  { "heirloom-mailx", "^(\\d+\\.)+\\d+\\s\\d+/\\d+/\\d+$" },
  { "ctags-exuberant", "^(\\d+\\.)+\\d+~svn\\d+$" },
  { "xz", "^xz\\s.*((\\d+\\.)\\d+(alpha)?)$" },
  { "lzmainfo", "lzmainfo\\s.*((\\d+\\.)\\d+(alpha)?)" },
  { "vlc", "VLC/((\\d+\\.)\\d+)" }, { "ld.bfd", "\\s(\\d+\\.\\d+)$" },
  { "autogen", "autogen.*\\s(\\d+\\.\\d+)$" },
  { "diffstat", "v\\s(\\d+\\.\\d+)\\s" }, { "zdump", "(\\d+\\.\\d+-\\d+)" },
  { "urxvt", "^urxvt-(\\d+\\.\\d+)$" }, { "urxvtd", "^urxvt-(\\d+\\.\\d+)$" },
  { "kmimetypefinder", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },
  { "ktrash", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },
  { "kstart", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },
  { "kjs", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },
  { "kdeinit4", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },
  { "kiconfinder", "(\\d+\\.\\d+\\.\\d+)\\s\\(\\1\\)" },

#define V_VERSION(name)                                                        \
  { #name, "v((\\d+[\\.-])+\\d+)" }
  V_VERSION(alsamixer), V_VERSION(busybox), V_VERSION(nc.traditional),
  V_VERSION(gpg), V_VERSION(gpgv), V_VERSION(hdparam), V_VERSION(qiv),
  V_VERSION(mdatopbm), V_VERSION(pbmtomda), V_VERSION(uconv),
  V_VERSION(wpa_cli),
#undef V_VERSION

#define BZ_VERSION "-(\\d+\\.\\d+\\.\\d+)"
  { "bzcat", BZ_VERSION }, { "bzip2", BZ_VERSION }, { "bunzip2", BZ_VERSION },
#undef BZ_VERSION

#define BINUTILS_VERSION(name)                                                 \
  { #name, "[Bb]inutils.*(\\d+\\.\\d+)" }
  BINUTILS_VERSION(addr2line), BINUTILS_VERSION(as), BINUTILS_VERSION(ar),
  BINUTILS_VERSION(c++ filt), BINUTILS_VERSION(dwp), BINUTILS_VERSION(elfedit),
  BINUTILS_VERSION(ld.gold), BINUTILS_VERSION(gprof), BINUTILS_VERSION(ranlib),
  BINUTILS_VERSION(size), BINUTILS_VERSION(strip), BINUTILS_VERSION(nm),
  BINUTILS_VERSION(objcopy), BINUTILS_VERSION(objdump), BINUTILS_VERSION(gdb),
  BINUTILS_VERSION(strings),
#undef BINUTILS_VERSION

#define DCTRL_TOOLS_VERSION(name)                                              \
  { #name, #name "\\s\\(dctrl-tools\\)\\s((\\d+\\.)+\\d+)" }
  DCTRL_TOOLS_VERSION(tbl - dctrl), DCTRL_TOOLS_VERSION(grep - dctrl),
  DCTRL_TOOLS_VERSION(join - dctrl), DCTRL_TOOLS_VERSION(sort - dctrl),
#undef DCTRL_TOOLS_VERSION

#define SVERSION_VERSION(name)                                                 \
  { #name, "version\\s(\\d+)" }
#define VERSION_VERSION(name)                                                  \
  { #name, "[vV]ersion\\s((\\d+\\.)+\\d+(-p(\\d+\\.)*\\d+)?)" }
  VERSION_VERSION(alsaucm), VERSION_VERSION(amidi), VERSION_VERSION(amixer),
  VERSION_VERSION(aplay), VERSION_VERSION(aplaymidi), VERSION_VERSION(arecord),
  VERSION_VERSION(arecordmidi), VERSION_VERSION(aseqdump), VERSION_VERSION(at),
  VERSION_VERSION(atq), VERSION_VERSION(atrm), VERSION_VERSION(bash),
  VERSION_VERSION(bibclean), VERSION_VERSION(clang), VERSION_VERSION(clang++),
  VERSION_VERSION(ctangle), VERSION_VERSION(depmod), VERSION_VERSION(dvilj),
  VERSION_VERSION(dvilj2p), VERSION_VERSION(eptex), VERSION_VERSION(euptex),
  VERSION_VERSION(faked - sysv), VERSION_VERSION(faked - tcp),
  VERSION_VERSION(feh), VERSION_VERSION(ifdown), VERSION_VERSION(ifquery),
  VERSION_VERSION(ifup), VERSION_VERSION(insmod), VERSION_VERSION(ischroot),
  SVERSION_VERSION(kmod), VERSION_VERSION(kpseaccess),
  VERSION_VERSION(kpsereadlink), VERSION_VERSION(kpsestat),
  VERSION_VERSION(lesskey), VERSION_VERSION(llvm - clang),
  VERSION_VERSION(lspci), VERSION_VERSION(lsmod), VERSION_VERSION(mf),
  VERSION_VERSION(mf - nowin), VERSION_VERSION(mft), SVERSION_VERSION(modinfo),
  SVERSION_VERSION(modprobe), VERSION_VERSION(otangle),
  VERSION_VERSION(odvitype), VERSION_VERSION(pdvitype), VERSION_VERSION(ps),
  VERSION_VERSION(ps2pk), VERSION_VERSION(ptftopl), VERSION_VERSION(rbash),
  VERSION_VERSION(rmmod), VERSION_VERSION(run - parts), VERSION_VERSION(setpci),
  VERSION_VERSION(vptovf), VERSION_VERSION(tangle), VERSION_VERSION(tex),
  VERSION_VERSION(ttf2afm), VERSION_VERSION(udevd), VERSION_VERSION(umax_pp),
  VERSION_VERSION(vlna), VERSION_VERSION(word - list - compress),
#undef VERSION_VERSION

#define NAME_VERSION(name)                                                     \
  { #name, #name ",?\\s+v?((\\d+[\\.-])+\\d+\\w*)" }
  NAME_VERSION(acpi), NAME_VERSION(apropos), NAME_VERSION(bzip2recover),
  NAME_VERSION(catman), NAME_VERSION(cryptsetup), NAME_VERSION(curl),
  NAME_VERSION(discover), NAME_VERSION(dosfsck), NAME_VERSION(dosfslabel),
  NAME_VERSION(halt), NAME_VERSION(htop), NAME_VERSION(hostapd),
  NAME_VERSION(hostapd_cli), NAME_VERSION(ifconfig), NAME_VERSION(init),
  NAME_VERSION(ipmaddr), NAME_VERSION(iptunnel), NAME_VERSION(inkscape),
  NAME_VERSION(killall5), NAME_VERSION(last), NAME_VERSION(lexgrog),
  NAME_VERSION(man), NAME_VERSION(mandb), NAME_VERSION(manpath),
  NAME_VERSION(nano), NAME_VERSION(pg), NAME_VERSION(plipconfig),
  NAME_VERSION(pulseaudio), NAME_VERSION(shutdown), NAME_VERSION(sulogin),
  NAME_VERSION(tempfile), NAME_VERSION(time), NAME_VERSION(usbhid - dump),
  NAME_VERSION(whatis), NAME_VERSION(xchat), NAME_VERSION(wpa_supplicant),
  NAME_VERSION(zsoelim),
#undef NAME_VERSION

#define NET_TOOLS_VERSION(name)                                                \
  { #name, "net-tools\\s((\\d+\\.)+\\d+)" }
  NET_TOOLS_VERSION(slattach), NET_TOOLS_VERSION(netstat),
  NET_TOOLS_VERSION(mii - tool), NET_TOOLS_VERSION(route),
#undef NET_TOOLS_VERSION

#define UTIL_LINUX_VERSION(name)                                               \
  { #name, "util-linux\\s(\\d+\\.\\d+\\.\\d+)" }
  UTIL_LINUX_VERSION(agetty), UTIL_LINUX_VERSION(blkid),
  UTIL_LINUX_VERSION(blockdev), UTIL_LINUX_VERSION(cfdisk),
  UTIL_LINUX_VERSION(chrt), UTIL_LINUX_VERSION(ddate),
  UTIL_LINUX_VERSION(dmesg), UTIL_LINUX_VERSION(fdisk),
  UTIL_LINUX_VERSION(fdformat), UTIL_LINUX_VERSION(flock),
  UTIL_LINUX_VERSION(fsck), UTIL_LINUX_VERSION(fsck.minix),
  UTIL_LINUX_VERSION(getopt), UTIL_LINUX_VERSION(getty),
  UTIL_LINUX_VERSION(hwclock), UTIL_LINUX_VERSION(isosize),
  UTIL_LINUX_VERSION(ionice), UTIL_LINUX_VERSION(ldattach),
  UTIL_LINUX_VERSION(logger), UTIL_LINUX_VERSION(mcookie),
  UTIL_LINUX_VERSION(mkfs), UTIL_LINUX_VERSION(mkfs.bfs),
  UTIL_LINUX_VERSION(mkfs.cramfs), UTIL_LINUX_VERSION(mkfs.minix),
  UTIL_LINUX_VERSION(mkswap), UTIL_LINUX_VERSION(more),
  UTIL_LINUX_VERSION(mount), UTIL_LINUX_VERSION(namei),
  UTIL_LINUX_VERSION(readprofile), UTIL_LINUX_VERSION(rename.ul),
  UTIL_LINUX_VERSION(renice), UTIL_LINUX_VERSION(rev),
  UTIL_LINUX_VERSION(rtcwake), UTIL_LINUX_VERSION(script),
  UTIL_LINUX_VERSION(scriptreplay), UTIL_LINUX_VERSION(setterm),
  UTIL_LINUX_VERSION(sfdisk), UTIL_LINUX_VERSION(swapoff),
  UTIL_LINUX_VERSION(swapon), UTIL_LINUX_VERSION(switch_root),
  UTIL_LINUX_VERSION(tailf), UTIL_LINUX_VERSION(taskset),
  UTIL_LINUX_VERSION(tunelp), UTIL_LINUX_VERSION(umount),
  UTIL_LINUX_VERSION(wall), UTIL_LINUX_VERSION(whereis),
  UTIL_LINUX_VERSION(wipefs),
#undef UTIL_LINUX_VERSION

#define KBD_VERSION(name)                                                      \
  { #name, "kbd\\s(\\d+\\.\\d+\\.\\d+)" }
  KBD_VERSION(openvt), KBD_VERSION(loadkeys), KBD_VERSION(chvt),
  KBD_VERSION(fgconsole), KBD_VERSION(setfont), KBD_VERSION(showconsolefont),
  KBD_VERSION(showkey), KBD_VERSION(setvtrgb), KBD_VERSION(screendump),
  KBD_VERSION(getkeycodes), KBD_VERSION(setkeycodes), KBD_VERSION(setmetamode),
  KBD_VERSION(loadunimap), KBD_VERSION(kbdinfo), KBD_VERSION(deallocvt),
  KBD_VERSION(setleds), KBD_VERSION(mapscrn), KBD_VERSION(dumpkeys),
  KBD_VERSION(kbd_mode), KBD_VERSION(kbdrate), KBD_VERSION(psfxtable),
#undef KBD_VERSION

#define NTFS_VERSION(name)                                                     \
  { #name, "(\\d{4}(\\.\\d){2}\\w+\\.\\d+)" }
  NTFS_VERSION(mkntfs), NTFS_VERSION(ntfs), NTFS_VERSION(ntfscat),
  NTFS_VERSION(ntfscmp), NTFS_VERSION(ntfscp), NTFS_VERSION(ntfsclone),
  NTFS_VERSION(ntfscluster), NTFS_VERSION(ntfsdecrypt),
  NTFS_VERSION(ntfsmftalloc), NTFS_VERSION(ntfstruncate),
  NTFS_VERSION(ntfsresize), NTFS_VERSION(ntfsundelete), NTFS_VERSION(ntfslabel),
  NTFS_VERSION(ntfsmove), NTFS_VERSION(ntfswipe), NTFS_VERSION(ntfsinfo),
  NTFS_VERSION(ntfsfix), NTFS_VERSION(ntfsls), NTFS_VERSION(ntfsdump_logfile),
  NTFS_VERSION(ntfs - 3g), NTFS_VERSION(ntfs - 3g.probe),
  NTFS_VERSION(lowntfs - 3g),
#undef NTFS_VERSION

  // default regexp: very restrictive
  { "", "^(\\d+\\.(\\d+\\.)*\\d+)$" }
};

/// \brief Manage the binding between a binary name and a regular expression
/// Implements the default behavior
class RegExFactory {

  std::map<std::string, boost::regex> database_;

public:
  RegExFactory() {
    // initializer lists would be soooo nice here
    for (size_t i = 0; i < sizeof(entries) / sizeof(*entries); ++i) {
      assert(database_.find(entries[i][0]) == database_.end());
      database_[entries[i][0]] = boost::regex(entries[i][1]);
    }
  }

  boost::regex const &get(std::string const &binary_name) {
    std::map<std::string, boost::regex>::const_iterator needle =
        database_.find(binary_name);
    if (needle == database_.end()) {
      return database_.find("")->second;
    } else {
      return needle->second;
    }
  }
} thefactory;
}

VersionScanner::VersionScanner(std::string const &binary_name)
    : regex_(thefactory.get(binary_name)) {}

void VersionScanner::operator()(std::set<std::string> &versions,
                                char const *begin, char const *end) {
  char const *needle = begin;

  while ((begin < end) && (needle = (char *)memchr(begin, 0, (end - begin)))) {
    boost::match_results<char const *> matches;
    if (boost::regex_search(begin, matches, regex_)) {
      // always record the outermost match
      versions.insert(std::string(matches[1].first, matches[1].second));
    }
    begin = needle + 1;
  }
}
