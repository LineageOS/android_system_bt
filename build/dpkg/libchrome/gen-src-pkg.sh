#!/bin/bash
# Generates Debian source and binary packages of libchrome.

if [ -z "$1" ]; then
        echo "Usage: gen-src-pkg.sh <output-dir>"
        exit 1
fi

outdir="$1"
pkgdir=libchrome-780652
origtar=libchrome_780652.orig.tar.gz
scriptdir="$( cd "$( dirname "$0" )" && pwd )"
branch=release-R90-13816.B

tmpdir=$(mktemp -d)
echo Generating source package in "${tmpdir}".

# Download platform2 source.
cd "${tmpdir}"
git clone --branch "${branch}" https://chromium.googlesource.com/chromiumos/platform2 || exit 1
mkdir "${pkgdir}"
cd "${pkgdir}"
# Trim platform2, only common-mk is needed.
cp -a ../platform2/{common-mk,.gn} .

# Download libchrome source and apply Chrome OS's patches.
git clone --branch "${branch}" https://chromium.googlesource.com/aosp/platform/external/libchrome || exit 1
cd libchrome
rm -rf .git
while read -r patch; do
  patch -p1 < "libchrome_tools/patches/${patch}"
done < <(grep -E '^[^#]' "libchrome_tools/patches/patches")

# Clean up temporary platform2 checkout.
cd ../..
rm -rf platform2

# Debian requires creating .orig.tar.gz.
tar czf "${origtar}" "${pkgdir}"

# Debianize the source.
cd "${pkgdir}"
yes | debmake || exit 1
cp -aT "${scriptdir}/debian/" "${tmpdir}/${pkgdir}/debian/"

# Build source package and binary package.
cd "${tmpdir}/${pkgdir}"
dpkg-buildpackage --no-sign || exit 1

# Copy the results to output dir.
cd "${tmpdir}"
mkdir -p "${outdir}/src"
cp *.dsc *.orig.tar.gz *.debian.tar.xz "${outdir}/src"
cp *.deb "${outdir}"
cd /

echo Removing temporary directory "${tmpdir}".
rm -rf "${tmpdir}"

echo Done. Check out Debian source package in "${outdir}".
