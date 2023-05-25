#!/bin/sh

REPOS="https://svn.apache.org/repos/asf/serf"

if test $# != 1; then
  echo "USAGE: $0 TAG"
  exit 1
fi

version=$1

# provide for examining dist.sh output before creating a tag
if test "${version}" = "trunk"; then
  url="${REPOS}/trunk"
else
  url="${REPOS}/tags/${version}"
fi

release="serf-${version}"

# on Mac OS, TMPDIR is scary long. we want an unexpanded form in $short
work="${TMPDIR-/tmp}/serf-dist.$$"
short='${TMPDIR}'/serf-dist.$$

echo "Preparing ${release} in ${short} ..."

mkdir "${work}"
cd "${work}"

echo "Exporting latest serf ..."
svn export --quiet "${url}" "${release}" || exit 1
echo "`find ${release} -type f | wc -l` files exported"

prepare_directory()
{
cd "${release}"

# Remove anything that should not be in the distribution
echo "Removing from release: dist.sh STATUS"
rm dist.sh
[ -r STATUS ] && rm STATUS

major="`sed -n '/SERF_MAJOR_VERSION/s/[^0-9]*//gp' serf.h`"
minor="`sed -n '/SERF_MINOR_VERSION/s/[^0-9]*//gp' serf.h`"
patch="`sed -n '/SERF_PATCH_VERSION/s/[^0-9]*//gp' serf.h`"

actual_version="${major}.${minor}.${patch}"

cd "${work}"

if test "${version}" != "trunk" -a "${version%%-*}" != "${actual_version}"; then
  echo "ERROR: exported version '${actual_version}' does not match '${version}'"
  exit 1
fi

}

prepare_directory

tarball="${work}/${release}.tar"
tar -cf "${tarball}" "${release}"

bzip2 "${tarball}"
echo "${short}/${release}.tar.bz2 ready."

# Let's redo everything for a Windows .zip file
echo "Saving ${release} as ${release}.unix"
mv "${release}" "${release}.unix"

echo "Exporting latest serf using CRLF ..."
svn export --native-eol=CRLF --quiet "${url}" "${release}" || exit 1
echo "`find ${release} -type f | wc -l` files exported"

prepare_directory

if ! diff -brq "${release}.unix" "${release}"; then
  echo "ERROR: export directories differ."
  exit 1
fi

zipfile="${work}/${release}.zip"
zip -9rq "${zipfile}" "${release}"
echo "${short}/${release}.zip ready."

echo "Saving ${release} as ${release}.win"
mv "${release}" "${release}.win"

cd ${work}

# allow checksum tool names to be overridden
[ -n "$MD5SUM" ] || MD5SUM=md5sum
[ -n "$SHA1SUM" ] || SHA1SUM=sha1sum
[ -n "$SHA256SUM" ] || SHA256SUM=sha256sum

echo ""
echo "Done:"

sign_file()
{
  if [ -n "$SIGN" ]; then
    type gpg > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      if test -n "$user"; then
        args="--default-key $user"
      fi
      for ARG in $@
      do
        gpg --armor $args --detach-sign $ARG
      done
    else
      type pgp > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        if test -n "$user"; then
          args="-u $user"
        fi
        for ARG in $@
        do
          pgp -sba $ARG $args
        done
      fi
    fi
  fi
}

ls -l "${release}.tar.bz2" "${release}.zip"
sign_file ${release}.tar.bz2 ${release}.zip
echo ""
echo "md5sums:"
$MD5SUM "${release}.tar.bz2" "${release}.zip"
echo ""
echo "sha1sums:"
$SHA1SUM "${release}.tar.bz2" "${release}.zip"
echo ""
echo "sha256sums:"
$SHA256SUM "${release}.tar.bz2" "${release}.zip"
echo ""
