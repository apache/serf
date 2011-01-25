#!/bin/sh

REPOS="http://serf.googlecode.com/svn/"

if test $# != 2; then
  echo "USAGE: $0 TAG APR-SOURCE-PARENT"
  exit 1
fi

version=$1
srcdir=$2

release="serf-${version}"

work="${TMPDIR-/tmp}/serf-dist.$$"
short='${TMPDIR}'/serf-dist.$$

echo "Preparing ${release} in ${short} ..."

mkdir "${work}"
cd "${work}"

echo "Exporting latest serf ..."
svn export --quiet "${REPOS}/tags/${version}" "${release}" || exit 1
echo "`find ${release} -type f | wc -l` files exported"

cd "${release}"

if ! ./buildconf --with-apr="${srcdir}/apr" --with-apr-util="${srcdir}/apr-util" ; then
  echo "Exiting..."
  exit 1
fi

# Remove anything that should not be in the distribution
echo "Removing from release: dist.sh"
rm dist.sh

major="`sed -n '/SERF_MAJOR_VERSION/s/[^0-9]*//p' serf.h`"
minor="`sed -n '/SERF_MINOR_VERSION/s/[^0-9]*//p' serf.h`"
patch="`sed -n '/SERF_PATCH_VERSION/s/[^0-9]*//p' serf.h`"

actual_version="${major}.${minor}.${patch}"

cd $work

if test "${version}" != "${actual_version}"; then
  echo "ERROR: exported version does not match"
  exit 1
fi

tarball="${work}/${release}.tar"
tar -cf "${tarball}" "${release}"

bzip2 --keep "${tarball}"
echo "${short}/${release}.tar.bz2 ready."

gzip -9 "${tarball}"
echo "${short}/${release}.tar.gz ready."
