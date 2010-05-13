#!/bin/sh

REPOS="http://serf.googlecode.com/svn/trunk/"

if ! test -e serf.h ; then
  echo "$0 must be run from trunk"
  exit 1
fi

major="`sed -n '/SERF_MAJOR_VERSION/s/[^0-9]*//p' serf.h`"
minor="`sed -n '/SERF_MINOR_VERSION/s/[^0-9]*//p' serf.h`"
patch="`sed -n '/SERF_PATCH_VERSION/s/[^0-9]*//p' serf.h`"

version="serf-${major}.${minor}.${patch}"

work="${TMPDIR}/serf-dist.$$"
short='${TMPDIR}'/serf-dist.$$

echo "Preparing $version in $short ..."

mkdir $work
cd $work

echo "Exporting latest serf ..."
svn export --quiet $REPOS $version
echo "`find $version -type f | wc -l` files exported"

cd $version

if ! ./buildconf $* ; then
  echo "Exiting..."
  exit 1
fi

# Remove anything that should not be in the distribution
echo "Removing from release: dist.sh"
rm dist.sh

cd $work

tarball="${work}/${version}.tar"
tar -cf ${tarball} ${version}

bzip2 --keep ${tarball}
echo "${short}/${version}.tar.bz2 ready."

gzip -9 ${tarball}
echo "${short}/${version}.tar.gz ready."
