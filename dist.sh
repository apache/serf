#!/bin/sh

REPOS="http://serf.googlecode.com/svn/trunk/"

CONTENTS="[CLMNR]* buckets build buildconf config* context.c \
          design-guide.txt *.h serf.mak serfmake test"


major="`sed -n '/SERF_MAJOR_VERSION/s/[^0-9]*//p' serf.h`"
minor="`sed -n '/SERF_MINOR_VERSION/s/[^0-9]*//p' serf.h`"
patch="`sed -n '/SERF_PATCH_VERSION/s/[^0-9]*//p' serf.h`"

version="serf-${major}.${minor}.${patch}"

work="${TMPDIR}/serf-dist.$$"

echo "Preparing $version in $work ..."

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

cd $work

tarball="${work}/${version}.tar"
tar --no-recursion -cf ${tarball} ${version}
for item in ${CONTENTS} ; do
  if ! tar --append -f ${tarball} ${version}/${item} ; then
    echo "${tarball} failed."
    exit 1
  fi
done

bzip2 --keep ${tarball}
echo "${tarball}.bz2 ready."

gzip -9 ${tarball}
echo "${tarball}.gz ready."
