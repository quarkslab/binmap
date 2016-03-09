======
Binmap
======


What is it?
-----------

Binmap is a system scanner; it takes a system or system image and walks through
all files, looking for programs and libraries and collecting various
information such as dependencies, symbols etc.

It supports ELF and PE formats.

Installation
------------

Debian/Ubuntu
=============

The following packages are needed:

    - cmake
    - g++
    - libboost-python1.55-dev
    - libboost-system1.55-dev
    - libboost-program-options1.55-dev
    - libboost-filesystem1.55-dev
    - libboost-regex1.55-dev
    - libboost-serialization1.55-dev
    - zlib1g-dev
    - libssl-dev
    - libelfg0-dev

Then run::

    $ mkdir _build
    $ cd _build
    $ cmake ..
    $ make

Eventually as root::

    $ make install

Windows
=======

You need Visual Studio installed & ready. Then:

    1. Insall cmake (http://www.cmake.org/cmake/resources/software.html) and make sure it's in your path.

    2. Get zlib (http://www.zlib.net/)

    3. Get boost (get precompiled binaries http://boost.teeks99.com/)

Then run something like the following::

    $ cmake -DBoost_DEBUG=ON -G "Visual Studio 12" -DBoost_USE_STATIC_LIBS=ON -DBOOST_ROOT=D:\Programming\Libraries\boost_1_55_0 -DBOOST_LIBRARYDIR=D:\Programming\Libraries\boost_1_55_0\lib32-msvc-12.0 -DZLIB_LIBRARY=D:\Programming\Libraries\zlib-1.2.8 -DZLIB_INCLUDE_DIR=D:\Programming\Libraries\zlib-1.2.8


Usage
-----

Using binmap is a two step process:

1. Scan a directory, for instance::

    $ ./binmap scan -v1 /usr/local -o local.dat

   This creates a database containing informations about the binaries that lie in this directory.

2. Dump the database to the dot format::

    $ ./binmap view -i local.dat -o local.dot

   or inspect the database using the Python API described below.


Python API
----------

The ``blobmap`` module gives a read-only access to the content of a binmap database::

    >>> import blobmap

First thing to do is to load a database::

    >>> blobs = blobmap.BlobMap('local.dat')

A ``BlobMap`` is an ordered container of blobs, in chronologial order, last being the most recent entry::

    >>> blob = blobs.last()

A blob is basically a directed graph, where nodes are binaries and edges
represent a use dependency---something like this program depends on this
library. It can be indexed by paths, as in::

    >>> clang_metadata = blob['/usr/local/bin/clang']
    >>> print(str(clang_metadata))
    clang: 8fcffc4a97cd4aaa1a32938a9e95d3b253476121(13223 exported symbols)(1303 imported symbols)(1 hardening features)

One can access the metadata for each node independently::

    >>> clang_metadata.hash
    8fcffc4a97cd4aaa1a32938a9e95d3b253476121
    >>> clang_metadata.hardening_features
    {'fortified'}
    >>> help(clang_metadata)
    [...]

The graph can be navigated using the ``successors`` and ``predecessors`` methods::

    >>> blob.successors('/usr/local/bin/clang')
    {'/lib/x86_64-linux-gnu/libtinfo.so.5',
     '/lib/x86_64-linux-gnu/libz.so.1',
     '/lib32/libc.so.6',
     ...}

It's also possible to make a diff between two blob, in order to gather intel concerning the changes of state of a system::

    >>> from blobmap import BlobMap as BM
    >>> b = BM('mynewprog.dat')
    >>> g1, g0 = [b[k] for k in b.keys()][-2:]
    >>> diff = g0.diff(g1)
    >>> diff.added
    {'/.../libmy1.so'}
    >>> diff.removed
    {'/.../libmy0.so'}
    >>> diff.updated
    {'/.../myprog'}


Testing
-------

A simple test is to scan yourself::

    $ ./binmap scan -v2 ./binmap

or::

    $ binmap.exe scan -v2 binmap.exe


For linux users, run CTests::

    $ make test


Cross compiling
---------------

See ``tools/cross.sh``


Authors
-------

- Serge Guelton <sguelton@quarkslab.com>
- Sébastien Renaud <srenaud@quarkslab.com>

