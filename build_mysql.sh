#!/bin/bash
if [ -d debug ]
then
  cd debug
  make && make install
else
  mkdir debug
  cd debug

  cmake -DWITH_DEBUG=1 -DCMAKE_INSTALL_PREFIX=./mysql  -DMYSQL_DATADIR=./mysql/data \
    -DWITH_SSL=yes -DENABLED_LOCAL_INFILE=1 -DWITH_READLINE=1 \
    -DMY_MAINTAINER_CXX_WARNINGS="-Wall -Wextra -Wunused -Wwrite-strings -Wno-strict-aliasing  -Wno-unused-parameter -Woverloaded-virtual" \
    -DMY_MAINTAINER_C_WARNINGS="-Wall -Wextra -Wunused -Wwrite-strings -Wno-strict-aliasing -Wdeclaration-after-statement" \
    ..

  make && make install

  cd mysql
  cur_path=`pwd`
  echo "[mysqld]
  gdb
  basedir=${cur_path}/
  datadir=${cur_path}/data
  socket=${cur_path}/data/my.sock
  " > my.cnf


  # create default database
  cd scripts
  ./mysql_install_db --defaults-file=../my.cnf --datadir=../data --basedir=../ --user=$whoami

fi
