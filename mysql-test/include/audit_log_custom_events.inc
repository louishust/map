# produce some events for audit log

CREATE TABLE t1 (c1 INT, c2 CHAR(20));
--error ER_TABLE_EXISTS_ERROR
CREATE TABLE t1
             (c1 INT,
              c2 CHAR(20));
INSERT INTO t1 VALUES (1,'a'),(2,'b'),(3,'c');
SELECT * FROM t1;
--error ER_NO_SUCH_TABLE
SELECT * FROM t2;
DROP TABLE t1;

PREPARE stmt1 FROM 'SELECT 1';
EXECUTE stmt1;
SHOW STATUS LIKE 'audit_log%';

DEALLOCATE PREPARE stmt1;

show variables like 'audit_log%';
connect (con1,localhost,root,,mysql);
connection default;
disconnect con1;
--replace_result $MASTER_MYSOCK MASTER_SOCKET $MASTER_MYPORT MASTER_PORT
--error ER_ACCESS_DENIED_ERROR
connect (con1,localhost,no_such_user,,mysql);
connection default;
create table t1 (id int);
create table t2 (id int);
insert into t1 values (1), (2);
insert into t2 values (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2), (1), (2);
select * from t1;
alter table t1 rename renamed_t1;
--error ER_NO_SUCH_TABLE
select * from t_doesnt_exist;
--error 1064
syntax_error_query;
drop table renamed_t1, t2;
show variables like 'audit_log%';
create database sa_db;
connect (con1,localhost,root,,test);
connection con1;
create table t1 (id2 int);
insert into t1 values (1), (2);
select * from t1;
drop table t1;
use sa_db;
create table sa_t1(id int);
insert into sa_t1 values (1), (2);
drop table sa_t1;
drop database sa_db;
connection default;
create user 'jeffrey'@'localhost' IDENTIFIED BY 'mypass';
drop user 'jeffrey'@'localhost';
select '&;&&&""""<><<>>>>';
disconnect con1;

## test for custom statement
connection default;
create table t1(c1 int);
alter table t1 add index idx1(c1);
create index idx2 on t1(c1);
drop index idx2 on t1;
grant all on *.* to u1@'%' identified by 'xxxxxxxx';
revoke all on *.* from u1@'%';
drop user u1@'%';
truncate table t1;
select * from t1;
drop table t1;
set global max_connections=151;
set names utf8;
create database db1;
alter database db1 CHARACTER SET utf8mb4;
drop database db1;

CREATE SERVER s
FOREIGN DATA WRAPPER mysql
OPTIONS (USER 'Remote', HOST '192.168.1.106', DATABASE 'test');
ALTER SERVER s OPTIONS (USER 'sally');
DROP SERVER s;
