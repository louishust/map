# Copyright (c) 2016 GreatOpenSource LLC and/or its affiliates. All rights reserved.

MYSQL_ADD_PLUGIN(audit_log audit_log.c file_logger.c buffer.c audit_file.c
 audit_syslog.c
 MODULE_ONLY MODULE_OUTPUT_NAME "audit_log")
