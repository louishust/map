/* Copyright (c) 2016 GreatOpenSource and/or its affiliates. All rights reserved. */

#ifndef AUDIT_LOG_BUFFER_INCLUDED
#define AUDIT_LOG_BUFFER_INCLUDED

#include <string.h> // for size_t
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct audit_log_buffer audit_log_buffer_t;

typedef int (*audit_log_write_func)(void *data, const char *buf, size_t len,
                                    log_record_state_t state);

audit_log_buffer_t *audit_log_buffer_init(size_t size, int drop_if_full,
                                 audit_log_write_func write_func, void *data);
void audit_log_buffer_shutdown(audit_log_buffer_t *log);
int audit_log_buffer_write(audit_log_buffer_t *log,
                           const char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
