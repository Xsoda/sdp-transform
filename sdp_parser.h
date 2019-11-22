#ifndef __SDP_PARSER_H__
#define __SDP_PARSER_H__

#include <stdint.h>
#include <stdlib.h>

#define EXC_STR(X) #X
#define EXC_TOSTR(x) EXC_STR(x)
#define EXC_PRINT puts("Exc: " __FILE__ ":" EXC_TOSTR(__LINE__) "\n");

#define _try(TRY) { result = TRY; if (result) { EXC_PRINT; goto _catch; } }
#define _throw(ERROR) { result = ERROR; EXC_PRINT; goto _catch; }

enum {
    SDP_PARSE_FIELD,
    SDP_PARSE_DESCRIBE,
};

typedef struct sdp_parser {
    const char *source;
    const char *cursor;
    const char *eof;
    size_t length;
    int state;
    int index;
    uint8_t type;
    void *data;
} sdp_parser_t;

typedef int (*sdp_field_cb)(sdp_parser_t *parser, uint8_t type, int count);
typedef int (*sdp_describe_cb)(sdp_parser_t *parser, int index, const char *at, size_t length);

typedef struct sdp_parser_setting {
    sdp_field_cb on_field_begin;
    sdp_describe_cb on_describe;
    sdp_field_cb on_field_end;
} sdp_parser_setting_t;

int sdp_parser_init(sdp_parser_t *parser, const char *source, size_t length);
int sdp_parser_execute(sdp_parser_t *parser, sdp_parser_setting_t *setting);

#endif  /* !__SDP_PARSER_H__ */
