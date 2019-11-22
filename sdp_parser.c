#include "sdp_parser.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int sdp_parser_init(sdp_parser_t *parser, const char *source, size_t length) {
    parser->source = source;
    parser->cursor = source;
    parser->eof = source + length;
    parser->index = 0;
    parser->type = 0;
    parser->length = 0;
    parser->state = SDP_PARSE_FIELD;
    return 0;
}

int sdp_parser_execute(sdp_parser_t *parser, sdp_parser_setting_t *setting) {
    int result;
    while (parser->cursor < parser->eof) {
        if (*parser->cursor == '=') {
            if (parser->state == SDP_PARSE_FIELD) {
                parser->type = parser->cursor[-1];
                _try(setting->on_field_begin(parser, parser->type, parser->index));
                parser->length = 0;
                parser->state = SDP_PARSE_DESCRIBE;
            } else {
                parser->length++;
            }
            parser->cursor++;
        } else if (isspace(*(unsigned char *)parser->cursor)) {
            if (parser->length > 0 && parser->state == SDP_PARSE_DESCRIBE) {
                _try(setting->on_describe(parser, parser->index, parser->cursor - parser->length, parser->length));
                parser->index++;
                parser->length = 0;
            }
            if (parser->cursor[0] == '\r' && parser->cursor[1] == '\n') {
                _try(setting->on_field_end(parser, parser->type, parser->index));
                parser->index = 0;
                parser->state = SDP_PARSE_FIELD;
                parser->cursor += 2;
            } else if (parser->cursor[0] == '\r' || parser->cursor[0] == '\n') {
                _try(setting->on_field_end(parser, parser->type, parser->index));
                parser->state = SDP_PARSE_FIELD;
                parser->index = 0;
                parser->cursor++;
            } else {
                parser->cursor++;
            }
        } else {
            parser->cursor++;
            parser->length++;
        }
    }
    if (parser->length > 0 && parser->state == SDP_PARSE_DESCRIBE) {
        _try(setting->on_describe(parser, parser->index, parser->cursor - parser->length, parser->length));
        parser->index++;
        parser->length = 0;
    }
    if (parser->cursor == parser->eof && parser->state == SDP_PARSE_DESCRIBE) {
        _try(setting->on_field_end(parser, parser->type, parser->index));
        parser->index = 0;
        parser->state = SDP_PARSE_FIELD;
    }
_catch:
    return result;
}
