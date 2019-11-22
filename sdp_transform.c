#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "sdp_transform.h"
#include "sdp_parser.h"
#include "cbor.h"

enum {
    ATTRI_NONE,
    ATTRI_FINGERPRINT,
    ATTRI_RTPMAP,
    ATTRI_FMTP,
    ATTRI_EXT,
    ATTRI_RTCP,
    ATTRI_CANDIDATE,
    ATTRI_SSRC,
    ATTRI_RTCPFB,
    ATTRI_CRYPTO,
    ATTRI_MSID,
    ATTRI_SOURCE_FILTER,
    ATTRI_SIMULCAST,
    ATTRI_SIMULCAST03,
    ATTRI_RID,
    ATTRI_MSID_SEMANTIC,
    ATTRI_SSRC_GROUP,
    ATTRI_GROUP,
    ATTRI_SCTPMAP,
    ATTRI_KEYWORDS,
    ATTRI_FLOORID,
    ATTRI_CONTENT,
    ATTRI_MEDIACLK,
    ATTRI_UNKNOWN,
};

typedef struct sdp_transform {
    cbor_value_t *root;
    uint8_t type;
    int attri;
    int top;
    cbor_value_t *stack[8];
} sdp_transform_t;

#define transform_push(transform, val) (transform)->stack[(transform)->top++] = (val)
#define transform_pop(transform) ((transform)->stack[--(transform)->top])
#define transform_top(transform) ((transform)->stack[(transform)->top - 1])

int sdp_transform_version(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_origin(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_media(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_string(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_connection(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_timezone(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_bandwidth(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_timing(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_attribute(sdp_transform_t *transform, int index, const char *at, size_t length);
int sdp_transform_repeat(sdp_transform_t *transform, int index, const char *at, size_t length);

static int on_field_begin(sdp_parser_t *parser, uint8_t type, int count) {
    sdp_transform_t *transform = (sdp_transform_t *)parser->data;
    transform->type = type;
    if (type == 'o'
        || type == 'b'
        || type == 't'
        || type == 'c') {
        cbor_value_t *ele = cbor_init_map();
        transform_push(transform, ele);
    } else if (type == 'p'
               || type == 'e'
               || type == 'i'
               || type == 'u'
               || type == 's') {
        cbor_value_t *ele = cbor_init_string("", 0);
        transform_push(transform, ele);
    } else if (type == 'm') {
        cbor_value_t *media = cbor_map_dotget(transform->root, "media");
        if (media == NULL) {
            media = cbor_init_array();
            cbor_map_set_value(transform->root, "media", media);
        }
        cbor_value_t *ele = cbor_init_map();
        cbor_container_insert_tail(media, ele);
        transform_push(transform, ele);
    } else if (type == 'a') {
        transform->attri = ATTRI_NONE;
    }
    return 0;
}

static int on_describe(sdp_parser_t *parser, int index, const char *at, size_t length) {
    int result;
    sdp_transform_t *transform = (sdp_transform_t *)parser->data;
    uint8_t type = transform->type;
    if (type == 'v') {
        _try(sdp_transform_version(transform, index, at, length));
    } else if (type == 'o') {
        _try(sdp_transform_origin(transform, index, at, length));
    } else if (type == 'm') {
        _try(sdp_transform_media(transform, index, at, length));
    } else if (type == 'c') {
        _try(sdp_transform_connection(transform, index, at, length));
    } else if (type == 'z') {
        _try(sdp_transform_timezone(transform, index, at, length));
    } else if (type == 'b') {
        _try(sdp_transform_bandwidth(transform, index, at, length));
    } else if (type == 't') {
        _try(sdp_transform_timing(transform, index, at, length));
    } else if (type == 'r') {
        _try(sdp_transform_repeat(transform, index, at, length));
    } else if (type == 'a') {
        _try(sdp_transform_attribute(transform, index, at, length));
    } else if (type == 'p'
               || type == 'e'
               || type == 'i'
               || type == 'u'
               || type == 's') {
        _try(sdp_transform_string(transform, index, at, length));
    }
_catch:
    return result;
}

static int on_field_end(sdp_parser_t *parser, uint8_t type, int count) {
    sdp_transform_t *transform = (sdp_transform_t *)parser->data;
    if (type == 'o') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "origin", ele);
    } else if (type == 'c') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "connection", ele);
    } else if (type == 'b') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "bandwidth", ele);
    } else if (type == 't') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "timing", ele);
    } else if (type == 'p') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "phone", ele);
    } else if (type == 'e') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "email", ele);
    } else if (type == 's') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "name", ele);
    } else if (type == 'i') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "description", ele);
    } else if (type == 'u') {
        cbor_value_t *ele = transform_pop(transform);
        cbor_map_set_value(transform_top(transform), "uri", ele);
    } else if (type == 'a' && transform->attri != ATTRI_NONE) {
        transform_pop(transform);
    }
    return 0;
}

int sdp_transform_version(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        int version = strtol(at, NULL, 10);
        cbor_map_set_integer(transform->root, "version", version);
        return 0;
    }
    return -1;
}

int sdp_transform_origin(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        cbor_value_t *username = cbor_init_string(at, length);
        cbor_map_set_value(transform_top(transform), "username", username);
    } else if (index == 1) {
        long long sessionid = strtol(at, NULL, 10);
        cbor_map_set_integer(transform_top(transform), "session_id", sessionid);
    } else if (index == 2) {
        long long sessionver = strtol(at, NULL, 10);
        cbor_map_set_integer(transform_top(transform), "session_version", sessionver);
    } else if (index == 3) {
        cbor_value_t *net_type = cbor_init_string(at, length);
        cbor_map_set_value(transform_top(transform), "net_type", net_type);
    } else if (index == 4) {
        if (!strncmp(at, "IP", 2)) {
            long long ip_ver = strtol(at + 2, NULL, 10);
            cbor_map_set_integer(transform_top(transform), "ip_ver", ip_ver);
        }
    } else if (index == 5) {
        cbor_value_t *address = cbor_init_string(at, length);
        cbor_map_set_value(transform_top(transform), "address", address);
    }
    return 0;
}

int sdp_transform_media(sdp_transform_t *transform, int index, const char *at, size_t length) {
    cbor_value_t *last = transform_top(transform);
    if (index == 0) {
        cbor_value_t *type = cbor_init_string(at, length);
        cbor_map_set_value(last, "type", type);
    } else if (index == 1) {
        int port = strtol(at, NULL, 10);
        cbor_map_set_integer(last, "port", port);
    } else if (index == 2) {
        cbor_value_t *protocol = cbor_init_string(at, length);
        cbor_map_set_value(last, "protocol", protocol);
    } else if (index == 3) {
        cbor_value_t *payloads = cbor_init_string(at, length);
        cbor_map_set_value(last, "payloads", payloads);
    } else {
        cbor_value_t *payloads = cbor_map_dotget(last, "payloads");
        cbor_blob_append_byte(payloads, 0x20);
        cbor_blob_append(payloads, at, length);
    }
    return 0;
}

int sdp_transform_string(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        cbor_blob_append(transform_top(transform), at, length);
    } else {
        cbor_blob_append_byte(transform_top(transform), 0x20);
        cbor_blob_append(transform_top(transform), at, length);
    }
    return 0;
}

int sdp_transform_connection(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 1) {
        if (!strncmp(at, "IP", 2)) {
            int ver = strtol(at + 2, NULL, 10);
            cbor_map_set_integer(transform_top(transform), "ip_ver", ver);
        }
    } else if (index == 2) {
        cbor_value_t *ip = cbor_init_string(at, length);
        cbor_map_set_value(transform_top(transform), "address", ip);
    }
    return 0;
}

int sdp_transform_timezone(sdp_transform_t *transform, int index, const char *at, size_t length) {
    return 0;
}

int sdp_transform_bandwidth(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        char *ch = strchr(at, ':');
        if (ch && ch < at + length) {
            cbor_value_t *type = cbor_init_string(at, ch - at);
            cbor_map_set_value(transform_top(transform), "type", type);
            int limit = strtol(ch + 1, NULL, 10);
            cbor_map_set_integer(transform_top(transform), "limit", limit);
        }
    }
    return 0;
}

int sdp_transform_timing(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        int start = strtol(at, NULL, 10);
        cbor_map_set_integer(transform_top(transform), "start", start);
    } else if (index == 1) {
        int stop = strtol(at, NULL, 10);
        cbor_map_set_integer(transform_top(transform), "stop", stop);
    }
    return 0;
}

int sdp_transform_encryptionkey(sdp_transform_t *transform, int index, const char *at, size_t length) {

}

int sdp_transform_attribute(sdp_transform_t *transform, int index, const char *at, size_t length) {
    cbor_value_t *last = transform_top(transform);
    if (index == 0) {
        if (!strncmp(at, "ice-ufrag:", 10) && length > 10) {
            cbor_value_t *ufrag = cbor_init_string(at + 10, length - 10);
            cbor_map_set_value(last, "ice_ufrag", ufrag);
        } else if (!strncmp(at, "ice-pwd:", 8) && length > 8) {
            cbor_value_t *pwd = cbor_init_string(at + 8, length - 8);
            cbor_map_set_value(last, "ice_pwd", pwd);
        } else if (!strncmp(at, "ice-options:", 12) && length > 12) {
            cbor_value_t *options = cbor_init_string(at + 12, length - 12);
            cbor_map_set_value(last, "ice_options", options);
        } else if (!strncmp(at, "fingerprint:", 12) && length > 12) {
            cbor_value_t *type = cbor_init_string(at + 12, length - 12);
            cbor_value_t *fingerprint = cbor_init_map();
            cbor_map_set_value(fingerprint, "type", type);
            cbor_map_set_value(last, "fingerprint", fingerprint);
            transform->attri = ATTRI_FINGERPRINT;
            transform_push(transform, fingerprint);
        } else if (!strncmp(at, "framerate:", 10)) {
            double framerate = strtod(at + 10, NULL);
            cbor_map_set_double(last, "framerate", framerate);
        } else if (!strncmp(at, "label:", 6)) {
            cbor_value_t *label = cbor_init_string(at + 6, length - 6);
            cbor_map_set_value(last, "label", label);
        } else if (!strncmp(at, "simulcast:", 10)) {
            if (length > 10) {
                cbor_value_t *simulcast = cbor_init_map();
                cbor_map_set_value(last, "simulcast", simulcast);
                cbor_value_t *dir1 = cbor_init_string(at + 10, length - 10);
                cbor_map_set_value(simulcast, "dir1", dir1);
                transform->attri = ATTRI_SIMULCAST;
                transform_push(transform, simulcast);
            } else {
                cbor_value_t *simulcast = cbor_init_map();
                cbor_map_set_value(last, "simulcast_03", simulcast);
                transform->attri = ATTRI_SIMULCAST03;
                transform_push(transform, simulcast);
            }
        } else if (!strncmp(at, "rtpmap:", 7) && length > 7) {
            int payload = strtol(at + 7, NULL, 10);
            cbor_value_t *rtpmap = cbor_map_dotget(transform_top(transform), "rtp");
            cbor_value_t *ele = cbor_init_map();
            cbor_map_set_integer(ele, "payload", payload);
            if (rtpmap == NULL) {
                rtpmap = cbor_init_array();
                cbor_map_set_value(last, "rtp", rtpmap);
            }
            cbor_container_insert_tail(rtpmap, ele);
            transform_push(transform, ele);
            transform->attri = ATTRI_RTPMAP;
        } else if (!strncmp(at, "fmtp:", 5)) {
            int payload = strtol(at + 5, NULL, 10);
            cbor_value_t *fmtp = cbor_map_dotget(transform_top(transform), "fmtp");
            cbor_value_t *ele = cbor_init_map();
            cbor_map_set_integer(ele, "payload", payload);
            if (fmtp == NULL) {
                fmtp = cbor_init_array();
                cbor_map_set_value(last, "fmtp", fmtp);
            }
            cbor_container_insert_tail(fmtp, ele);
            transform_push(transform, ele);
            transform->attri = ATTRI_FMTP;
        } else if (!strncmp(at, "rtcp:", 5)) {
            int port = strtol(at + 5, NULL, 10);
            cbor_value_t *ele = cbor_init_map();
            cbor_map_set_integer(ele, "port", port);
            cbor_map_set_value(last, "rtcp", ele);
            transform_push(transform, ele);
            transform->attri = ATTRI_RTCP;
        } else if (!strncmp(at, "control:", 8)) {
            cbor_value_t *control = cbor_init_string(at + 8, length - 8);
            cbor_map_set_value(last, "control", control);
        } else if (!strncmp(at, "extmap:", 7)) {
            char *end;
            int value = strtol(at + 7, &end, 10);
            cbor_value_t *ext = cbor_map_dotget(last, "ext");
            cbor_value_t *ele = cbor_init_map();
            cbor_map_set_integer(ele, "value", value);
            if (ext == NULL) {
                ext = cbor_init_array();
                cbor_map_set_value(last, "ext", ext);
            }
            cbor_container_insert_tail(ext, ele);
            if (*end == '/') {
                cbor_value_t *direction = cbor_init_map(end + 1, at + length - end - 1);
                cbor_map_set_value(ext, "direction", direction);
            }
            transform_push(transform, ele);
            transform->attri = ATTRI_EXT;
        } else if (!strncmp(at, "candidate:", 10)) {
            long long foundation = strtoll(at + 10, NULL, 10);
            cbor_value_t *candidates = cbor_map_dotget(last, "candidates");
            cbor_value_t *ele = cbor_init_map();
            if (candidates == NULL) {
                candidates = cbor_init_array();
                cbor_map_set_value(last, "candidates", candidates);
            }
            cbor_container_insert_tail(candidates, ele);
            cbor_map_set_integer(ele, "foundation", foundation);
            transform_push(transform, ele);
            transform->attri = ATTRI_CANDIDATE;
        } else if (!strncmp(at, "ssrc:", 5)) {
            long long id = strtoll(at + 5, NULL, 10);
            cbor_value_t *ssrcs = cbor_map_dotget(last, "ssrcs");
            cbor_value_t *ele = cbor_init_map();
            if (ssrcs == NULL) {
                ssrcs = cbor_init_array();
                cbor_map_set_value(last, "ssrcs", ssrcs);
            }
            cbor_container_insert_tail(ssrcs, ele);
            cbor_map_set_integer(ele, "id", id);
            transform_push(transform, ele);
            transform->attri = ATTRI_SSRC;
        } else if (!strncmp(at, "rtcp-fb:", 8)) {
            cbor_value_t *feedback = cbor_map_dotget(last, "rtcp_fb");
            cbor_value_t *ele = cbor_init_map();
            if (at[8] == '*') {
                cbor_map_set_string(ele, "payload", "*");
            } else {
                int payload = strtol(at + 8, NULL, 10);
                cbor_map_set_integer(ele, "payload", payload);
            }
            if (feedback == NULL) {
                feedback = cbor_init_array();
                cbor_map_set_value(last, "rtcp_fb", feedback);
            }
            cbor_container_insert_tail(feedback, ele);
            transform_push(transform, ele);
            transform->attri = ATTRI_RTCPFB;
        } else if (!strncmp(at, "sendrecv", 8)
                   || !strncmp(at, "recvonly", 8)
                   || !strncmp(at, "sendonly", 8)
                   || !strncmp(at, "inactive", 8)) {
            cbor_value_t *direction = cbor_init_string(at, length);
            cbor_map_set_value(last, "direction", direction);
        } else if (!strncmp(at, "rtcp-mux", 8)) {
            cbor_value_t *rtcp_mux = cbor_init_string(at, length);
            cbor_map_set_value(last, "rtcp_mux", rtcp_mux);
        } else if (!strncmp(at, "sctpmap:", 8)) {
            cbor_value_t *ele = cbor_init_map();
            cbor_map_set_value(last, "stcpmap", ele);
            int number = strtol(at + 8, NULL, 10);
            cbor_map_set_integer(ele, "sctp_number", number);
            transform_push(transform, ele);
            transform->attri = ATTRI_SCTPMAP;
        } else if (!strncmp(at, "maxptime:", 9)) {
            int tm = strtol(at + 9, NULL, 10);
            cbor_value_t *maxptime = cbor_init_integer(tm);
            cbor_map_set_value(last, "maxptime", maxptime);
        } else if (!strncmp(at, "ptime:", 6)) {
            int tm = strtol(at + 6, NULL, 10);
            cbor_value_t *ptime = cbor_init_integer(tm);
            cbor_map_set_value(last, "ptime", ptime);
        } else if (!strncmp(at, "setup:", 6)) {
            cbor_value_t *setup = cbor_init_string(at + 6, length - 6);
            cbor_map_set_value(last, "setup", setup);
        } else if (!strncmp(at, "connection:", 11)) {
            cbor_value_t *connection_type = cbor_init_string(at + 11, length - 11);
            cbor_map_set_value(last, "connection_type", connection_type);
        } else if (!strncmp(at, "crypto:", 7)) {
            int id = strtol(at + 7, NULL, 10);
            cbor_value_t *crypto = cbor_init_map();
            cbor_map_set_integer(crypto, "id", id);
            cbor_map_set_value(last, "crypto", crypto);
            transform_push(transform, crypto);
            transform->attri = ATTRI_CRYPTO;
        } else if (!strncmp(at, "msid:", 5)) {
            cbor_value_t *msid = cbor_init_string(at + 5, length - 5);
            cbor_map_set_value(last, "msid", msid);
            transform_push(transform, msid);
            transform->attri = ATTRI_MSID;
        } else if (!strncmp(at, "msid-semantic:", 14)) {
            cbor_value_t *msid_semantic = cbor_init_map();
            cbor_map_set_value(last, "msid_semantic", msid_semantic);
            transform_push(transform, msid_semantic);
            transform->attri = ATTRI_MSID_SEMANTIC;
        } else if (!strncmp(at, "mid:", 4)) {
            int mid = strtol(at + 4, NULL, 10);
            cbor_map_set_integer(last, "mid", mid);
        } else if (!strncmp(at, "source-filter:", 14)) {
            cbor_value_t *filter = cbor_init_map();
            cbor_map_set_value(last, "source_filter", filter);
            transform_push(transform, filter);
            transform->attri = ATTRI_SOURCE_FILTER;
        } else if (!strncmp(at, "rid:", 4)) {
            cbor_value_t *ele = cbor_init_map();
            cbor_value_t *rids = cbor_map_dotget(last, "rids");
            if (rids == NULL) {
                rids = cbor_init_array();
                cbor_map_set_value(last, "rids", rids);
            }
            cbor_container_insert_tail(rids, ele);
            int id = strtol(at + 4, NULL, 10);
            cbor_map_set_integer(ele, "id", id);
            transform_push(transform, ele);
            transform->attri = ATTRI_RID;
        } else if (!strncmp(at, "ssrc-group:", 11)) {
            cbor_value_t *ele = cbor_init_map();
            cbor_value_t *groups = cbor_map_dotget(last, "ssrc_groups");
            if (groups == NULL) {
                groups = cbor_init_array();
                cbor_map_set_value(last, "ssrc_groups", groups);
            }
            cbor_container_insert_tail(groups, ele);
            cbor_value_t *semantics = cbor_init_string(at + 11, length - 11);
            cbor_map_set_value(ele, "semantics", semantics);
            transform_push(transform, ele);
            transform->attri = ATTRI_SSRC_GROUP;
        } else if (!strncmp(at, "group:", 6)) {
            cbor_value_t *ele = cbor_init_map();
            cbor_value_t *groups = cbor_map_dotget(last, "groups");
            if (groups == NULL) {
                groups = cbor_init_array();
                cbor_map_set_value(last, "groups", groups);
            }
            cbor_container_insert_tail(groups, ele);
            cbor_value_t *type = cbor_init_string(at + 6, length - 6);
            cbor_map_set_value(ele, "type", type);
            transform_push(transform, ele);
            transform->attri = ATTRI_GROUP;
        } else if (!strncmp(at, "max-message-size:", 17)) {
            int size = strtol(at + 17, NULL, 10);
            cbor_map_set_integer(last, "max_message_size", size);
        } else if (!strncmp(at, "sctp-port:", 10)) {
            int port = strtol(at + 10, NULL, 10);
            cbor_map_set_integer(last, "sctp_port", port);
        } else if (!strncmp(at, "rtcp-rsize", 10)) {
            cbor_value_t *val = cbor_init_string(at, length);
            cbor_map_set_value(last, "rtcp_rsize", val);
        } else if (!strncmp(at, "floorid:", 8)) {
            cbor_value_t *id = cbor_init_string(at + 8, length - 8);
            cbor_value_t *floorid = cbor_init_map();
            cbor_map_set_value(floorid, "id", id);
            cbor_map_set_value(last, "floorid", floorid);
            transform_push(transform, floorid);
            transform->attri = ATTRI_FLOORID;
        } else if (!strncmp(at, "userid:", 7)) {
            cbor_value_t *userid = cbor_init_string(at + 7, length - 7);
            cbor_map_set_value(last, "userid", userid);
        } else if (!strncmp(at, "floorctrl:", 10)) {
            cbor_value_t *ctrl = cbor_init_string(at + 10, length - 10);
            cbor_map_set_value(last, "floorctrl", ctrl);
        } else if (!strncmp(at, "content:", 8)) {
            cbor_value_t *content = cbor_init_string(at + 8, length - 8);
            cbor_map_set_value(last, "content", content);
            transform_push(transform, content);
            transform->attri = ATTRI_CONTENT;
        } else if (!strncmp(at, "keywds:", 7)) {
            cbor_value_t *keywords = cbor_init_string(at + 7, length - 7);
            cbor_map_set_value(last, "keywords", keywords);
            transform_push(transform, keywords);
            transform->attri = ATTRI_KEYWORDS;
        } else if (!strncmp(at, "ts-refclk:", 10)) {
            cbor_value_t *ts_refclk = cbor_map_dotget(last, "ts_refclks");
            if (ts_refclk == NULL) {
                ts_refclk = cbor_init_array();
                cbor_map_set_value(last, "ts_refclks", ts_refclk);
            }
            cbor_value_t *ele = cbor_init_map();
            char *ch = strchr(at + 10, '=');
            if (ch && ch < at + length) {
                cbor_value_t *clksrc = cbor_init_string(at + 10, ch - at - 10);
                cbor_map_set_value(ele, "clksrc", clksrc);
                cbor_value_t *clksrc_ext = cbor_init_string(ch + 1, at + length - ch - 1);
                cbor_map_set_value(ele, "clksrc_ext", clksrc_ext);
            } else {
                cbor_value_t *clksrc = cbor_init_string(at + 10, length - 10);
                cbor_map_set_value(ele, "clksrc", clksrc);
            }
            cbor_container_insert_tail(ts_refclk, ele);
        } else if (!strncmp(at, "mediaclk:", 9)) {
            cbor_value_t *mediaclk = cbor_init_map();
            if (!strncmp(at + 9, "id=", 3)) {
                cbor_value_t *id = cbor_init_string(at + 12, length - 12);
                cbor_map_set_value(mediaclk, "id", id);
            } else {
                char *ch = strchr(at + 9, '=');
                if (ch && ch < at + length) {
                    cbor_value_t *clk_name = cbor_init_string(at + 9, ch - at - 9);
                    cbor_map_set_value(mediaclk, "clk_name", clk_name);
                    cbor_value_t *clk_value = cbor_init_string(ch + 1, at + length - ch - 1);
                    cbor_map_set_value(mediaclk, "clk_value", clk_value);
                } else {
                    cbor_value_t *clk_name = cbor_init_string(at + 9, length - 9);
                    cbor_map_set_value(mediaclk, "clk_name", clk_name);
                }
            }
            cbor_map_set_value(last, "mediaclk", mediaclk);
            transform_push(transform, mediaclk);
            transform->attri = ATTRI_MEDIACLK;
        } else if (!strncmp(at, "ice-lite", 8)) {
            cbor_value_t *ice_lite = cbor_init_string(at, length);
            cbor_map_set_value(last, "ice_lite", ice_lite);
        } else if (!strncmp(at, "end-of-candidates", 17)) {
            /* do nothing */
        } else {
            cbor_value_t *unknown = cbor_map_dotget(last, "unknown");
            cbor_value_t *ele = cbor_init_string("a=", 2);
            cbor_blob_append(ele, at, length);
            if (unknown == NULL) {
                unknown = cbor_init_array();
                cbor_map_set_value(last, "unknown", unknown);
            }
            cbor_container_insert_tail(unknown, ele);
            transform->attri = ATTRI_UNKNOWN;
            transform_push(transform, ele);
        }
    } else if (index == 1) {
        if (transform->attri == ATTRI_FINGERPRINT) {
            cbor_value_t *hash = cbor_init_string(at, length);
            cbor_map_set_value(last, "hash", hash);
        } else if (transform->attri == ATTRI_RTPMAP) {
            char *ch = strchr(at, '/');
            if (ch && ch < at + length) {
                char *end;
                cbor_value_t *codec = cbor_init_string(at, ch - at);
                cbor_map_set_value(last, "codec", codec);
                int rate = strtol(ch + 1, &end, 10);
                cbor_map_set_integer(last, "rate", rate);
                if (*end == '/') {
                    cbor_value_t *encoding = cbor_init_string(end + 1, at + length - end - 1);
                    cbor_map_set_value(last, "encoding", encoding);
                }
            } else {
                cbor_value_t *codec = cbor_init_string(at, length);
                cbor_map_set_value(last, "codec", codec);
            }
        } else if (transform->attri == ATTRI_FMTP) {
            cbor_value_t *config = cbor_init_string(at, length);
            cbor_map_set_value(last, "config", config);
        } else if (transform->attri == ATTRI_EXT) {
            cbor_value_t *encrypt_uri = cbor_init_string(at, length);
            cbor_map_set_value(last, "encrypt_uri", encrypt_uri);
        } else if (transform->attri == ATTRI_RTCP) {
            cbor_value_t *net_type = cbor_init_string(at, length);
            cbor_map_set_value(last, "net_type", net_type);
        } else if (transform->attri == ATTRI_CANDIDATE) {
            int component = strtol(at, NULL, 10);
            cbor_map_set_integer(last, "component", component);
        } else if (transform->attri == ATTRI_SSRC) {
            char *ch = strchr(at, ':');
            if (ch < at + length) {
                cbor_value_t *attribute = cbor_init_string(at, ch - at);
                cbor_map_set_value(last, "attribute", attribute);
                cbor_value_t *value = cbor_init_string(ch + 1, at + length - ch - 1);
                cbor_map_set_value(last, "value", value);
            } else {
                cbor_value_t *attribute = cbor_init_string(at, length);
                cbor_map_set_value(last, "attribute", attribute);
            }
        } else if (transform->attri == ATTRI_RTCPFB) {
            cbor_value_t *type = cbor_init_string(at, length);
            cbor_map_set_value(last, "type", type);
        } else if (transform->attri == ATTRI_CRYPTO) {
            cbor_value_t *suite = cbor_init_string(at, length);
            cbor_map_set_value(last, "suite", suite);
        } else if (transform->attri == ATTRI_SOURCE_FILTER) {
            cbor_value_t *mode = cbor_init_string(at, length);
            cbor_map_set_value(last, "filter_mode", mode);
        } else if (transform->attri == ATTRI_SIMULCAST) {
            cbor_value_t *list1 = cbor_init_string(at, length);
            cbor_map_set_value(last, "list1", list1);
        } else if (transform->attri == ATTRI_SIMULCAST03) {
            cbor_value_t *value = cbor_init_string(at, length);
            cbor_map_set_value(last, "value", value);
        } else if (transform->attri == ATTRI_RID) {
            cbor_value_t *direction = cbor_init_string(at, length);
            cbor_map_set_value(last, "direction", direction);
        } else if (transform->attri == ATTRI_SSRC_GROUP) {
            cbor_value_t *ssrcs = cbor_init_string(at, length);
            cbor_map_set_value(last, "ssrcs", ssrcs);
        } else if (transform->attri == ATTRI_GROUP) {
            cbor_value_t *mids = cbor_init_string(at, length);
            cbor_map_set_value(last, "mids", mids);
        } else if (transform->attri == ATTRI_MSID_SEMANTIC) {
            cbor_value_t *semantic = cbor_init_string(at, length);
            cbor_map_set_value(last, "semantic", semantic);
        } else if (transform->attri == ATTRI_SCTPMAP) {
            cbor_value_t *app = cbor_init_string(at, length);
            cbor_map_set_value(last, "app", app);
        } else if (transform->attri == ATTRI_FLOORID) {
            if (!strncmp(at, "mstrm:", 6)) {
                cbor_value_t *mstream = cbor_init_string(at + 6, length - 6);
                cbor_map_set_value(last, "mstream", mstream);
            } else if (!strncmp(at, "m-stream:", 9)) {
                cbor_value_t *mstream = cbor_init_string(at + 9, length - 9);
                cbor_map_set_value(last, "mstream", mstream);
            }
        }
    } else if (index == 2) {
        if (transform->attri == ATTRI_EXT) {
            cbor_value_t *uri = cbor_init_string(at, length);
            cbor_map_set_value(last, "uri", uri);
        } else if (transform->attri == ATTRI_RTCP) {
            if (!strncmp(at, "IP", 2)) {
                int ver = strtol(at + 2, NULL, 10);
                cbor_map_set_integer(last, "ip_ver", ver);
            }
        } else if (transform->attri == ATTRI_CANDIDATE) {
            cbor_value_t *transport = cbor_init_string(at, length);
            cbor_map_set_value(last, "transport", transport);
        } else if (transform->attri == ATTRI_RTCPFB) {
            cbor_value_t *value = cbor_init_string(at, length);
            cbor_map_set_value(last, "value", value);
        } else if (transform->attri == ATTRI_CRYPTO) {
            cbor_value_t *config = cbor_init_string(at, length);
            cbor_map_set_value(last, "config", config);
        } else if (transform->attri == ATTRI_SOURCE_FILTER) {
            cbor_value_t *net_type = cbor_init_string(at, length);
            cbor_map_set_value(last, "net_type", net_type);
        } else if (transform->attri == ATTRI_RTCPFB) {
            cbor_value_t *value = cbor_init_map(at, length);
            cbor_map_set_value(last, "value", value);
        } else if (transform->attri == ATTRI_SIMULCAST) {
            cbor_value_t *dir2 = cbor_init_string(at, length);
            cbor_map_set_value(last, "dir2", dir2);
        } else if (transform->attri == ATTRI_RID) {
            cbor_value_t *params = cbor_init_string(at, length);
            cbor_map_set_value(last, "params", params);
        } else if (transform->attri == ATTRI_MSID_SEMANTIC) {
            cbor_value_t *token = cbor_init_string(at, length);
            cbor_map_set_value(last, "token", token);
        } else if (transform->attri == ATTRI_SCTPMAP) {
            int size = strtol(at, NULL, 10);
            cbor_map_set_integer(last, "max_message_size", size);
        }
    } else if (index == 3) {
        if (transform->attri == ATTRI_EXT) {
            cbor_value_t *config = cbor_init_string(at, length);
            cbor_map_set_value(last, "config", config);
        } else if (transform->attri == ATTRI_RTCP) {
            cbor_value_t *address = cbor_init_string(at, length);
            cbor_map_set_value(last, "address", address);
        } else if (transform->attri == ATTRI_CANDIDATE) {
            long long priority = strtoll(at, NULL, 10);
            cbor_map_set_integer(last, "priority", priority);
        } else if (transform->attri == ATTRI_CRYPTO) {
            cbor_value_t *config = cbor_init_string(at, length);
            cbor_map_set_value(last, "session_config", config);
        } else if (transform->attri == ATTRI_SOURCE_FILTER) {
            cbor_value_t *address_type = cbor_init_string(at, length);
            cbor_map_set_value(last, "address_type", address_type);
        } else if (transform->attri == ATTRI_SIMULCAST) {
            cbor_value_t *list2 = cbor_init_string(at, length);
            cbor_map_set_value(last, "list2", list2);
        }
    } else if (index == 4) {
        if (transform->attri == ATTRI_CANDIDATE) {
            cbor_value_t *ip = cbor_init_string(at, length);
            cbor_map_set_value(last, "ip", ip);
        } else if (transform->attri == ATTRI_SOURCE_FILTER) {
            cbor_value_t *dest_address = cbor_init_string(at, length);
            cbor_map_set_value(last, "dest_address", dest_address);
        }
    } else if (index == 5) {
        if (transform->attri == ATTRI_CANDIDATE) {
            int port = strtol(at, NULL, 10);
            cbor_map_set_integer(last, "port", port);
        } else if (transform->attri == ATTRI_SOURCE_FILTER) {
            cbor_value_t *src_list = cbor_init_string(at, length);
            cbor_map_set_value(last, "src_list", src_list);
        }
    }

    if (transform->attri == ATTRI_FMTP && index >= 2) {
        cbor_value_t *config = cbor_map_dotget(last, "config");
        if (config) {
            cbor_blob_append_byte(config, 0x20);
            cbor_blob_append(config, at, length);
        }
    } else if (transform->attri == ATTRI_SSRC && index >= 2) {
        cbor_value_t *value = cbor_map_dotget(last, "value");
        if (value) {
            cbor_blob_append_byte(value, 0x20);
            cbor_blob_append(value, at, length);
        }
    } else if (transform->attri == ATTRI_MSID && index >= 2) {
        if (cbor_is_string(last)) {
            cbor_blob_append_byte(last, 0x20);
            cbor_blob_append(last, at, length);
        }
    } else if (transform->attri == ATTRI_SOURCE_FILTER && index > 5) {
        cbor_value_t *src_list = cbor_map_dotget(last, "src_list");
        if (cbor_is_string(src_list)) {
            cbor_blob_append_byte(src_list, 0x20);
            cbor_blob_append(src_list, at, length);
        }
    } else if ((transform->attri == ATTRI_UNKNOWN
                || transform->attri == ATTRI_KEYWORDS
                || transform->attri == ATTRI_CONTENT)
               && index > 0) {
        if (cbor_is_string(last)) {
            cbor_blob_append_byte(last, 0x20);
        }
        cbor_blob_append(last, at, length);
    } else if (transform->attri == ATTRI_SIMULCAST03 && index >= 2) {
        cbor_value_t *value = cbor_map_dotget(last, "value");
        if (cbor_is_string(value)) {
            cbor_blob_append_byte(value, 0x20);
            cbor_blob_append(value, at, length);
        }
    } else if (transform->attri == ATTRI_RID && index > 2) {
        cbor_value_t *params = cbor_map_dotget(last, "params");
        if (cbor_is_string(params)) {
            cbor_blob_append_byte(params, 0x20);
            cbor_blob_append(params, at, length);
        }
    } else if (transform->attri == ATTRI_SSRC_GROUP && index >= 2) {
        cbor_value_t *ssrcs = cbor_map_dotget(last, "ssrcs");
        if (cbor_is_string(ssrcs)) {
            cbor_blob_append_byte(ssrcs, 0x20);
            cbor_blob_append(ssrcs, at, length);
        }
    } else if (transform->attri == ATTRI_GROUP && index >= 2) {
        cbor_value_t *mids = cbor_map_dotget(last, "mids");
        if (cbor_is_string(mids)) {
            cbor_blob_append_byte(mids, 0x20);
            cbor_blob_append(mids, at, length);
        }
    } else if (transform->attri == ATTRI_MEDIACLK && index > 0) {
        if (!strncmp(at, "rate=", 5)) {
            char *end;
            int rate_numerator = strtol(at + 5, &end, 10);
            cbor_map_set_integer(last, "rate_numerator", rate_numerator);
            if (*end == '/') {
                int rate_denominator = strtol(end + 1, NULL, 10);
                cbor_map_set_integer(last, "rate_denominator", rate_denominator);
            }
        } else {
            char *ch = strchr(at, '=');
            if (ch && ch < at + length) {
                cbor_value_t *clk_name = cbor_init_string(at, ch - at);
                cbor_value_t *clk_value = cbor_init_string(ch + 1, at + length - ch - 1);
                cbor_map_set_value(last, "clk_name", clk_name);
                cbor_map_set_value(last, "clk_value", clk_value);
            } else {
                cbor_value_t *clk_name = cbor_init_string(at, length);
                cbor_map_set_value(last, "clk_name", clk_name);
            }
        }
    } else if (transform->attri == ATTRI_CANDIDATE && index > 5) {
        if (index % 2 == 0) {
            if (!strncmp(at, "typ", 3)) {
                cbor_value_t *key = cbor_init_string("type", 4);
                transform_push(transform, key);
            } else if (!strncmp(at, "raddr", 5)) {
                cbor_value_t *key = cbor_init_string(at, length);
                transform_push(transform, key);
            } else if (!strncmp(at, "rport", 5)) {
                cbor_value_t *key = cbor_init_string(at, length);
                transform_push(transform, key);
            } else if (!strncmp(at, "tcptype", 7)) {
                cbor_value_t *key = cbor_init_string(at, length);
                transform_push(transform, key);
            } else if (!strncmp(at, "generation", 10)) {
                cbor_value_t *key = cbor_init_string(at, length);
                transform_push(transform, key);
            } else if (!strncmp(at, "network-id", 10)) {
                cbor_value_t *key = cbor_init_string("network_id", 10);
                transform_push(transform, key);
            } else if (!strncmp(at, "network-cost", 12)) {
                cbor_value_t *key = cbor_init_string("network_cost", 12);
                transform_push(transform, key);
            }
        } else {
            cbor_value_t *key = transform_pop(transform);
            last = transform_top(transform);
            if (cbor_is_string(key) && cbor_is_map(last)) {
                const char *str = cbor_string(key);
                if (!strcmp(str, "type")) {
                    int typ = strtol(at, NULL, 10);
                    cbor_value_t *val = cbor_init_integer(typ);
                    cbor_map_insert(last, key, val);
                } else if (!strcmp(str, "raddr")) {
                    cbor_value_t *val = cbor_init_string(at, length);
                    cbor_map_insert(last, key, val);
                } else if (!strcmp(str, "rport")) {
                    int port = strtol(at, NULL, 10);
                    cbor_value_t *val = cbor_init_integer(port);
                    cbor_map_insert(last, key, val);
                } else if (!strcmp(str, "tcptype")) {
                    cbor_value_t *val = cbor_init_string(at, length);
                    cbor_map_insert(last, key, val);
                } else if (!strcmp(str, "network_id")) {
                    int id = strtol(at, NULL, 10);
                    cbor_value_t *val = cbor_init_integer(id);
                    cbor_map_insert(last, key, val);
                } else if (!strcmp(str, "network_cast")) {
                    int cost = strtol(at, NULL, 10);
                    cbor_value_t *val = cbor_init_integer(cost);
                    cbor_map_insert(last, key, val);
                }
            } else {
                cbor_destroy(key);
            }
        }
    }
    return 0;
}

int sdp_transform_email(sdp_transform_t *transform, int index, const char *at, size_t length) {
    if (index == 0) {
        cbor_value_t *email = cbor_init_string(at, length);
        cbor_map_set_value(transform->root, "email", email);
    } else {
        cbor_value_t *email = cbor_map_dotget(transform->root, "email");
        cbor_blob_append_byte(email, 0x20);
        cbor_blob_append(email, at, length);
    }
    return 0;
}

int sdp_transform_repeat(sdp_transform_t *transform, int index, const char *at, size_t length) {
    return 0;
}

cbor_value_t *sdp_transform_parse(const char *str, size_t length) {
    sdp_parser_t parser;
    sdp_parser_setting_t setting;
    sdp_transform_t transform;

    memset(&transform, 0, sizeof(sdp_transform_t));
    parser.data = (void *)&transform;
    sdp_parser_init(&parser, str, length);
    setting = (sdp_parser_setting_t){
        on_field_begin,
        on_describe,
        on_field_end
    };
    transform.root = cbor_init_map();
    transform_push(&transform, transform.root);
    sdp_parser_execute(&parser, &setting);
    return transform.root;
}
