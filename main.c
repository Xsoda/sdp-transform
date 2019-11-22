#include <stdio.h>
#include <stdlib.h>
#include "sdp_transform.h"

int main(int argc, char **argv) {
    FILE *fp = fopen(argv[1], "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        size_t length = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char *content = (char *)malloc(length);
        fread(content, sizeof(char), length, fp);
        fclose(fp);

        cbor_value_t *sdp = sdp_transform_parse(content, length);
        free(content);

        content = cbor_json_dumps(sdp, &length, true);
        fprintf(stdout, "%.*s", (int)length, content);
        free(content);
    }
    return 0;
}
