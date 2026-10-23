#include <stdio.h>
#include <stdlib.h>
#include <jpeglib.h>
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
    struct jpeg_decompress_struct c; struct jpeg_error_mgr e;
    c.err = jpeg_std_error(&e); jpeg_create_decompress(&c); jpeg_stdio_src(&c, f);
    jpeg_read_header(&c, TRUE);
    jvirt_barray_ptr *co = jpeg_read_coefficients(&c);
    FILE *o = stdout; int n = c.num_components; fwrite(&n, 4, 1, o);
    for (int ci = 0; ci < n; ci++) {
        int wb = c.comp_info[ci].width_in_blocks, hb = c.comp_info[ci].height_in_blocks;
        fwrite(&wb, 4, 1, o); fwrite(&hb, 4, 1, o);
        for (int by = 0; by < hb; by++) {
            JBLOCKARRAY r = c.mem->access_virt_barray((j_common_ptr)&c, co[ci], by, 1, FALSE);
            fwrite(r[0], sizeof(JBLOCK), wb, o);
        }
    }
    return 0;
}
