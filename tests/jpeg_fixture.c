/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
/* Writes a deterministic test JPEG, so tests don't need external tools.

   jpeg_fixture OUT WIDTH HEIGHT COMPONENTS QUALITY [option...]
     progressive  progressive scans          optimize  optimized Huffman tables
     arith        arithmetic coding          restart   restart markers every row
     markers      EXIF (APP1), ICC (APP2) and comment markers
     nojfif       no JFIF (APP0) header, as many cameras write
     444          no chroma subsampling (default 4:2:0 for color)
     manyscans    progressive with 568 scans (each AC coefficient of each
                  component refined bit by bit): a valid but slow-to-read
                  file, past the 500-scan limit jpeg_load enforces

   The picture is a gradient with deterministic texture, so it has plenty
   of non-zero AC coefficients like a photograph. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s OUT WIDTH HEIGHT COMPONENTS QUALITY [option...]\n", argv[0]);
        return 2;
    }
    int w = atoi(argv[2]), h = atoi(argv[3]), comps = atoi(argv[4]), quality = atoi(argv[5]);
    int progressive = 0, optimize = 0, arith = 0, restart = 0, markers = 0, full = 0, many = 0;
    int nojfif = 0, flat = 0;
    for (int i = 6; i < argc; i++) {
        progressive |= !strcmp(argv[i], "progressive");
        optimize    |= !strcmp(argv[i], "optimize");
        arith       |= !strcmp(argv[i], "arith");
        restart     |= !strcmp(argv[i], "restart");
        markers     |= !strcmp(argv[i], "markers");
        full        |= !strcmp(argv[i], "444");
        many        |= !strcmp(argv[i], "manyscans");
        nojfif      |= !strcmp(argv[i], "nojfif");
        flat        |= !strcmp(argv[i], "flat");  /* plain gray but for one column of blocks */
    }

    FILE *fp = fopen(argv[1], "wb");
    if (!fp) { perror(argv[1]); return 1; }
    struct jpeg_compress_struct c;
    struct jpeg_error_mgr err;
    c.err = jpeg_std_error(&err);
    jpeg_create_compress(&c);
    jpeg_stdio_dest(&c, fp);
    c.image_width = w;
    c.image_height = h;
    c.input_components = comps;
    c.in_color_space = comps == 1 ? JCS_GRAYSCALE : JCS_RGB;
    jpeg_set_defaults(&c);
    jpeg_set_quality(&c, quality, TRUE);
    if (progressive) jpeg_simple_progression(&c);
    if (many) {
        /* DC for all components, then per component and AC coefficient:
           first scan at Al=2, refinements to Al=1 and Al=0 */
        static jpeg_scan_info scans[1 + 3 * 63 * 3];
        int n = 0;
        scans[n].comps_in_scan = comps;
        for (int k = 0; k < comps; k++) scans[n].component_index[k] = k;
        scans[n].Ss = scans[n].Se = 0;
        scans[n].Ah = scans[n].Al = 0;
        n++;
        for (int k = 0; k < comps; k++)
            for (int coef = 1; coef < 64; coef++)
                for (int pass = 0; pass < 3; pass++) {
                    scans[n].comps_in_scan = 1;
                    scans[n].component_index[0] = k;
                    scans[n].Ss = scans[n].Se = coef;
                    scans[n].Ah = pass == 0 ? 0 : 3 - pass;
                    scans[n].Al = 2 - pass;
                    n++;
                }
        c.scan_info = scans;
        c.num_scans = n;
    }
    c.optimize_coding = optimize;
    c.arith_code = arith;
    if (restart) c.restart_in_rows = 1;
    if (nojfif) c.write_JFIF_header = FALSE;
    if (full && comps == 3)
        for (int i = 0; i < 3; i++) c.comp_info[i].h_samp_factor = c.comp_info[i].v_samp_factor = 1;
    jpeg_start_compress(&c, TRUE);

    if (markers) {
        static const unsigned char exif[] = "Exif\0\0MM\0*\0\0\0\x08\0\0";
        unsigned char icc[14 + 136] = "ICC_PROFILE";
        icc[12] = 1;  /* chunk 1 */
        icc[13] = 1;  /* of 1 */
        for (int i = 0; i < 136; i++) icc[14 + i] = (unsigned char)(i * 7);
        jpeg_write_marker(&c, JPEG_APP0 + 1, exif, sizeof(exif) - 1);
        jpeg_write_marker(&c, JPEG_APP0 + 2, icc, sizeof(icc));
        jpeg_write_marker(&c, JPEG_COM, (const JOCTET *)"made by jpeg_fixture", 20);
    }

    unsigned char *row = malloc((size_t)w * comps);
    unsigned seed = 12345;
    while (c.next_scanline < c.image_height) {
        int y = c.next_scanline;
        for (int x = 0; x < w; x++)
            for (int k = 0; k < comps; k++) {
                seed = seed * 1103515245u + 12345u;
                int v = (x * 255 / (w ? w : 1) + y * 128 / (h ? h : 1) + k * 60) % 256;
                v += (int)((seed >> 16) % 41) - 20;  /* texture */
                if (flat && x >= 8) v = 128;
                row[(size_t)x * comps + k] = (unsigned char)(v < 0 ? 0 : v > 255 ? 255 : v);
            }
        JSAMPROW rows[1] = {row};
        jpeg_write_scanlines(&c, rows, 1);
    }
    jpeg_finish_compress(&c);
    jpeg_destroy_compress(&c);
    fclose(fp);
    free(row);
    return 0;
}
