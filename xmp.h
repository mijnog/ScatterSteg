/* SPDX-License-Identifier: MIT OR Apache-2.0
   Copyright (C) 2026 Maxime de Montbron */
#ifndef XMP_H
#define XMP_H

#include <stddef.h>
#include <string.h>

/* Why a cover whose XMP cites a remote content credential is refused,
   for PNG and JPEG alike (as rust/src/cover.rs) */
#define COVER_C2PA_REFERENCE "a reference to a content credential (C2PA) signing its pixels"

/* Does this XMP (or the chunk or segment holding it) cite a C2PA manifest
   kept elsewhere? The C2PA spec does it with dcterms:provenance, so: the
   Dublin Core terms namespace, and a provenance property in some prefix. */
static inline int xmp_cites_c2pa(const unsigned char *d, size_t n) {
    static const char ns[] = "http://purl.org/dc/terms/", prop[] = ":provenance";
    int has_ns = 0, has_prop = 0;
    for (size_t i = 0; i < n && !(has_ns && has_prop); i++) {
        if (n - i >= sizeof(ns) - 1 && !memcmp(d + i, ns, sizeof(ns) - 1)) has_ns = 1;
        if (n - i >= sizeof(prop) - 1 && !memcmp(d + i, prop, sizeof(prop) - 1)) has_prop = 1;
    }
    return has_ns && has_prop;
}

#endif /* XMP_H */
