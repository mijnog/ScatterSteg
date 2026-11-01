#!/bin/bash
# Speed and memory of embed and extract (benchmark/speed.py), for the "Speed"
# note: each build in DIR (c-main, c-new, r-main, r-new: C and Rust, before
# and after a change) on DIR/photo.jpg and DIR/photo.png, at the size `info`
# suggests and at capacity. Measured on 2026-11-01 with photo.jpg =
# Wikimedia Commons "2014 Nowy Aton, Widok ze szczytu Góry Iwerskiej (05).jpg"
# (4241x2827, CC BY-SA 4.0) and photo.png = it saved as RGB PNG by Pillow
# (compress_level 6). Run it on an otherwise idle machine.
# Usage: run_speed.sh DIR
D=$1
PY=${PY:-/home/max/bench/venv/bin/python}
M=$(dirname "$(readlink -f "$0")")/speed.py
cd "$D"
echo "machine: $(nproc) threads, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2), $(free -g | awk '/Mem:/{print $2}') GiB; load at start $(cut -d' ' -f1-3 /proc/loadavg)"
for kind in jpg png; do
  for b in c-main c-new r-main r-new; do
    sug=$(./$b info photo.$kind | sed -n 's/^Suggested: at most \([0-9]*\) byte.*/\1/p')
    cap=$(./$b info photo.$kind | sed -n 's/^Capacity:  \([0-9]*\) bytes.*/\1/p')
    for size in $sug $cap; do
      out=$D/out-$b-$kind-$size.$kind
      echo "$b $kind $size embed:   $($PY -I $M $D/$b embed photo.$kind $out $size)"
      echo "$b $kind $size extract: $($PY -I $M $D/$b extract $out $D/x.bin)"
      rm -f $out $out.msg
    done
  done
done
echo DONE
