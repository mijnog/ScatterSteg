CC      = gcc
CFLAGS  = -Wall -Wextra -std=c17 -g $(COSTS_FLAGS)
LIBS    = -lsodium -lpng -ljpeg -lz -lm

# Distortion models (distortion.h), for benchmark builds: PNG_COSTS is hill,
# wow or suniward, JPEG_COSTS uerd or juniward. Images made with any of them
# read back with every build. Rebuild from clean after changing them.
PNG_COSTS  ?= hill
JPEG_COSTS ?= uerd
upper       = $(shell echo $(1) | tr a-z A-Z)
COSTS_FLAGS = -DSCATTERSTEG_PNG_COSTS=COSTS_$(call upper,$(PNG_COSTS)) \
              -DSCATTERSTEG_JPEG_COSTS=COSTS_$(call upper,$(JPEG_COSTS))

SRCS    = main.c codec.c prng.c embed.c stc.c png_io.c jpeg_io.c atomic_write.c distortion.c
OBJS    = $(SRCS:.c=.o)
TARGET  = scattersteg

# Release hardening, for the normal build only (test builds use sanitizers,
# which don't mix with _FORTIFY_SOURCE). Flags the compiler doesn't support
# are dropped, e.g. -fcf-protection off x86.
cc-option      = $(shell $(CC) $(1) -Werror -x c -c /dev/null -o /dev/null 2>/dev/null && echo $(1))
HARDEN_CFLAGS  = -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE \
                 $(call cc-option,-fstack-clash-protection) $(call cc-option,-fcf-protection)
HARDEN_LDFLAGS = -pie -Wl,-z,relro,-z,now,-z,noexecstack

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(HARDEN_LDFLAGS) $(LIBS)

%.o: %.c $(wildcard *.h)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) -c $< -o $@

# Tests build every source with ASan/UBSan into tests/build, separate from
# the normal objects, so leaks and memory errors in error paths fail the run.
TEST_DIR    = tests/build
TEST_CFLAGS = $(CFLAGS) -I. -Itests -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_ENV    = ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
UNIT_TESTS  = $(TEST_DIR)/test_embed $(TEST_DIR)/test_stc $(TEST_DIR)/test_prng $(TEST_DIR)/test_png_io $(TEST_DIR)/test_jpeg_io $(TEST_DIR)/test_faults $(TEST_DIR)/test_distortion
HDRS        = codec.h png_io.h jpeg_io.h prng.h embed.h stc.h atomic_write.h distortion.h

# Fault-injection build: the sources force-include tests/fault.h, so a test
# can make the Nth malloc/fopen/fclose/rename/... fail (see tests/fault.c)
FAULT_DIR   = $(TEST_DIR)/fault
FAULT_OBJS  = $(SRCS:%.c=$(FAULT_DIR)/%.o) $(FAULT_DIR)/fault.o $(FAULT_DIR)/fault_sodium.o

test: unit-test cli-test

unit-test: $(UNIT_TESTS) $(TEST_DIR)/jpeg_fixture
	@for t in $(UNIT_TESTS); do echo "== $$t"; $(TEST_ENV) $$t || exit 1; done

cli-test: $(TEST_DIR)/scattersteg $(TEST_DIR)/scattersteg-fault $(TEST_DIR)/jpeg_fixture
	@echo "== tests/test_cli.py"
	$(TEST_ENV) SCATTERSTEG=$(TEST_DIR)/scattersteg SCATTERSTEG_FAULT=$(TEST_DIR)/scattersteg-fault \
		JPEG_FIXTURE=$(TEST_DIR)/jpeg_fixture \
		python3 tests/test_cli.py

$(TEST_DIR)/test_embed: tests/test_embed.c embed.c png_io.c atomic_write.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_embed.c embed.c png_io.c atomic_write.c -o $@ -lpng -lz -lsodium -lm

$(TEST_DIR)/test_stc: tests/test_stc.c stc.c stc.h tests/test.h | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_stc.c stc.c -o $@ -lm

$(TEST_DIR)/test_prng: tests/test_prng.c prng.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_prng.c prng.c -o $@ -lsodium

$(TEST_DIR)/test_png_io: tests/test_png_io.c png_io.c atomic_write.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_png_io.c png_io.c atomic_write.c -o $@ -lpng -lz

$(TEST_DIR)/test_jpeg_io: tests/test_jpeg_io.c jpeg_io.c embed.c atomic_write.c distortion.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_jpeg_io.c jpeg_io.c embed.c atomic_write.c distortion.c -o $@ -ljpeg -lsodium -lm

$(TEST_DIR)/test_distortion: tests/test_distortion.c distortion.c embed.c png_io.c atomic_write.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_distortion.c distortion.c embed.c png_io.c atomic_write.c -o $@ -lpng -lz -lsodium -lm

# Writes test JPEGs (no sanitizers: it's a tool, not code under test)
$(TEST_DIR)/jpeg_fixture: tests/jpeg_fixture.c | $(TEST_DIR)
	$(CC) $(CFLAGS) tests/jpeg_fixture.c -o $@ -ljpeg

$(TEST_DIR)/test_faults: tests/test_faults.c $(FAULT_DIR)/png_io.o $(FAULT_DIR)/atomic_write.o $(FAULT_DIR)/fault.o tests/test.h | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_faults.c $(FAULT_DIR)/png_io.o $(FAULT_DIR)/atomic_write.o $(FAULT_DIR)/fault.o -o $@ -lpng -lz

$(TEST_DIR)/scattersteg: $(SRCS) $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) $(SRCS) -o $@ $(LIBS)

$(TEST_DIR)/scattersteg-fault: $(FAULT_OBJS)
	$(CC) $(TEST_CFLAGS) $(FAULT_OBJS) -o $@ $(LIBS)

$(FAULT_DIR)/%.o: %.c tests/fault.h $(HDRS) | $(FAULT_DIR)
	$(CC) $(TEST_CFLAGS) -include tests/fault.h -c $< -o $@

$(FAULT_DIR)/fault.o: tests/fault.c tests/fault.h | $(FAULT_DIR)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(FAULT_DIR)/fault_sodium.o: tests/fault_sodium.c tests/fault.h | $(FAULT_DIR)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# Fuzzing (clang/libFuzzer). Runs each target for FUZZ_TIME seconds in
# parallel; crashing inputs are saved as tests/build/fuzz/crash-*.
FUZZ_DIR    = $(TEST_DIR)/fuzz
FUZZ_CC     = clang
FUZZ_CFLAGS = -g -O1 -I. -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
FUZZ_TIME  ?= 60
# Small ASan quarantine: big-but-legal decodes otherwise pile up as RSS.
# A single allocation over the 1 GiB pixel cap still counts as a failure.
FUZZ_ENV    = ASAN_OPTIONS=quarantine_size_mb=16:allocator_release_to_os_interval_ms=100
FUZZ_ARGS   = -max_total_time=$(FUZZ_TIME) -rss_limit_mb=4096 -malloc_limit_mb=1100 -close_fd_mask=2
FUZZERS     = $(FUZZ_DIR)/fuzz_png_load $(FUZZ_DIR)/fuzz_jpeg_load $(FUZZ_DIR)/fuzz_embed $(FUZZ_DIR)/fuzz_stc $(FUZZ_DIR)/fuzz_png_roundtrip $(FUZZ_DIR)/fuzz_codec
FUZZ_TARGETS = png_load jpeg_load embed stc png_roundtrip codec

fuzz: $(FUZZERS) $(TEST_DIR)/jpeg_fixture
	@test -d $(FUZZ_DIR)/corpus/png_load || python3 tests/fuzz/make_seeds.py $(FUZZ_DIR)/corpus/png_load
	@test -d $(FUZZ_DIR)/corpus/jpeg_load || { mkdir -p $(FUZZ_DIR)/corpus/jpeg_load && \
		for v in "16 16 3 85" "40 24 1 70" "33 17 3 90 progressive" "24 24 3 75 arith" \
		         "48 32 3 85 restart markers" "32 32 3 95 444 optimize"; do \
			$(TEST_DIR)/jpeg_fixture "$(FUZZ_DIR)/corpus/jpeg_load/$$(echo $$v | tr ' ' _).jpg" $$v; \
		done; }
	@cd $(FUZZ_DIR) && pids= && \
	for t in $(FUZZ_TARGETS); do \
		mkdir -p corpus/$$t; \
		cp ../../fuzz/regressions/$$t/* corpus/$$t/ 2>/dev/null; \
		$(FUZZ_ENV) ./fuzz_$$t $(FUZZ_ARGS) -print_final_stats=1 -artifact_prefix=crash-$$t- \
			corpus/$$t > fuzz_$$t.log 2>&1 & pids="$$pids $$!"; \
	done; \
	fail=0; for p in $$pids; do wait $$p || fail=1; done; \
	for t in $(FUZZ_TARGETS); do \
		printf '%-14s %s runs\n' $$t "$$(sed -n 's/^stat::number_of_executed_units: *//p' fuzz_$$t.log)"; \
	done; \
	if [ $$fail != 0 ]; then grep -h -A5 -E '^==[0-9]+==|^SUMMARY' fuzz_*.log; ls crash-* 2>/dev/null; exit 1; fi

$(FUZZ_DIR)/fuzz_png_load: tests/fuzz/fuzz_png_load.c png_io.c atomic_write.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_png_load.c png_io.c atomic_write.c -o $@ -lpng -lz

$(FUZZ_DIR)/fuzz_jpeg_load: tests/fuzz/fuzz_jpeg_load.c jpeg_io.c embed.c atomic_write.c distortion.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(COSTS_FLAGS) tests/fuzz/fuzz_jpeg_load.c jpeg_io.c embed.c atomic_write.c distortion.c -o $@ -ljpeg -lsodium -lm

$(FUZZ_DIR)/fuzz_stc: tests/fuzz/fuzz_stc.c stc.c stc.h | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_stc.c stc.c -o $@ -lm

$(FUZZ_DIR)/fuzz_embed: tests/fuzz/fuzz_embed.c embed.c prng.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_embed.c embed.c prng.c -o $@ -lsodium

# Built with Argon2id swapped for BLAKE2b (see codec.c), never for real use
$(FUZZ_DIR)/fuzz_codec: tests/fuzz/fuzz_codec.c codec.c embed.c prng.c stc.c distortion.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(COSTS_FLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION tests/fuzz/fuzz_codec.c codec.c embed.c prng.c stc.c distortion.c -o $@ -lsodium -lz -lm

$(FUZZ_DIR)/fuzz_png_roundtrip: tests/fuzz/fuzz_png_roundtrip.c png_io.c atomic_write.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_png_roundtrip.c png_io.c atomic_write.c -o $@ -lpng -lz

# Line coverage over the whole suite, fault sweeps included. All binaries
# link the same instrumented objects so their counts add up.
COV_DIR     = $(TEST_DIR)/cov
COV_CFLAGS  = $(CFLAGS) -O0 -I. -Itests --coverage
COV_OBJS    = $(SRCS:%.c=$(COV_DIR)/%.o) $(COV_DIR)/fault.o $(COV_DIR)/fault_sodium.o

coverage: $(COV_OBJS) | $(COV_DIR)
	rm -f $(COV_DIR)/*.gcda
	$(CC) $(COV_CFLAGS) tests/test_embed.c $(COV_DIR)/embed.o $(COV_DIR)/png_io.o $(COV_DIR)/atomic_write.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_embed -lpng -lz -lsodium -lm
	$(CC) $(COV_CFLAGS) tests/test_stc.c $(COV_DIR)/stc.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_stc -lm
	$(CC) $(COV_CFLAGS) tests/test_prng.c $(COV_DIR)/prng.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_prng -lsodium
	$(CC) $(COV_CFLAGS) tests/test_png_io.c $(COV_DIR)/png_io.o $(COV_DIR)/atomic_write.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_png_io -lpng -lz
	$(CC) $(COV_CFLAGS) tests/test_jpeg_io.c $(COV_DIR)/jpeg_io.o $(COV_DIR)/embed.o $(COV_DIR)/atomic_write.o $(COV_DIR)/distortion.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_jpeg_io -ljpeg -lsodium -lm
	$(CC) $(COV_CFLAGS) tests/test_faults.c $(COV_DIR)/png_io.o $(COV_DIR)/atomic_write.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_faults -lpng -lz
	$(CC) $(COV_CFLAGS) $(SRCS:%.c=$(COV_DIR)/%.o) $(COV_DIR)/fault.o $(COV_DIR)/fault_sodium.o -o $(COV_DIR)/scattersteg $(LIBS)
	$(MAKE) --no-print-directory $(TEST_DIR)/jpeg_fixture
	for t in test_embed test_stc test_prng test_png_io test_jpeg_io test_faults; do $(COV_DIR)/$$t > /dev/null 2>&1 || exit 1; done
	SCATTERSTEG=$(COV_DIR)/scattersteg SCATTERSTEG_FAULT=$(COV_DIR)/scattersteg JPEG_FIXTURE=$(TEST_DIR)/jpeg_fixture \
		python3 tests/test_cli.py > $(COV_DIR)/cli.log 2>&1 || { echo "tests failed (see $(COV_DIR)/cli.log); coverage still reported"; }
	@gcov -o $(COV_DIR) $(SRCS) 2>/dev/null | \
		awk '/^File .*\.c/ {f=$$2} /^Lines executed/ && f !~ /tests|\/usr/ {print f, $$0; f=""}'
	@mv *.c.gcov $(COV_DIR)/; rm -f *.h.gcov
	@echo "annotated sources: $(COV_DIR)/*.c.gcov (lines marked ##### never ran)"

$(COV_DIR)/%.o: %.c tests/fault.h $(HDRS) | $(COV_DIR)
	$(CC) $(COV_CFLAGS) -include tests/fault.h -c $< -o $@

$(COV_DIR)/fault.o: tests/fault.c tests/fault.h | $(COV_DIR)
	$(CC) $(COV_CFLAGS) -c $< -o $@

$(COV_DIR)/fault_sodium.o: tests/fault_sodium.c tests/fault.h | $(COV_DIR)
	$(CC) $(COV_CFLAGS) -c $< -o $@

$(TEST_DIR) $(FAULT_DIR) $(COV_DIR) $(FUZZ_DIR):
	mkdir -p $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf $(TEST_DIR)

.PHONY: all test unit-test cli-test fuzz coverage clean