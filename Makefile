CC      = gcc
CFLAGS  = -Wall -Wextra -std=c17 -g
LIBS    = -lsodium -lpng

SRCS    = main.c prng.c embed.c png_io.c
OBJS    = $(SRCS:.c=.o)
TARGET  = scattersteg

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Tests build every source with ASan/UBSan into tests/build, separate from
# the normal objects, so leaks and memory errors in error paths fail the run.
TEST_DIR    = tests/build
TEST_CFLAGS = $(CFLAGS) -I. -Itests -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_ENV    = ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
UNIT_TESTS  = $(TEST_DIR)/test_embed $(TEST_DIR)/test_prng $(TEST_DIR)/test_png_io $(TEST_DIR)/test_faults
HDRS        = png_io.h prng.h embed.h

# Fault-injection build: the sources force-include tests/fault.h, so a test
# can make the Nth malloc/fopen/fclose/rename/... fail (see tests/fault.c)
FAULT_DIR   = $(TEST_DIR)/fault
FAULT_OBJS  = $(SRCS:%.c=$(FAULT_DIR)/%.o) $(FAULT_DIR)/fault.o $(FAULT_DIR)/fault_sodium.o

test: unit-test cli-test

unit-test: $(UNIT_TESTS)
	@for t in $(UNIT_TESTS); do echo "== $$t"; $(TEST_ENV) $$t || exit 1; done

cli-test: $(TEST_DIR)/scattersteg $(TEST_DIR)/scattersteg-fault
	@echo "== tests/test_cli.py"
	$(TEST_ENV) SCATTERSTEG=$(TEST_DIR)/scattersteg SCATTERSTEG_FAULT=$(TEST_DIR)/scattersteg-fault \
		python3 tests/test_cli.py

$(TEST_DIR)/test_embed: tests/test_embed.c embed.c png_io.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_embed.c embed.c png_io.c -o $@ -lpng -lsodium

$(TEST_DIR)/test_prng: tests/test_prng.c prng.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_prng.c prng.c -o $@ -lsodium

$(TEST_DIR)/test_png_io: tests/test_png_io.c png_io.c tests/test.h $(HDRS) | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_png_io.c png_io.c -o $@ -lpng -lz

$(TEST_DIR)/test_faults: tests/test_faults.c $(FAULT_DIR)/png_io.o $(FAULT_DIR)/fault.o tests/test.h | $(TEST_DIR)
	$(CC) $(TEST_CFLAGS) tests/test_faults.c $(FAULT_DIR)/png_io.o $(FAULT_DIR)/fault.o -o $@ -lpng

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
FUZZERS     = $(FUZZ_DIR)/fuzz_png_load $(FUZZ_DIR)/fuzz_embed $(FUZZ_DIR)/fuzz_png_roundtrip

fuzz: $(FUZZERS)
	@test -d $(FUZZ_DIR)/corpus/png_load || python3 tests/fuzz/make_seeds.py $(FUZZ_DIR)/corpus/png_load
	@cd $(FUZZ_DIR) && pids= && \
	for t in png_load embed png_roundtrip; do \
		mkdir -p corpus/$$t; \
		$(FUZZ_ENV) ./fuzz_$$t $(FUZZ_ARGS) -print_final_stats=1 -artifact_prefix=crash-$$t- \
			corpus/$$t > fuzz_$$t.log 2>&1 & pids="$$pids $$!"; \
	done; \
	fail=0; for p in $$pids; do wait $$p || fail=1; done; \
	for t in png_load embed png_roundtrip; do \
		printf '%-14s %s runs\n' $$t "$$(sed -n 's/^stat::number_of_executed_units: *//p' fuzz_$$t.log)"; \
	done; \
	if [ $$fail != 0 ]; then grep -h -A5 -E '^==[0-9]+==|^SUMMARY' fuzz_*.log; ls crash-* 2>/dev/null; exit 1; fi

$(FUZZ_DIR)/fuzz_png_load: tests/fuzz/fuzz_png_load.c png_io.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_png_load.c png_io.c -o $@ -lpng -lz

$(FUZZ_DIR)/fuzz_embed: tests/fuzz/fuzz_embed.c embed.c prng.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_embed.c embed.c prng.c -o $@ -lsodium

$(FUZZ_DIR)/fuzz_png_roundtrip: tests/fuzz/fuzz_png_roundtrip.c png_io.c $(HDRS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz/fuzz_png_roundtrip.c png_io.c -o $@ -lpng

# Line coverage over the whole suite, fault sweeps included. All binaries
# link the same instrumented objects so their counts add up.
COV_DIR     = $(TEST_DIR)/cov
COV_CFLAGS  = $(CFLAGS) -O0 -I. -Itests --coverage
COV_OBJS    = $(SRCS:%.c=$(COV_DIR)/%.o) $(COV_DIR)/fault.o $(COV_DIR)/fault_sodium.o

coverage: $(COV_OBJS) | $(COV_DIR)
	rm -f $(COV_DIR)/*.gcda
	$(CC) $(COV_CFLAGS) tests/test_embed.c $(COV_DIR)/embed.o $(COV_DIR)/png_io.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_embed -lpng -lsodium
	$(CC) $(COV_CFLAGS) tests/test_prng.c $(COV_DIR)/prng.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_prng -lsodium
	$(CC) $(COV_CFLAGS) tests/test_png_io.c $(COV_DIR)/png_io.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_png_io -lpng -lz
	$(CC) $(COV_CFLAGS) tests/test_faults.c $(COV_DIR)/png_io.o $(COV_DIR)/fault.o -o $(COV_DIR)/test_faults -lpng
	$(CC) $(COV_CFLAGS) $(SRCS:%.c=$(COV_DIR)/%.o) $(COV_DIR)/fault.o $(COV_DIR)/fault_sodium.o -o $(COV_DIR)/scattersteg $(LIBS)
	for t in test_embed test_prng test_png_io test_faults; do $(COV_DIR)/$$t > /dev/null 2>&1 || exit 1; done
	SCATTERSTEG=$(COV_DIR)/scattersteg SCATTERSTEG_FAULT=$(COV_DIR)/scattersteg \
		python3 tests/test_cli.py > /dev/null 2>&1 || { echo "tests failed; coverage still reported"; }
	@gcov -o $(COV_DIR) $(SRCS) 2>/dev/null | \
		awk '/^File .*\.c/ {f=$$2} /^Lines executed/ && f !~ /tests|\/usr/ {print f, $$0; f=""}'
	@mv *.c.gcov $(COV_DIR)/
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