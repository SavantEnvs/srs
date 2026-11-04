# Top-level MP4 box with size 0 hangs `SrsMp4Decoder::initialize()`

`hang.mp4` (an `ftyp` followed by a box whose 32-bit size is 0) makes `SrsMp4Decoder::initialize()` spin
forever on one CPU core, with no memory growth.

Root cause, `trunk/src/kernel/srs_kernel_mp4.cpp`: `SrsMp4BoxReader::do_read()` returns the size-0 box,
`SrsMp4Box::decode()` accepts it (`SRS_MP4_EOF_SIZE`, returns early), and `SrsMp4BoxReader::skip()` then runs
`stream->erase((int)box->sz())`, which erases 0 bytes. `SrsMp4Decoder::initialize()` reads the same box again,
for ever.

`mayhem/harnesses/fuzz_mp4.cpp` therefore walks the boxes itself (it stops after a size-0 box, as ISO/IEC
14496-12 section 4.2 defines it) instead of calling `initialize()`. This file is a reproducer only and must
never be copied into `testsuite/`: a hanging seed fails Mayhem's start-up probe for every run.

Not yet reported upstream (ossrs/srs). Suggested report: "`SrsMp4Decoder::initialize()` never returns on an MP4
whose first box after `ftyp` has a 32-bit size of 0: `SrsMp4BoxReader::skip()` erases `box->sz()` = 0 bytes."
