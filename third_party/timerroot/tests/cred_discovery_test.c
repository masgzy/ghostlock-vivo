/* Host test for the runtime cred-signature discovery in timer98260.c.
 * Reproduces the PD2352C 16.2.17.0 observation: table cred_req=0xb0
 * (BTF sizeof), runtime cred pair 0xb8/0xc0 x2 among a busy histogram. */
#define main t98260_disabled_main
#include "timer98260.c"
#undef main

#include <assert.h>

static unsigned char buf[256 * 1024];

/* One kmem_cache_alloc record in the layout scan_cred_allocs uses:
 *   [i-12] pid(u32)  [i-8] site(u64)  [i] ptr(u64)  [i+8] req(u64)  [i+16] alloc(u64)
 * `at` is where the pid goes; keep records >= 64 bytes apart and past i=16. */
static size_t put_rec(size_t at, unsigned pid, unsigned long long req,
                      unsigned long long alloc, unsigned long long ptr)
{
    unsigned long long site = 0xffffffc008100000ULL;
    memcpy(buf + at, &pid, 4);
    memcpy(buf + at + 4, &site, 8);
    memcpy(buf + at + 12, &ptr, 8);
    memcpy(buf + at + 20, &req, 8);
    memcpy(buf + at + 28, &alloc, 8);
    return at + 64;
}

int main(void)
{
    size_t n = 64;
    unsigned pid = 21576;
    unsigned long long cred_ptr = 0xffffff8954185400ULL, site = 0, R = 0;
    unsigned long long dreq = 0, dalloc = 0;
    int c;

    /* The exact histogram from the device log. */
    for (int i = 0; i < 40; i++) n = put_rec(n, pid, 0xc8, 0xc8, 0xffffff89aaaa0000ULL + i);
    for (int i = 0; i < 45; i++) n = put_rec(n, pid, 0x100, 0x100, 0xffffff89bbbb0000ULL + i);
    for (int i = 0; i < 9; i++) n = put_rec(n, pid, 0x78, 0x80, 0xffffff89cccc0000ULL + i);
    for (int i = 0; i < 2; i++) n = put_rec(n, pid, 0xb8, 0xc0, cred_ptr + i * 0xc0);
    for (int i = 0; i < 8; i++) n = put_rec(n, pid, 0x108, 0x140, 0xffffff89dddd0000ULL + i);
    for (int i = 0; i < 3; i++) n = put_rec(n, pid, 0xd0, 0xd0, 0xffffff89eeee0000ULL + i);

    /* 1. table signature (0xb0, like the BTF-derived value) matches nothing */
    g_geo.cred_req = 0xb0;
    g_geo.cred_alloc = 0;
    c = scan_cred_allocs(buf, n, (int)pid, &site, &R);
    assert(c == 0 && R == 0);

    /* 2. discovery picks the unique count==2 cred-sized pair */
    assert(discover_cred_signature(buf, n, (int)pid, &dreq, &dalloc) == 1);
    assert(dreq == 0xb8 && dalloc == 0xc0);

    /* 3. adopting it makes the scan find both records, first ptr = cred */
    g_geo.cred_req = dreq;
    g_geo.cred_alloc = dalloc;
    R = 0;
    c = scan_cred_allocs(buf, n, (int)pid, &site, &R);
    assert(c == 2);
    assert(R == cred_ptr);
    assert((site & 0x1fffff) == (0xffffffc008100000ULL & 0x1fffff));

    /* 4. ambiguity: a second count==2 cred-sized pair blocks adoption */
    n = put_rec(n, pid, 0x90, 0x98, 0xffffff89ffff0000ULL);
    n = put_rec(n, pid, 0x90, 0x98, 0xffffff89ffff00c0ULL);
    assert(discover_cred_signature(buf, n, (int)pid, &dreq, &dalloc) == 0);

    /* 5. no count==2 pair at all (exec missed) blocks adoption too */
    memset(buf, 0, sizeof(buf));
    n = 64;
    for (int i = 0; i < 7; i++) n = put_rec(n, pid, 0xc8, 0xc8, 0xffffff89aaaa0000ULL + i);
    assert(discover_cred_signature(buf, n, (int)pid, &dreq, &dalloc) == 0);

    /* 6. other-pid records never pollute the child's histogram */
    memset(buf, 0, sizeof(buf));
    n = 64;
    n = put_rec(n, pid + 1, 0xb8, 0xc0, 0xffffff89aaaa0000ULL);
    n = put_rec(n, pid + 1, 0xb8, 0xc0, 0xffffff89aaaa00c0ULL);
    assert(discover_cred_signature(buf, n, (int)pid, &dreq, &dalloc) == 0);

    printf("cred discovery: all checks passed\n");
    return 0;
}
