// CPU features set
#include "cpu-features.h"

#if defined(_M_X64) || defined(__x86_64__)
static void cpuid(int cpuinfo[4], int info_type)
{
    __asm__ __volatile__(
        "cpuid" : "=a"(cpuinfo[0]),
                  "=b"(cpuinfo[1]),
                  "=c"(cpuinfo[2]),
                  "=d"(cpuinfo[3]) : "a"(info_type), "c"(0));
}

void get_cpu_features(cpu_features_t *f)
{
    int info[4];
    cpuid(info, 0);
    int nIds = info[0];

    cpuid(info, 0x80000000);
    unsigned nExIds = info[0];

    //  Detect Features
    if (nIds >= 0x00000001)
    {
        cpuid(info, 0x00000001);
        f->HW_MMX = (info[3] & ((int)1 << 23)) != 0;
        f->HW_SSE = (info[3] & ((int)1 << 25)) != 0;
        f->HW_SSE2 = (info[3] & ((int)1 << 26)) != 0;
        f->HW_SSE3 = (info[2] & ((int)1 << 0)) != 0;

        f->HW_SSSE3 = (info[2] & ((int)1 << 9)) != 0;
        f->HW_SSE41 = (info[2] & ((int)1 << 19)) != 0;
        f->HW_SSE42 = (info[2] & ((int)1 << 20)) != 0;
        f->HW_AES = (info[2] & ((int)1 << 25)) != 0;

        f->HW_AVX = (info[2] & ((int)1 << 28)) != 0;
        f->HW_FMA3 = (info[2] & ((int)1 << 12)) != 0;

        f->HW_RDRAND = (info[2] & ((int)1 << 30)) != 0;
    }
    if (nIds >= 0x00000007)
    {
        cpuid(info, 0x00000007);
        f->HW_AVX2 = (info[1] & ((int)1 << 5)) != 0;

        f->HW_BMI1 = (info[1] & ((int)1 << 3)) != 0;
        f->HW_BMI2 = (info[1] & ((int)1 << 8)) != 0;
        f->HW_ADX = (info[1] & ((int)1 << 19)) != 0;
        f->HW_SHA = (info[1] & ((int)1 << 29)) != 0;
        f->HW_PREFETCHWT1 = (info[2] & ((int)1 << 0)) != 0;

        f->HW_AVX512F = (info[1] & ((int)1 << 16)) != 0;
        f->HW_AVX512CD = (info[1] & ((int)1 << 28)) != 0;
        f->HW_AVX512PF = (info[1] & ((int)1 << 26)) != 0;
        f->HW_AVX512ER = (info[1] & ((int)1 << 27)) != 0;
        f->HW_AVX512VL = (info[1] & ((int)1 << 31)) != 0;
        f->HW_AVX512BW = (info[1] & ((int)1 << 30)) != 0;
        f->HW_AVX512DQ = (info[1] & ((int)1 << 17)) != 0;
        f->HW_AVX512IFMA = (info[1] & ((int)1 << 21)) != 0;
        f->HW_AVX512VBMI = (info[2] & ((int)1 << 1)) != 0;
    }
    if (nExIds >= 0x80000001)
    {
        cpuid(info, 0x80000001);
        f->HW_x64 = (info[3] & ((int)1 << 29)) != 0;
        f->HW_ABM = (info[2] & ((int)1 << 5)) != 0;
        f->HW_SSE4a = (info[2] & ((int)1 << 6)) != 0;
        f->HW_FMA4 = (info[2] & ((int)1 << 16)) != 0;
        f->HW_XOP = (info[2] & ((int)1 << 11)) != 0;
    }
}
#endif
