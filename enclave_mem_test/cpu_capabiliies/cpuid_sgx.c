/* 
 * This is based on ayeks's gist. I added a detailed parsing of Leaf 1 and Leaf 2 and higher.
 *
 * Fan Zhang
 */
#include <stdio.h>
#include <stdint.h>

#define POW2(n) (1 << n)
#define B2MB(b) (b << 20)

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
        /* ecx is often an input as well as an output. */
        asm volatile("cpuid"
            : "=a" (*eax),
              "=b" (*ebx),
              "=c" (*ecx),
              "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

#define title \
"\n**************************************************************************\n" \
"* CPUID Leaf %dH, Sub-Leaf %d of Intel SGX Capabilities (EAX=%dH,ECX=%d) *\n" \
"**************************************************************************\n"

int main(int argc, char **argv)
{
  /* This programm prints some CPUID information and tests the SGX support of the CPU */

  unsigned eax, ebx, ecx, edx;
  eax = 1; /* processor info and feature bits */

  native_cpuid(&eax, &ebx, &ecx, &edx);
  printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

  printf("stepping %d\n", eax & 0xF); // Bit 3-0
  printf("model %d\n", (eax >> 4) & 0xF); // Bit 7-4
  printf("family %d\n", (eax >> 8) & 0xF); // Bit 11-8
  printf("processor type %d\n", (eax >> 12) & 0x3); // Bit 13-12
  printf("extended model %d\n", (eax >> 16) & 0xF); // Bit 19-16
  printf("extended family %d\n", (eax >> 20) & 0xFF); // Bit 27-20
  
  // if smx set - SGX global enable is supported
  printf("smx: %d\n", (ecx >> 6) & 1); // CPUID.1:ECX.[bit6]

  /* Extended feature bits (EAX=07H, ECX=0H)*/
  printf("\nExtended feature bits (EAX=07H, ECX=0H)\n");
  eax = 7;
  ecx = 0;
  native_cpuid(&eax, &ebx, &ecx, &edx);
  printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

  //CPUID.(EAX=07H, ECX=0H):EBX.SGX = 1,
  printf("SGX available: %d\n", (ebx >> 2) & 0x1);

  /* SGX has to be enabled in MSR.IA32_Feature_Control.SGX_Enable
	check with msr-tools: rdmsr -ax 0x3a
	SGX_Enable is Bit 18
	if SGX_Enable = 0 no leaf information will appear. 
     for more information check Intel Docs Architectures-software-developer-system-programming-manual - 35.1 Architectural MSRS
  */	

  /* CPUID Leaf 12H, Sub-Leaf 0 Enumeration of Intel SGX Capabilities (EAX=12H,ECX=0) */
  printf(title, 12, 0, 12, 0);
  eax = 0x12;
  ecx = 0;
  native_cpuid(&eax, &ebx, &ecx, &edx);
  printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

  printf("SGX 1 supported: %d\n", eax & 0x1);
  printf("SGX 2 supported: %d\n", (eax >> 1) & 0x1);
  printf("MaxEnclaveSize not in 64-bit mode: %d MB\n", POW2((edx & 0xFF) - 20));
  printf("MaxEnclaveSize in 64-bit mode: %d MB\n", POW2(((edx >> 8) & 0xFF) - 20));
  printf("MISC region support: %x\n", ebx);

  /* CPUID Leaf 12H, Sub-Leaf 1 Enumeration of Intel SGX Capabilities (EAX=12H,ECX=1) */
  printf(title, 12, 1, 12, 1);
  eax = 0x12;
  ecx = 1;
  native_cpuid(&eax, &ebx, &ecx, &edx);
  printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);
  printf("DEBUG: %d\n", (eax >> 1) & 0x1);
  printf("MODE64BIT: %d\n", (eax >> 2) & 0x1);
  printf("Provisioning key is available: %d\n", (eax >> 4) & 0x1);
  printf("EINIT token key is available: %d\n", (eax >> 5) & 0x1);

  printf("XFRM[1:0]: %d\n", (ecx & 0x3));
  printf("XCR0: %08x%08x\n", edx, ecx);

  long addr = 0;
  for (int i = 2; i < 10; i++) {
	  /* CPUID Leaf 12H, Sub-Leaf i Enumeration of Intel SGX Capabilities (EAX=12H,ECX=i) */
	  eax = 0x12;
	  ecx = i;
	  native_cpuid(&eax, &ebx, &ecx, &edx);
      if ((eax & 0x0F) == 1) {
          printf(title, 12, i, 12, i);
          printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);
          addr = ebx;
          printf("BASE address of EPC section: %08x%08x\n", ebx, (eax & 0xFFFFFFF0)); 
          addr = edx;
          printf("SIZE of EPC section: %08x%08x\n", edx, (ecx & 0xFFFFFFF0)); 
          if ((ebx & 0x0F) == 1) {
              printf("The EPC section is confidentiality, integrity and replay protected");
          }
      }
      else {break;}
  } 
}
