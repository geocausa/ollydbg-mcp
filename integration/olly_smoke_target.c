#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/*
 * Controlled 32-bit target for OllyDbg bridge smoke testing.
 *
 * The build disables ASLR and exports both symbols below. The build script
 * records their virtual addresses in a JSON manifest consumed by the Python
 * smoke runner. This executable is test material, not a production sample.
 */
__declspec(dllexport) volatile LONG olly_smoke_counter = 0x11223344L;

__declspec(dllexport) __declspec(noinline) void __cdecl olly_smoke_probe(void) {
  InterlockedIncrement(&olly_smoke_counter);
}

int main(void) {
  unsigned long iteration = 0;
  printf("OLLY_SMOKE_READY pid=%lu\n", (unsigned long)GetCurrentProcessId());
  fflush(stdout);

  /* Run for roughly ten minutes, long enough for an interactive smoke test. */
  while (iteration < 6000UL) {
    olly_smoke_probe();
    Sleep(100);
    iteration++;
  }
  return 0;
}
