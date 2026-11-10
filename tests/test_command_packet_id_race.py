#!/usr/bin/env python3
"""Check production command packet ID allocation with ThreadSanitizer."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "components/device/silabs/si91x/wireless/src/sl_si91x_driver.c"
UTILITY = ROOT / "components/device/silabs/si91x/wireless/src/sl_rsi_utility.c"

PREAMBLE = r"""
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t sl_status_t;
typedef uint32_t sli_wifi_wait_period_t;
typedef int sli_wifi_command_type_t;
#define SL_STATUS_OK 0
#define SL_STATUS_INVALID_INDEX 0x22
#define SI91X_CMD_MAX 5
#define SLI_WIFI_REQ_OPERMODE 0x10
#define SLI_SI91X_FEAT_FW_UPDATE_NEW_CODE 1
#define VERIFY_STATUS_AND_RETURN(status) do { if ((status) != SL_STATUS_OK) return (status); } while (0)
#define SLI_WIFI_ALLOCATE_COMMAND_BUFFER_WAIT_TIME 1000
#define SLI_WIFI_RETURN_IMMEDIATELY 0

typedef struct {
  uint8_t id;
} sl_wifi_buffer_t;

typedef struct {
  uint32_t unused;
} sli_si91x_queue_packet_t;

typedef struct {
  union {
    struct {
      uint16_t length;
      uint16_t command;
      uint8_t unused[12];
    };
    uint8_t desc[16];
  };
  uint8_t data[];
} sl_wifi_system_packet_t;

typedef struct {
  uint32_t feature_bit_map;
} sl_wifi_system_boot_configuration_t;

typedef uint32_t CORE_irqState_t;
static pthread_mutex_t atomic_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread atomic_uint *observed_id;
static atomic_uint entered;
static atomic_bool release_responses;
static void record_id(uint8_t id)
{
  if (observed_id) {
    atomic_store(observed_id, id);
  }
  atomic_fetch_add(&entered, 1);
}
static __attribute__((unused)) CORE_irqState_t CORE_EnterAtomic(void)
{
  pthread_mutex_lock(&atomic_mutex);
  return 0;
}
static __attribute__((unused)) void CORE_ExitAtomic(CORE_irqState_t state)
{
  (void)state;
  pthread_mutex_unlock(&atomic_mutex);
}

static sl_status_t sli_si91x_allocate_command_buffer(sl_wifi_buffer_t **host_buffer,
                                                      void **packet,
                                                      uint32_t size,
                                                      uint32_t wait)
{
  (void)wait;
  *host_buffer = calloc(1, sizeof(**host_buffer));
  *packet = calloc(1, size);
  if (!*host_buffer || !*packet) {
    abort();
  }
  return SL_STATUS_OK;
}

static void sli_si91x_host_free_buffer(sl_wifi_buffer_t *buffer)
{
  free(buffer);
}

static uint8_t sli_set_command_packet_flags(uint32_t command,
                                             sli_wifi_wait_period_t wait_period,
                                             const void *data_buffer)
{
  (void)command;
  (void)wait_period;
  (void)data_buffer;
  return 0;
}

static void sli_configure_si91x_command_packet_node(sli_si91x_queue_packet_t *node,
                                                     sl_wifi_buffer_t *buffer,
                                                     sli_wifi_command_type_t type,
                                                     uint8_t flags,
                                                     void *context,
                                                     sli_wifi_wait_period_t wait_period)
{
  (void)node;
  (void)buffer;
  (void)type;
  (void)flags;
  (void)context;
  (void)wait_period;
}

static sl_status_t sli_enqueue_si91x_command_packet(sli_wifi_command_type_t type,
                                                     sl_wifi_buffer_t *packet,
                                                     sl_wifi_buffer_t *buffer,
                                                     uint8_t packet_id)
{
  (void)type;
  packet->id = packet_id;
  buffer->id = packet_id;
  record_id(packet_id);
  free(packet);
  free(buffer);
  return SL_STATUS_OK;
}

static sl_status_t sli_handle_si91x_command_response(sli_wifi_command_type_t type,
                                                      sli_wifi_wait_period_t wait_period,
                                                      uint8_t packet_id,
                                                      sl_wifi_buffer_t **data_buffer,
                                                      sl_wifi_buffer_t **response)
{
  (void)type;
  (void)wait_period;
  (void)packet_id;
  (void)data_buffer;
  (void)response;
  while (!atomic_load(&release_responses)) {
    sched_yield();
  }
  return SL_STATUS_OK;
}

static sl_status_t sli_wifi_allocate_command_buffer(sl_wifi_buffer_t **host_buffer,
                                                     void **packet,
                                                     uint32_t size,
                                                     uint32_t wait)
{
  return sli_si91x_allocate_command_buffer(host_buffer, packet, size, wait);
}

static void sli_wifi_memory_manager_free_buffer(sl_wifi_buffer_t *buffer)
{
  free(buffer);
}

static void sli_configure_command_packet_node(sli_si91x_queue_packet_t *node,
                                               sl_wifi_buffer_t *buffer,
                                               sli_wifi_command_type_t type,
                                               uint8_t flags,
                                               void *context,
                                               sli_wifi_wait_period_t wait_period)
{
  sli_configure_si91x_command_packet_node(node, buffer, type, flags, context, wait_period);
}

static sl_status_t sli_enqueue_command_packet(sli_wifi_command_type_t type,
                                               sl_wifi_buffer_t *packet,
                                               sl_wifi_buffer_t *buffer,
                                               uint8_t packet_id)
{
  return sli_enqueue_si91x_command_packet(type, packet, buffer, packet_id);
}

static sl_status_t sli_handle_command_response(sli_wifi_command_type_t type,
                                                sli_wifi_wait_period_t wait_period,
                                                uint8_t packet_id,
                                                void **data_buffer,
                                                sl_wifi_buffer_t **response)
{
  return sli_handle_si91x_command_response(type,
                                           wait_period,
                                           packet_id,
                                           (sl_wifi_buffer_t **)data_buffer,
                                           response);
}
"""

CHECKS = r"""
static atomic_bool start;
static atomic_bool stress_start;
static atomic_uint errors;
static atomic_uint ids[2];

static bool wait_for_commands(unsigned target)
{
  for (unsigned i = 0; i < 1000000 && atomic_load(&entered) < target; ++i) {
    sched_yield();
  }
  return atomic_load(&entered) == target;
}

static void *generic_worker(void *context)
{
  (void)context;
  observed_id = &ids[0];
  while (!atomic_load(&start)) {
    sched_yield();
  }
  if (sli_wifi_send_command(0, 0, NULL, 0, 1, NULL, NULL) != SL_STATUS_OK) {
    atomic_fetch_add(&errors, 1);
  }
  return NULL;
}

static void *si91x_worker(void *context)
{
  (void)context;
  observed_id = &ids[1];
  while (!atomic_load(&start)) {
    sched_yield();
  }
  sl_wifi_buffer_t *buffer = calloc(1, sizeof(*buffer));
  if (!buffer
      || sli_si91x_driver_send_command_packet(0, 0, buffer, 1, NULL, NULL) != SL_STATUS_OK) {
    atomic_fetch_add(&errors, 1);
  }
  return NULL;
}

static void *stress_worker(void *context)
{
  (void)context;
  observed_id = NULL;
  while (!atomic_load(&stress_start)) {
    sched_yield();
  }
  for (unsigned i = 0; i < 10000; ++i) {
    sl_wifi_buffer_t *buffer = calloc(1, sizeof(*buffer));
    if (!buffer
        || sli_si91x_driver_send_command_packet(0,
                                                0,
                                                buffer,
                                                SLI_WIFI_RETURN_IMMEDIATELY,
                                                NULL,
                                                NULL) != SL_STATUS_OK) {
      atomic_fetch_add(&errors, 1);
    }
  }
  return NULL;
}

int main(void)
{
  pthread_t threads[2];
  if (pthread_create(&threads[0], NULL, generic_worker, NULL) != 0
      || pthread_create(&threads[1], NULL, si91x_worker, NULL) != 0) {
    abort();
  }
  atomic_store(&start, true);
  bool delivered = wait_for_commands(2);
  if (!delivered) {
    fprintf(stderr, "Both command paths did not enqueue\n");
    atomic_fetch_add(&errors, 1);
  }
  bool duplicate = delivered && ids[0] == ids[1];
  if (duplicate) {
    fprintf(stderr, "Concurrent paths received the same ID: %u\n", ids[0]);
  }
  atomic_store(&release_responses, true);
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);

  if (pthread_create(&threads[0], NULL, stress_worker, NULL) != 0
      || pthread_create(&threads[1], NULL, stress_worker, NULL) != 0) {
    abort();
  }
  atomic_store(&stress_start, true);
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);

  unsigned error_count = atomic_load(&errors);
  printf("Command ID checks: duplicate=%d, call errors=%u\n", duplicate, error_count);
  return duplicate || error_count;
}
"""


def main():
    source = DRIVER.read_text()
    needle = "sl_status_t sli_si91x_driver_send_command_packet("
    start = source.index(needle, source.index(needle) + 1)
    end = source.index("\nstatic sl_status_t sl_si91x_driver_send_data_packet", start)
    function = source[start:end]
    utility = UTILITY.read_text()
    generic_start = utility.index("sl_status_t sli_wifi_send_command(")
    allocator_start = utility.find("uint8_t sli_wifi_allocate_command_packet_id(void)")
    allocator = utility[allocator_start:generic_start] if allocator_start >= 0 else ""
    generic_end = utility.index("\n// Helper function implementations", generic_start)
    generic_function = utility[generic_start:generic_end]
    with tempfile.TemporaryDirectory(prefix="si91x-command-id-test-") as directory:
        test_source = Path(directory) / "test.c"
        executable = Path(directory) / "test"
        test_source.write_text(PREAMBLE + allocator + function + generic_function + CHECKS)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(
            compiler
            + [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-g",
                "-fsanitize=thread",
                "-pthread",
                str(test_source),
                "--output",
                str(executable),
            ],
            check=True,
        )
        env = dict(os.environ, TSAN_OPTIONS="halt_on_error=1 exitcode=66")
        return subprocess.run([str(executable)], env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
