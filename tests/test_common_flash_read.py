#!/usr/bin/env python3
"""Run the production flash reader against a simulated command transport."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "components/device/silabs/si91x/wireless/src/sl_si91x_driver.c"

PREAMBLE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t sl_status_t;
#define SL_STATUS_OK 0
#define SL_STATUS_FAIL 1
#define SL_STATUS_TIMEOUT 7
#define SL_STATUS_INVALID_PARAMETER 0x21
#define SL_STATUS_INVALID_COUNT 0x2B
#define MAX_CHUNK_SIZE 1400
#define SLI_COMMON_REQ_TA_M4_COMMANDS 1
#define SLI_WIFI_COMMON_CMD 0
#define SL_SI91X_READ_FROM_COMMON_FLASH 1
#define SLI_COMMON_RSP_TA_M4_COMMANDS_WAIT_TIME 31000
#define SLI_WIFI_WAIT_FOR_RESPONSE(value) (value)
#define SL_VERIFY_POINTER_OR_RETURN(pointer, error) do { if (!(pointer)) return (error); } while (0)
#define VERIFY_STATUS_AND_RETURN(status) do { if ((status) != SL_STATUS_OK) return (status); } while (0)

typedef struct {
  uint16_t length;
  uint16_t command;
  uint8_t unused[12];
  uint8_t data[];
} sl_wifi_system_packet_t;

typedef struct {
  uint8_t sub_cmd;
  uint32_t nwp_address;
  uint16_t output_buffer_length;
} sli_si91x_read_flash_request_t;

typedef struct {
  uint16_t length;
  void *data;
} sl_wifi_buffer_t;

static union {
  uint32_t alignment;
  uint8_t bytes[sizeof(sl_wifi_system_packet_t) + MAX_CHUNK_SIZE + 16];
} response_storage;
static sl_wifi_buffer_t response;
static int length_delta;
static uint16_t capacity_limit;
static unsigned calls;
static unsigned frees;
static unsigned fail_on_call;
static bool null_packet;
static bool null_buffer;
static unsigned failures;

#define CHECK(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
    ++failures; \
  } \
} while (0)

static sl_status_t sli_si91x_driver_send_command(
  uint32_t command, unsigned command_type, const void *data, uint32_t data_length,
  uint32_t wait_period, void *context, sl_wifi_buffer_t **buffer)
{
  (void)command;
  (void)command_type;
  (void)data_length;
  (void)wait_period;
  (void)context;
  const sli_si91x_read_flash_request_t *request = data;
  ++calls;
  *buffer = NULL;
  if (calls == fail_on_call) {
    return SL_STATUS_TIMEOUT;
  }
  sl_wifi_system_packet_t *packet = (void *)response_storage.bytes;
  packet->length = (uint16_t)(request->output_buffer_length + length_delta);
  for (unsigned i = 0; i < packet->length; ++i) {
    packet->data[i] = (uint8_t)(request->nwp_address + i);
  }
  response.length = capacity_limit ? capacity_limit : sizeof(response_storage.bytes);
  response.data = null_packet ? NULL : packet;
  *buffer = null_buffer ? NULL : &response;
  return SL_STATUS_OK;
}

static void *sli_wifi_host_get_buffer_data(sl_wifi_buffer_t *buffer, unsigned offset, uint16_t *length)
{
  CHECK(buffer != NULL || null_buffer);
  if (!buffer) {
    return NULL;
  }
  CHECK(offset == 0);
  if (length) {
    *length = buffer->length;
  }
  return buffer->data;
}

static void sli_si91x_host_free_buffer(sl_wifi_buffer_t *buffer)
{
  CHECK(buffer == &response || (null_buffer && buffer == NULL));
  ++frees;
}

static void reset_transport(void)
{
  length_delta = 0;
  capacity_limit = 0;
  calls = 0;
  frees = 0;
  fail_on_call = 0;
  null_packet = false;
  null_buffer = false;
}
"""

CHECKS = r"""
static void test_mismatched_length(int delta)
{
  reset_transport();
  length_delta = delta;
  struct {
    uint8_t output[8];
    uint8_t canary[16];
  } destination;
  memset(&destination, 0xa5, sizeof(destination));
  sl_status_t status = sl_si91x_command_to_read_common_flash(0x100, sizeof(destination.output), destination.output);
  CHECK(status == SL_STATUS_INVALID_COUNT);
  for (unsigned i = 0; i < sizeof(destination.output); ++i) {
    CHECK(destination.output[i] == 0xa5);
  }
  for (unsigned i = 0; i < sizeof(destination.canary); ++i) {
    CHECK(destination.canary[i] == 0xa5);
  }
  CHECK(calls == 1);
  CHECK(frees == 1);
}

static void test_truncated_buffer(void)
{
  reset_transport();
  capacity_limit = sizeof(sl_wifi_system_packet_t) + 4;
  uint8_t output[8];
  memset(output, 0xa5, sizeof(output));
  CHECK(sl_si91x_command_to_read_common_flash(0x100, sizeof(output), output) == SL_STATUS_INVALID_COUNT);
  CHECK(output[0] == 0xa5);
  CHECK(frees == 1);
}

static void test_missing_packet(void)
{
  reset_transport();
  null_packet = true;
  uint8_t output[8];
  memset(output, 0xa5, sizeof(output));
  CHECK(sl_si91x_command_to_read_common_flash(0x100, sizeof(output), output) == SL_STATUS_INVALID_COUNT);
  CHECK(output[0] == 0xa5);
  CHECK(frees == 1);
}

static void test_missing_buffer(void)
{
  reset_transport();
  null_buffer = true;
  uint8_t output[8];
  memset(output, 0xa5, sizeof(output));
  CHECK(sl_si91x_command_to_read_common_flash(0x100, sizeof(output), output) == SL_STATUS_INVALID_COUNT);
  CHECK(output[0] == 0xa5);
  CHECK(frees == 1);
}

static void test_valid_chunks(void)
{
  reset_transport();
  uint8_t output[MAX_CHUNK_SIZE + 17];
  CHECK(sl_si91x_command_to_read_common_flash(0x100, sizeof(output), output) == SL_STATUS_OK);
  for (unsigned i = 0; i < sizeof(output); ++i) {
    CHECK(output[i] == (uint8_t)(0x100 + i));
  }
  CHECK(calls == 2);
  CHECK(frees == 2);
}

static void test_transport_error(void)
{
  reset_transport();
  fail_on_call = 2;
  uint8_t output[MAX_CHUNK_SIZE + 17];
  CHECK(sl_si91x_command_to_read_common_flash(0x100, sizeof(output), output) == SL_STATUS_TIMEOUT);
  CHECK(calls == 2);
  CHECK(frees == 1);
}

int main(void)
{
  test_mismatched_length(8);
  test_mismatched_length(-4);
  test_truncated_buffer();
  test_missing_packet();
  test_missing_buffer();
  test_valid_chunks();
  test_transport_error();
  printf("Common flash response checks: %u failures\n", failures);
  return failures ? 1 : 0;
}
"""


def main():
    source = DRIVER.read_text()
    start = source.index("sl_status_t sl_si91x_command_to_read_common_flash(")
    end = source.index("\nsl_status_t sl_si91x_m4_ta_secure_handshake(", start)
    reader = source[start:end]
    with tempfile.TemporaryDirectory(prefix="si91x-flash-test-") as directory:
        test_source = Path(directory) / "test.c"
        executable = Path(directory) / "test"
        test_source.write_text(PREAMBLE + reader + CHECKS)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        subprocess.run(
            compiler
            + [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                str(test_source),
                "--output",
                str(executable),
            ],
            check=True,
        )
        return subprocess.run([str(executable)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
