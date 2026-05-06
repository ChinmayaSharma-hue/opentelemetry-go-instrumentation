// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "arguments.h"
#include "trace/span_context.h"
#include "go_context.h"
#include "go_types.h"
#include "uprobe.h"
#include "trace/start_span.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_OPERATION_SIZE 64
#define MAX_KEY_SIZE 64
#define MAX_ADDR_LEN 64
#define MAX_CONCURRENT 50

struct redis_request_t {
    BASE_SPAN_PROPERTIES
    char operation[MAX_OPERATION_SIZE];
    char key[MAX_KEY_SIZE];
    char address[MAX_ADDR_LEN];
    __u64 namespace;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, struct redis_request_t);
    __uint(max_entries, MAX_CONCURRENT);
} redis_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct redis_request_t));
    __uint(max_entries, 1);
} redis_request_storage_map SEC(".maps");

volatile const u64 base_cmd_args_pos;
volatile const u64 options_db_pos;
volatile const u64 options_addr_pos;

// This instrumentation attaches uprobe to the following function:
// func (c *baseClient) process(ctx context.Context, cmd Cmder) error
SEC("uprobe/process")
int uprobe_process(struct pt_regs *ctx) {
    // initializing the data structure to hold the extracted data
    u32 map_id = 0;
    struct redis_request_t *redis_request = bpf_map_lookup_elem(&redis_request_storage_map, &map_id);
    if (redis_request == NULL) return 0;
    __builtin_memset(redis_request, 0, sizeof(*redis_request));
    redis_request->start_time = bpf_ktime_get_ns();

    // retrieving the baseClient pointer and redis.Cmder instance pointer
    // arguments
    // 1 -> baseClient pointer
    // 2 -> context.Context, type pointer
    // 3 -> context.Context, data pointer
    // 4 -> redis.Cmder, type pointer
    // 5 -> redis.Cmder, data pointer
    void *client_ptr = get_argument(ctx, 1);
    void *redis_cmd_ptr = get_argument(ctx, 5);

    // reading the values from redis CMD pointer
    // step 1, ensuring that the slice has at least two members
    struct go_slice args_slice = {0};
    bpf_probe_read_user(&args_slice, sizeof(args_slice), redis_cmd_ptr + base_cmd_args_pos);
    if (args_slice.len < 2) {
        return 0;
    }

    // step 2, retrieving the first member of the slice, operation
    struct go_iface arg0 = {0};
    bpf_probe_read_user(&arg0, sizeof(arg0), (void *)args_slice.array);
    if(!get_go_string_from_user_ptr((void *)arg0.data, redis_request->operation, MAX_OPERATION_SIZE)) {
        bpf_printk("Failed to get the operation from args");
        return 0;
    }

    // step 3, filtering out non-traced operations
    if (__builtin_memcmp(redis_request->operation, "hello", 5) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "auth", 4) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "client", 6) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "select", 6) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "ping", 4) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "quit", 4) == 0) return 0;
    if (__builtin_memcmp(redis_request->operation, "reset", 5) == 0) return 0;

    // step 4, retrieving the second member of the slice, key
    struct go_iface arg1 = {0};
    bpf_probe_read_user(&arg1, sizeof(arg1), (void *)args_slice.array + sizeof(struct go_iface));
    if(!get_go_string_from_user_ptr((void *)arg1.data, redis_request->key, MAX_KEY_SIZE)) {
        bpf_printk("Failed to get the key from args");
    }

    // step 5, reading values from the client pointer
    void *client_opts_ptr = NULL;
    bpf_probe_read_user(&client_opts_ptr, sizeof(client_opts_ptr), (void*)client_ptr);

    // step 6, reading the DB namespace
    if (!client_opts_ptr) return 0;
    bpf_probe_read_user(&redis_request->namespace, sizeof(redis_request->namespace), (void*)client_opts_ptr + options_db_pos);

    // step 7, reading the address
    if(!get_go_string_from_user_ptr((void*)client_opts_ptr + options_addr_pos, redis_request->address, MAX_ADDR_LEN)) {
        bpf_printk("Failed to get address from baseClient");
    }

    struct go_iface go_context = {0};
    get_Go_context(ctx, 2, 0, true, &go_context);
    start_span_params_t start_span_params = {
        .ctx = ctx,
        .go_context = &go_context,
        .psc = &redis_request->psc,
        .sc = &redis_request->sc,
        .get_parent_span_context_fn = NULL,
        .get_parent_span_context_arg = NULL,
    };
    start_span(&start_span_params);

    // Get key
    void *key = (void *)GOROUTINE(ctx);

    bpf_map_update_elem(&redis_events, &key, redis_request, 0);

    return 0;
}

UPROBE_RETURN(process, struct redis_request_t, redis_events)
